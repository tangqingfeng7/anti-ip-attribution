#!/usr/bin/env python3
"""Local web UI server for editing mihomo rule-set sources."""

import argparse
import ipaddress
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

import mrs_tool


WEB_DIR = Path(__file__).resolve().parent / "mrs_web"
RULE_SUFFIXES = {".yaml", ".yml", ".text", ".list", ".mrs"}


def workspace_path(workspace, user_path):
    if not user_path:
        raise ValueError("path is required")

    root = Path(workspace).resolve()
    candidate = Path(user_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("path must stay inside this repository") from exc
    return resolved


def relative_path(workspace, path):
    return Path(path).resolve().relative_to(Path(workspace).resolve()).as_posix()


def list_rule_files(workspace):
    root = Path(workspace).resolve()
    files = []
    for path in root.rglob("*"):
        if not path.is_file() or not _is_rule_file(path):
            continue
        if ".git" in path.relative_to(root).parts:
            continue
        if path.suffix.lower() in {".yaml", ".yml"} and not _has_yaml_payload(path):
            continue
        files.append(relative_path(root, path))
    return sorted(files)


def _is_rule_file(path):
    suffix = path.suffix.lower()
    return suffix in RULE_SUFFIXES or path.name.lower().endswith(".mrs.txt")


def _has_yaml_payload(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    except yaml.YAMLError:
        return False
    return isinstance(data, dict) and isinstance(data.get("payload"), list)


def infer_behavior(rules):
    if any("," in rule for rule in rules):
        return "classical"
    if rules:
        try:
            for rule in rules:
                ipaddress.ip_network(rule, strict=False)
            return "ipcidr"
        except ValueError:
            pass
    return "domain"


def api_list_rules(workspace, payload):
    source = workspace_path(workspace, payload.get("path", ""))
    fmt = payload.get("format") or mrs_tool.infer_format(source)
    rules = mrs_tool.load_rules(source, fmt)
    return {
        "path": relative_path(workspace, source),
        "format": fmt,
        "behavior": infer_behavior(rules),
        "rules": rules,
    }


def api_update_rules(workspace, payload):
    source = workspace_path(workspace, payload.get("path", ""))
    fmt = payload.get("format") or mrs_tool.infer_format(source)
    behavior = payload.get("behavior", "")
    add = payload.get("add") or []
    remove = payload.get("remove") or []

    if isinstance(add, str):
        add = [add]
    if isinstance(remove, str):
        remove = [remove]

    changed = mrs_tool.update_rules(
        source,
        fmt=fmt,
        add=add,
        remove=remove,
        behavior=behavior,
        dry_run=False,
    )
    return {
        "changed": changed,
        "path": relative_path(workspace, source),
        "format": fmt,
        "rules": mrs_tool.load_rules(source, fmt),
    }


def api_build_mrs(workspace, payload):
    source = workspace_path(workspace, payload.get("source", ""))
    output = workspace_path(workspace, payload.get("output", ""))
    fmt = payload.get("format") or mrs_tool.infer_format(source)
    behavior = payload.get("behavior", "")
    mihomo = payload.get("mihomo") or None

    mrs_tool.build_mrs(
        source=source,
        output=output,
        behavior=behavior,
        fmt=fmt,
        mihomo=mihomo,
        workspace=workspace,
    )
    return {"output": relative_path(workspace, output)}


def api_dump_mrs(workspace, payload):
    source = workspace_path(workspace, payload.get("source", ""))
    output = workspace_path(workspace, payload.get("output", ""))
    behavior = payload.get("behavior", "")
    mihomo = payload.get("mihomo") or None

    mrs_tool.dump_mrs(
        source=source,
        output=output,
        behavior=behavior,
        mihomo=mihomo,
        workspace=workspace,
    )
    return {"output": relative_path(workspace, output)}


def _query_to_payload(query):
    parsed = parse_qs(query, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def make_handler(workspace):
    root = Path(workspace).resolve()

    class MrsRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/favicon.ico":
                    self.send_response(204)
                    self.end_headers()
                    return
                if parsed.path == "/api/files":
                    self._send_json({"files": list_rule_files(root)})
                    return
                if parsed.path == "/api/rules":
                    self._send_json(api_list_rules(root, _query_to_payload(parsed.query)))
                    return
                self._serve_static(parsed.path)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)

        def do_POST(self):
            parsed = urlparse(self.path)
            try:
                payload = self._read_json()
                if parsed.path == "/api/update":
                    self._send_json(api_update_rules(root, payload))
                    return
                if parsed.path == "/api/build":
                    self._send_json(api_build_mrs(root, payload))
                    return
                if parsed.path == "/api/dump":
                    self._send_json(api_dump_mrs(root, payload))
                    return
                self._send_json({"error": "not found"}, status=404)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            return json.loads(raw)

        def _send_json(self, payload, status=200):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve_static(self, request_path):
            rel = "index.html" if request_path in {"", "/"} else request_path.lstrip("/")
            static_path = (WEB_DIR / rel).resolve()
            try:
                static_path.relative_to(WEB_DIR.resolve())
            except ValueError:
                self._send_json({"error": "not found"}, status=404)
                return

            if not static_path.is_file():
                self._send_json({"error": "not found"}, status=404)
                return

            body = static_path.read_bytes()
            content_type = mimetypes.guess_type(static_path.name)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return MrsRequestHandler


def build_parser():
    parser = argparse.ArgumentParser(description="Start local MRS rule editor UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--workspace", default=".")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    workspace = Path(args.workspace).resolve()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(workspace))
    print(f"MRS editor: http://{args.host}:{args.port}/")
    print(f"Workspace: {workspace}")
    server.serve_forever()


if __name__ == "__main__":
    main()
