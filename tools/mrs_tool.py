#!/usr/bin/env python3
"""Edit readable mihomo rule-set sources and rebuild .mrs files."""

import argparse
import ipaddress
import shutil
import subprocess
from pathlib import Path

import yaml


SUPPORTED_BEHAVIORS = {"classical", "domain", "ipcidr"}
MRS_BEHAVIORS = {"domain", "ipcidr"}
SUPPORTED_FORMATS = {"yaml", "text"}
MRS_INPUT_FORMAT = "mrs"


def infer_format(path):
    suffix = Path(path).suffix.lower()
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix in {".txt", ".text", ".list"}:
        return "text"
    raise ValueError("cannot infer format; pass --format yaml or --format text")


def _clean_rule(rule):
    return str(rule).strip()


def find_mihomo(mihomo=None, workspace=None):
    exe = mihomo or shutil.which("mihomo") or shutil.which("mihomo.exe")
    if exe:
        return exe

    search_root = Path(workspace or ".")
    for candidate in sorted((search_root / ".cache" / "mihomo").glob("**/mihomo*.exe")):
        if candidate.is_file():
            return str(candidate)

    raise FileNotFoundError(
        "mihomo executable not found; pass --mihomo C:\\path\\to\\mihomo.exe"
    )


def _read_yaml_doc(path):
    if not path.exists():
        return {"payload": []}

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError(f"{path} must be a YAML object with a payload list")

    payload = data.get("payload", [])
    if payload is None:
        payload = []
    if not isinstance(payload, list):
        raise ValueError(f"{path} payload must be a list")

    data["payload"] = [_clean_rule(rule) for rule in payload if _clean_rule(rule)]
    return data


def load_rules(path, fmt=None):
    path = Path(path)
    fmt = fmt or infer_format(path)
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported format: {fmt}")

    if fmt == "yaml":
        return list(_read_yaml_doc(path)["payload"])

    if not path.exists():
        return []

    rules = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            rule = line.strip()
            if rule and not rule.startswith("#"):
                rules.append(rule)
    return rules


def save_rules(path, rules, fmt=None):
    path = Path(path)
    fmt = fmt or infer_format(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "yaml":
        data = _read_yaml_doc(path)
        data["payload"] = rules
        with path.open("w", encoding="utf-8", newline="\n") as file:
            yaml.safe_dump(data, file, allow_unicode=True, sort_keys=False)
        return

    with path.open("w", encoding="utf-8", newline="\n") as file:
        if rules:
            file.write("\n".join(rules) + "\n")
        else:
            file.write("")


def _dedupe_keep_order(rules):
    seen = set()
    result = []
    for rule in rules:
        if rule not in seen:
            seen.add(rule)
            result.append(rule)
    return result


def validate_rules(rules, behavior):
    if behavior not in SUPPORTED_BEHAVIORS:
        raise ValueError(f"unsupported behavior: {behavior}")

    if behavior == "domain":
        for rule in rules:
            if "," in rule:
                raise ValueError(
                    f"domain mrs rule must not be a classical comma rule: {rule}"
                )
        return

    if behavior == "classical":
        return

    for rule in rules:
        try:
            ipaddress.ip_network(rule, strict=False)
        except ValueError as exc:
            raise ValueError(f"ipcidr mrs rule must be a CIDR: {rule}") from exc


def update_rules(path, fmt, add, remove, behavior, dry_run=False):
    path = Path(path)
    fmt = fmt or infer_format(path)
    current = load_rules(path, fmt)
    remove_set = {_clean_rule(rule) for rule in remove if _clean_rule(rule)}
    additions = [_clean_rule(rule) for rule in add if _clean_rule(rule)]

    updated = [rule for rule in current if rule not in remove_set]
    updated.extend(additions)
    updated = _dedupe_keep_order(updated)
    validate_rules(updated, behavior)

    changed = updated != current
    if changed and not dry_run:
        save_rules(path, updated, fmt)
    return changed


def build_mrs(source, output, behavior, fmt, mihomo=None, workspace=None):
    source = Path(source)
    output = Path(output)
    fmt = fmt or infer_format(source)
    validate_rules(load_rules(source, fmt), behavior)

    if behavior not in MRS_BEHAVIORS:
        raise ValueError("mrs build only supports domain or ipcidr behavior")
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported format: {fmt}")

    exe = find_mihomo(mihomo, workspace=workspace)
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [exe, "convert-ruleset", behavior, fmt, str(source), str(output)],
        check=True,
    )


def dump_mrs(source, output, behavior, mihomo=None, workspace=None):
    source = Path(source)
    output = Path(output)
    if behavior not in MRS_BEHAVIORS:
        raise ValueError("mrs dump only supports domain or ipcidr behavior")
    exe = find_mihomo(mihomo, workspace=workspace)
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [exe, "convert-ruleset", behavior, MRS_INPUT_FORMAT, str(source), str(output)],
        check=True,
    )


def _add_common_options(parser):
    parser.add_argument("--format", choices=sorted(SUPPORTED_FORMATS), default=None)
    parser.add_argument("--behavior", choices=sorted(SUPPORTED_BEHAVIORS), required=True)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Edit yaml/text mihomo rule-set sources and rebuild .mrs files."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="print source rules")
    list_parser.add_argument("source")
    list_parser.add_argument("--format", choices=sorted(SUPPORTED_FORMATS), default=None)

    add_parser = subparsers.add_parser("add", help="add rules to source")
    add_parser.add_argument("source")
    add_parser.add_argument("rules", nargs="+")
    _add_common_options(add_parser)
    add_parser.add_argument("--compile", dest="compile_to")
    add_parser.add_argument("--mihomo")
    add_parser.add_argument("--dry-run", action="store_true")

    remove_parser = subparsers.add_parser("remove", help="remove rules from source")
    remove_parser.add_argument("source")
    remove_parser.add_argument("rules", nargs="+")
    _add_common_options(remove_parser)
    remove_parser.add_argument("--compile", dest="compile_to")
    remove_parser.add_argument("--mihomo")
    remove_parser.add_argument("--dry-run", action="store_true")

    build_parser_ = subparsers.add_parser("build", help="build .mrs from source")
    build_parser_.add_argument("source")
    build_parser_.add_argument("output")
    _add_common_options(build_parser_)
    build_parser_.add_argument("--mihomo")

    dump_parser = subparsers.add_parser("dump", help="dump .mrs to editable text")
    dump_parser.add_argument("source")
    dump_parser.add_argument("output")
    dump_parser.add_argument("--behavior", choices=sorted(MRS_BEHAVIORS), required=True)
    dump_parser.add_argument("--mihomo")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        for rule in load_rules(args.source, args.format):
            print(rule)
        return 0

    if args.command in {"add", "remove"}:
        add = args.rules if args.command == "add" else []
        remove = args.rules if args.command == "remove" else []
        changed = update_rules(
            args.source,
            fmt=args.format,
            add=add,
            remove=remove,
            behavior=args.behavior,
            dry_run=args.dry_run,
        )
        print("changed" if changed else "unchanged")
        if args.compile_to and not args.dry_run:
            build_mrs(
                source=args.source,
                output=args.compile_to,
                behavior=args.behavior,
                fmt=args.format,
                mihomo=args.mihomo,
            )
        return 0

    if args.command == "build":
        build_mrs(
            source=args.source,
            output=args.output,
            behavior=args.behavior,
            fmt=args.format,
            mihomo=args.mihomo,
        )
        return 0

    if args.command == "dump":
        dump_mrs(
            source=args.source,
            output=args.output,
            behavior=args.behavior,
            mihomo=args.mihomo,
        )
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
