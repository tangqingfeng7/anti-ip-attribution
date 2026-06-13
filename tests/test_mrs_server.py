import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import mrs_server


class MrsServerTests(unittest.TestCase):
    def test_list_rules_reads_file_inside_workspace(self):
        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "rules.yaml").write_text(
                "payload:\n- example.com\n", encoding="utf-8"
            )

            result = mrs_server.api_list_rules(
                workspace, {"path": "rules.yaml", "format": "yaml"}
            )

            self.assertEqual(result["rules"], ["example.com"])
            self.assertEqual(result["path"], "rules.yaml")

    def test_list_rules_suggests_classical_for_comma_rules(self):
        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "rules.yaml").write_text(
                "payload:\n- DOMAIN-SUFFIX,example.com\n", encoding="utf-8"
            )

            result = mrs_server.api_list_rules(
                workspace, {"path": "rules.yaml", "format": "yaml"}
            )

            self.assertEqual(result["behavior"], "classical")

    def test_update_rules_adds_rule_and_returns_new_list(self):
        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "rules.yaml").write_text(
                "payload:\n- example.com\n", encoding="utf-8"
            )

            result = mrs_server.api_update_rules(
                workspace,
                {
                    "path": "rules.yaml",
                    "format": "yaml",
                    "behavior": "domain",
                    "add": ["+.example.org"],
                    "remove": [],
                },
            )

            self.assertTrue(result["changed"])
            self.assertEqual(result["rules"], ["example.com", "+.example.org"])

    def test_rejects_paths_outside_workspace(self):
        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)

            with self.assertRaises(ValueError):
                mrs_server.api_list_rules(
                    workspace, {"path": "../outside.yaml", "format": "yaml"}
                )

    def test_list_rule_files_skips_yaml_without_payload(self):
        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "source.yaml").write_text(
                "payload:\n- example.com\n", encoding="utf-8"
            )
            (workspace / "config.yaml").write_text(
                "config:\n  rules: []\n", encoding="utf-8"
            )
            (workspace / "rules.list").write_text("example.com\n", encoding="utf-8")
            (workspace / "requirements.txt").write_text(
                "PyYAML==6.0.2\n", encoding="utf-8"
            )
            (workspace / "Games.mrs.txt").write_text(
                "+.example.com\n", encoding="utf-8"
            )
            (workspace / "Games.mrs").write_bytes(b"not-real-mrs")

            self.assertEqual(
                mrs_server.list_rule_files(workspace),
                ["Games.mrs", "Games.mrs.txt", "rules.list", "source.yaml"],
            )

    def test_dump_mrs_uses_resolved_workspace_paths(self):
        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "Games.mrs").write_bytes(b"not-real-mrs")

            with patch("mrs_server.mrs_tool.dump_mrs") as dump:
                result = mrs_server.api_dump_mrs(
                    workspace,
                    {
                        "source": "Games.mrs",
                        "output": "Games.mrs.txt",
                        "behavior": "domain",
                        "mihomo": "mihomo.exe",
                    },
                )

            dump.assert_called_once_with(
                source=(workspace / "Games.mrs").resolve(),
                output=(workspace / "Games.mrs.txt").resolve(),
                behavior="domain",
                mihomo="mihomo.exe",
                workspace=workspace,
            )
            self.assertEqual(result["output"], "Games.mrs.txt")

    def test_build_mrs_uses_resolved_workspace_paths(self):
        with TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "rules.yaml").write_text(
                "payload:\n- example.com\n", encoding="utf-8"
            )

            with patch("mrs_server.mrs_tool.build_mrs") as build:
                result = mrs_server.api_build_mrs(
                    workspace,
                    {
                        "source": "rules.yaml",
                        "output": "out/rules.mrs",
                        "format": "yaml",
                        "behavior": "domain",
                        "mihomo": "mihomo.exe",
                    },
                )

            build.assert_called_once_with(
                source=(workspace / "rules.yaml").resolve(),
                output=(workspace / "out" / "rules.mrs").resolve(),
                behavior="domain",
                fmt="yaml",
                mihomo="mihomo.exe",
                workspace=workspace,
            )
            self.assertEqual(result["output"], "out/rules.mrs")


if __name__ == "__main__":
    unittest.main()
