import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import mrs_tool


class MrsToolTests(unittest.TestCase):
    def test_add_rule_to_yaml_payload_deduplicates(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rules.yaml"
            path.write_text("payload:\n- example.com\n", encoding="utf-8")

            changed = mrs_tool.update_rules(
                path,
                fmt="yaml",
                add=["example.com", "+.example.org"],
                remove=[],
                behavior="domain",
                dry_run=False,
            )

            self.assertTrue(changed)
            self.assertEqual(
                mrs_tool.load_rules(path, "yaml"),
                ["example.com", "+.example.org"],
            )

    def test_remove_rule_from_text_file(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rules.text"
            path.write_text("# note\nexample.com\nold.example\n", encoding="utf-8")

            changed = mrs_tool.update_rules(
                path,
                fmt="text",
                add=[],
                remove=["old.example"],
                behavior="domain",
                dry_run=False,
            )

            self.assertTrue(changed)
            self.assertEqual(mrs_tool.load_rules(path, "text"), ["example.com"])

    def test_ipcidr_rejects_domain_rule(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ip.yaml"
            path.write_text("payload: []\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                mrs_tool.update_rules(
                    path,
                    fmt="yaml",
                    add=["example.com"],
                    remove=[],
                    behavior="ipcidr",
                    dry_run=False,
                )

    def test_classical_allows_comma_rules_for_editing(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "classical.yaml"
            path.write_text("payload: []\n", encoding="utf-8")

            changed = mrs_tool.update_rules(
                path,
                fmt="yaml",
                add=["DOMAIN-SUFFIX,example.com"],
                remove=[],
                behavior="classical",
                dry_run=False,
            )

            self.assertTrue(changed)
            self.assertEqual(
                mrs_tool.load_rules(path, "yaml"),
                ["DOMAIN-SUFFIX,example.com"],
            )

    def test_build_mrs_rejects_classical_behavior(self):
        with TemporaryDirectory() as temp_dir:
            src = Path(temp_dir) / "rules.yaml"
            dst = Path(temp_dir) / "rules.mrs"
            src.write_text("payload:\n- DOMAIN-SUFFIX,example.com\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                mrs_tool.build_mrs(
                    source=src,
                    output=dst,
                    behavior="classical",
                    fmt="yaml",
                    mihomo="mihomo.exe",
                )

    def test_build_mrs_invokes_mihomo_convert(self):
        with TemporaryDirectory() as temp_dir:
            src = Path(temp_dir) / "rules.yaml"
            dst = Path(temp_dir) / "rules.mrs"
            src.write_text("payload:\n- example.com\n", encoding="utf-8")

            with patch("mrs_tool.shutil.which", return_value="mihomo"), patch(
                "mrs_tool.subprocess.run"
            ) as run:
                mrs_tool.build_mrs(
                    source=src,
                    output=dst,
                    behavior="domain",
                    fmt="yaml",
                    mihomo=None,
                )

            run.assert_called_once_with(
                ["mihomo", "convert-ruleset", "domain", "yaml", str(src), str(dst)],
                check=True,
            )

    def test_dump_mrs_invokes_mihomo_convert_from_mrs_to_text(self):
        with TemporaryDirectory() as temp_dir:
            src = Path(temp_dir) / "Games.mrs"
            dst = Path(temp_dir) / "Games.mrs.txt"
            src.write_bytes(b"not-real-mrs")

            with patch("mrs_tool.shutil.which", return_value="mihomo"), patch(
                "mrs_tool.subprocess.run"
            ) as run:
                mrs_tool.dump_mrs(
                    source=src,
                    output=dst,
                    behavior="domain",
                    mihomo=None,
                )

            run.assert_called_once_with(
                ["mihomo", "convert-ruleset", "domain", "mrs", str(src), str(dst)],
                check=True,
            )

    def test_find_mihomo_falls_back_to_local_cache(self):
        with TemporaryDirectory() as temp_dir:
            cached = (
                Path(temp_dir)
                / ".cache"
                / "mihomo"
                / "v1.19.27"
                / "mihomo-windows-amd64.exe"
            )
            cached.parent.mkdir(parents=True)
            cached.write_text("", encoding="utf-8")

            with patch("mrs_tool.shutil.which", return_value=None):
                self.assertEqual(mrs_tool.find_mihomo(workspace=temp_dir), str(cached))

    def test_missing_mihomo_has_clear_error(self):
        with TemporaryDirectory() as temp_dir:
            src = Path(temp_dir) / "rules.yaml"
            dst = Path(temp_dir) / "rules.mrs"
            src.write_text("payload: []\n", encoding="utf-8")

            with patch("mrs_tool.shutil.which", return_value=None):
                with self.assertRaises(FileNotFoundError):
                    mrs_tool.build_mrs(
                        source=src,
                        output=dst,
                        behavior="domain",
                        fmt="yaml",
                        mihomo=None,
                        workspace=temp_dir,
                    )


if __name__ == "__main__":
    unittest.main()
