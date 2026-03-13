"""Tests for the Scanner class."""

import textwrap

import pytest

from pathfinder.config import Config
from pathfinder.finding import Severity
from pathfinder.scanner import Scanner


class TestScanPath:
    """Integration tests: Scanner.scan_path on real temp files."""

    def test_scan_finds_hardcoded_private_key(self, make_file):
        path = make_file(
            "config.env",
            """\
            PRIVATE_KEY = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
            """,
        )
        scanner = Scanner()
        findings = scanner.scan_path(path)
        assert any(f.rule_id == "PF-CRED-001" for f in findings)

    def test_scan_finds_os_system(self, make_file):
        path = make_file(
            "deploy.py",
            """\
            import os
            os.system("rm -rf /tmp/cache")
            """,
        )
        scanner = Scanner()
        findings = scanner.scan_path(path)
        assert any(f.rule_id == "PF-CMDI-002" for f in findings)

    def test_scan_directory(self, make_tree):
        root = make_tree(
            {
                "app.py": textwrap.dedent("""\
                    import os
                    os.system("reboot")
                """),
                "lib/utils.py": textwrap.dedent("""\
                    import hashlib
                    h = hashlib.md5(b"data")
                """),
            }
        )
        scanner = Scanner()
        findings = scanner.scan_path(root)
        rule_ids = {f.rule_id for f in findings}
        assert "PF-CMDI-002" in rule_ids
        assert "PF-CRYP-001" in rule_ids

    def test_skip_excluded_directories(self, make_tree):
        root = make_tree(
            {
                "src/app.py": textwrap.dedent("""\
                    import os
                    os.system("ls")
                """),
                "node_modules/pkg/index.py": textwrap.dedent("""\
                    import os
                    os.system("ls")
                """),
            }
        )
        scanner = Scanner()
        findings = scanner.scan_path(root)
        # Only src/app.py should be scanned, not node_modules
        assert all("node_modules" not in f.file_path for f in findings)
        assert any(f.rule_id == "PF-CMDI-002" for f in findings)


class TestSeverityFiltering:
    def test_filter_by_severity_high(self, make_file):
        path = make_file(
            "example.py",
            """\
            import os
            import hashlib
            # MD5 is MEDIUM, os.system is HIGH
            h = hashlib.md5(b"x")
            os.system("echo hello")
            """,
        )
        scanner = Scanner(severity_filter=Severity.HIGH)
        findings = scanner.scan_path(path)
        # All returned findings should be HIGH or above
        assert all(f.severity >= Severity.HIGH for f in findings)

    def test_filter_by_severity_critical(self, make_file):
        path = make_file(
            "example.py",
            """\
            import os
            os.system("echo hello")
            """,
        )
        scanner = Scanner(severity_filter=Severity.CRITICAL)
        findings = scanner.scan_path(path)
        # os.system is HIGH, not CRITICAL, so no findings
        assert len(findings) == 0


class TestScanFileContent:
    def test_scan_file_content_python(self):
        content = textwrap.dedent("""\
            import os
            os.system("rm -rf /")
        """)
        scanner = Scanner()
        findings = scanner.scan_file_content(content, "deploy.py")
        assert any(f.rule_id == "PF-CMDI-002" for f in findings)

    def test_scan_file_content_systemd(self):
        content = textwrap.dedent("""\
            [Unit]
            Description=My Service
            [Service]
            Environment=DB_PASSWORD=hunter2
            ExecStart=/usr/bin/myapp
        """)
        scanner = Scanner()
        findings = scanner.scan_file_content(content, "myapp.service")
        assert any(f.rule_id == "PF-SYSD-001" for f in findings)

    def test_scan_file_content_no_findings(self):
        content = textwrap.dedent("""\
            import json
            data = json.loads('{"key": "value"}')
        """)
        scanner = Scanner()
        findings = scanner.scan_file_content(content, "safe.py")
        assert len(findings) == 0


class TestSelectedRules:
    def test_run_only_selected_rules(self, make_file):
        path = make_file(
            "example.py",
            """\
            import os
            import hashlib
            os.system("ls")
            h = hashlib.md5(b"x")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRYP-001"])
        findings = scanner.scan_path(path)
        # Only PF-CRYP-001 should fire
        assert all(f.rule_id == "PF-CRYP-001" for f in findings)
        assert len(findings) > 0

    def test_exclude_rules_via_config(self, make_file):
        path = make_file(
            "example.py",
            """\
            import os
            os.system("ls")
            """,
        )
        config = Config(exclude_rules=["PF-CMDI-002"])
        scanner = Scanner(config=config)
        findings = scanner.scan_path(path)
        assert all(f.rule_id != "PF-CMDI-002" for f in findings)


class TestInlineSuppression:
    """Tests for the # pathfinder: ignore inline suppression feature."""

    def test_suppresses_finding_on_annotated_line(self):
        content = textwrap.dedent("""\
            import os
            os.system("echo hello")  # pathfinder: ignore
        """)
        scanner = Scanner()
        findings = scanner.scan_file_content(content, "deploy.py")
        assert not any(f.rule_id == "PF-CMDI-002" for f in findings)

    def test_does_not_suppress_unannotated_line(self):
        content = textwrap.dedent("""\
            import os
            os.system("echo hello")
        """)
        scanner = Scanner()
        findings = scanner.scan_file_content(content, "deploy.py")
        assert any(f.rule_id == "PF-CMDI-002" for f in findings)

    def test_suppresses_only_annotated_line_not_others(self):
        content = textwrap.dedent("""\
            import os
            import hashlib
            os.system("echo hello")  # pathfinder: ignore
            h = hashlib.md5(b"data")
        """)
        scanner = Scanner()
        findings = scanner.scan_file_content(content, "example.py")
        rule_ids = {f.rule_id for f in findings}
        assert "PF-CMDI-002" not in rule_ids
        assert "PF-CRYP-001" in rule_ids

    def test_suppression_works_on_file_scan(self, make_file):
        path = make_file(
            "deploy.py",
            """\
            import os
            os.system("echo hello")  # pathfinder: ignore
            """,
        )
        scanner = Scanner()
        findings = scanner.scan_path(path)
        assert not any(f.rule_id == "PF-CMDI-002" for f in findings)


class TestPermSourceCodeExclusion:
    """PF-PERM-002 should not flag source code files."""

    def test_perm002_skips_python_source(self, make_file):
        path = make_file("credentials.py", "x = 1\n")
        scanner = Scanner(selected_rules=["PF-PERM-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_perm002_still_flags_env_files(self, make_file):
        path = make_file("secret.env", "DB_HOST=localhost\n")
        import os
        os.chmod(path, 0o644)
        scanner = Scanner(selected_rules=["PF-PERM-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-PERM-002"


class TestFindingSorting:
    def test_findings_sorted_by_severity_desc(self, make_file):
        path = make_file(
            "mixed.py",
            """\
            import os
            import hashlib
            os.system("ls")
            h = hashlib.md5(b"x")
            """,
        )
        scanner = Scanner()
        findings = scanner.scan_path(path)
        if len(findings) >= 2:
            for i in range(len(findings) - 1):
                assert findings[i].severity >= findings[i + 1].severity
