"""Tests for credential detection rules (PF-CRED-*)."""

import textwrap

import pytest

from pathfinder.scanner import Scanner


class TestCredPrivateKey:
    """PF-CRED-001: Private key in config."""

    def test_detects_hex_private_key_in_env(self, make_file):
        path = make_file(
            "config.env",
            """\
            PRIVATE_KEY=0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-CRED-001"

    def test_detects_hex_private_key_in_python(self, make_file):
        path = make_file(
            "wallet.py",
            """\
            PRIVATE_KEY = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_no_false_positive_for_short_hex(self, make_file):
        path = make_file(
            "config.env",
            """\
            PRIVATE_KEY=0xabcdef
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCredApiKey:
    """PF-CRED-002: API key in source."""

    def test_detects_api_key_assignment(self, make_file):
        path = make_file(
            "settings.py",
            """\
            api_key = "xk_test_abcdefghijklmnopqrstuvwx"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_access_token(self, make_file):
        path = make_file(
            "config.yml",
            """\
            access_token: ghp_abcdefghijklmnopqrstuvwxyz12345
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_ignores_comments(self, make_file):
        path = make_file(
            "settings.py",
            """\
            # api_key = "xk_test_abcdefghijklmnopqrstuvwx"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_no_false_positive_short_value(self, make_file):
        path = make_file(
            "settings.py",
            """\
            api_key = "short"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCredPasswordDefault:
    """PF-CRED-003: Password with default fallback (AST)."""

    def test_detects_getenv_password_default(self, make_file):
        path = make_file(
            "db.py",
            """\
            import os
            password = os.getenv("DB_PASSWORD", "default_pass")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-CRED-003"

    def test_detects_environ_get_secret(self, make_file):
        path = make_file(
            "auth.py",
            """\
            import os
            secret = os.environ.get("API_SECRET", "fallback_secret_value")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_no_false_positive_empty_default(self, make_file):
        path = make_file(
            "db.py",
            """\
            import os
            password = os.getenv("DB_PASSWORD", "")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_no_false_positive_non_sensitive(self, make_file):
        path = make_file(
            "app.py",
            """\
            import os
            log_level = os.getenv("LOG_LEVEL", "INFO")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_no_false_positive_no_default(self, make_file):
        path = make_file(
            "db.py",
            """\
            import os
            password = os.getenv("DB_PASSWORD")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCredJwt:
    """PF-CRED-004: Hardcoded JWT/Bearer token."""

    def test_detects_bearer_token(self, make_file):
        path = make_file(
            "client.py",
            """\
            authorization = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_no_false_positive_placeholder(self, make_file):
        path = make_file(
            "client.py",
            """\
            # Just a comment about JWT tokens
            token = get_token()
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCredCloud:
    """PF-CRED-005: AWS/GCP/Azure credentials."""

    def test_detects_aws_access_key(self, make_file):
        path = make_file(
            "deploy.py",
            """\
            aws_key = "AKIAIOSFODNN7EXAMPLE"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_gcp_service_account(self, make_file):
        path = make_file(
            "creds.json",
            """\
            {
              "type": "service_account",
              "project_id": "my-project"
            }
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1


class TestCredSshKey:
    """PF-CRED-006: SSH private key content."""

    def test_detects_rsa_private_key(self, make_file):
        path = make_file(
            "deploy_key.txt",
            """\
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA7...
            -----END RSA PRIVATE KEY-----
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-006"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_openssh_private_key(self, make_file):
        path = make_file(
            "id_ed25519.txt",
            """\
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAA...
            -----END OPENSSH PRIVATE KEY-----
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-006"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_no_false_positive_public_key(self, make_file):
        path = make_file(
            "key.txt",
            """\
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9...
            -----END PUBLIC KEY-----
            """,
        )
        scanner = Scanner(selected_rules=["PF-CRED-006"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0
