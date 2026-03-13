"""Tests for CORS misconfiguration rules (PF-CORS-001 .. PF-CORS-003)."""

import pytest

from pathfinder.scanner import Scanner


class TestCorsAllowAllOrigins:
    """PF-CORS-001: allow_origins=["*"]."""

    def test_detects_wildcard_origins_list(self, make_file):
        path = make_file(
            "app.py",
            """\
            from fastapi.middleware.cors import CORSMiddleware

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["GET"],
            )
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-CORS-001"
        assert findings[0].cwe == 942

    def test_detects_origins_star_string(self, make_file):
        path = make_file(
            "app.py",
            """\
            cors = CORS(app, origins="*")
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_specific_origins(self, make_file):
        path = make_file(
            "app.py",
            """\
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com", "https://api.example.com"],
            )
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCorsHeaderWildcard:
    """PF-CORS-002: Access-Control-Allow-Origin: * in headers."""

    def test_detects_header_wildcard_python(self, make_file):
        path = make_file(
            "middleware.py",
            """\
            response.headers["Access-Control-Allow-Origin"] = "*"
            headers = {"Access-Control-Allow-Origin": "*"}
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-002"])
        findings = scanner.scan_path(path)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PF-CORS-002"

    def test_detects_header_wildcard_yaml(self, make_file):
        path = make_file(
            "nginx.conf",
            """\
            add_header Access-Control-Allow-Origin: *;
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_specific_origin_header(self, make_file):
        path = make_file(
            "middleware.py",
            """\
            headers["Access-Control-Allow-Origin"] = "https://example.com"
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestCorsCredentialsWildcard:
    """PF-CORS-003: allow_credentials=True with wildcard origin."""

    def test_detects_credentials_with_wildcard(self, make_file):
        path = make_file(
            "app.py",
            """\
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
            )
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-CORS-003"

    def test_safe_credentials_with_specific_origin(self, make_file):
        path = make_file(
            "app.py",
            """\
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
                allow_credentials=True,
            )
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_wildcard_without_credentials(self, make_file):
        path = make_file(
            "app.py",
            """\
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=False,
            )
            """,
        )
        scanner = Scanner(selected_rules=["PF-CORS-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0
