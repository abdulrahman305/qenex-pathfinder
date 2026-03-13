"""Tests for dependency security rules (PF-DEP-001 .. PF-DEP-003)."""

import pytest

from pathfinder.scanner import Scanner


class TestUnpinnedDependency:
    """PF-DEP-001: Unpinned dependency in requirements.txt."""

    def test_detects_unpinned_with_gte(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            requests>=2.28
            flask==3.0.0
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-DEP-001"

    def test_detects_bare_package_name(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            requests
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_pinned_dependencies(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            requests==2.32.3
            flask==3.0.0
            pyyaml==6.0.1
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_skips_comments_and_blanks(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            # This is a comment
            -r base.txt

            requests==2.32.3
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_only_applies_to_requirements_txt(self, make_file):
        path = make_file(
            "pyproject.toml",
            """\
            requests>=2.28
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestUnpinnedDockerImage:
    """PF-DEP-002: Unpinned Docker base image."""

    def test_detects_no_tag(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python
            RUN pip install flask
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-DEP-002"

    def test_detects_latest_tag(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM node:latest
            WORKDIR /app
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_stable_tag(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM debian:stable
            RUN apt-get update
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_pinned_version(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:3.12-slim
            WORKDIR /app
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_with_digest(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python@sha256:abcdef1234567890
            WORKDIR /app
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_scratch(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM scratch
            COPY app /app
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestKnownVulnerablePackage:
    """PF-DEP-003: Known vulnerable package version."""

    def test_detects_vulnerable_pyyaml(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            pyyaml==5.4.1
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-DEP-003"

    def test_detects_vulnerable_requests(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            requests==2.31.0
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_vulnerable_django(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            django==4.2.10
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_patched_version(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            pyyaml==6.0.1
            requests==2.32.3
            django==4.2.11
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_unknown_package(self, make_file):
        path = make_file(
            "requirements.txt",
            """\
            my-custom-package==1.0.0
            """,
        )
        scanner = Scanner(selected_rules=["PF-DEP-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0
