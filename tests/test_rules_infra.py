"""Tests for infrastructure rules: network, systemd, docker, permissions."""

import os
import stat
import textwrap

import pytest

from pathfinder.scanner import Scanner


# =========================================================================
# Network (PF-NET-*)
# =========================================================================


class TestNetBindAll:
    """PF-NET-001: Binding to 0.0.0.0."""

    def test_detects_bind_all(self, make_file):
        path = make_file(
            "config.yml",
            """\
            host: 0.0.0.0
            port: 8080
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].cwe == 668

    def test_safe_localhost_binding(self, make_file):
        path = make_file(
            "config.yml",
            """\
            host: 127.0.0.1
            port: 8080
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_detects_bind_in_python(self, make_file):
        path = make_file(
            "server.py",
            """\
            host = "0.0.0.0"
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_ignores_comments(self, make_file):
        path = make_file(
            "config.yml",
            """\
            # host: 0.0.0.0
            host: 127.0.0.1
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestNetDebug:
    """PF-NET-003: Debug mode enabled."""

    def test_detects_debug_true(self, make_file):
        path = make_file(
            "settings.py",
            """\
            debug = True
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_debug_false(self, make_file):
        path = make_file(
            "settings.py",
            """\
            debug = False
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


# =========================================================================
# Systemd (PF-SYSD-*)
# =========================================================================


class TestSystemdSecretEnv:
    """PF-SYSD-001: Secret in Environment= directive."""

    def test_detects_password_in_env(self, make_file):
        path = make_file(
            "myapp.service",
            """\
            [Unit]
            Description=My App

            [Service]
            Environment=DB_PASSWORD=supersecret123
            ExecStart=/usr/bin/myapp
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-SYSD-001"

    def test_detects_token_in_env(self, make_file):
        path = make_file(
            "bot.service",
            """\
            [Service]
            Environment=API_TOKEN=abc123longtoken456
            ExecStart=/usr/bin/bot
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_env_no_secret(self, make_file):
        path = make_file(
            "app.service",
            """\
            [Service]
            Environment=LOG_LEVEL=INFO
            ExecStart=/usr/bin/app
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestSystemdMissingProtect:
    """PF-SYSD-002: Missing ProtectSystem."""

    def test_detects_missing_protect_system(self, make_file):
        path = make_file(
            "basic.service",
            """\
            [Unit]
            Description=Basic

            [Service]
            ExecStart=/usr/bin/basic
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_with_protect_system(self, make_file):
        path = make_file(
            "hardened.service",
            """\
            [Unit]
            Description=Hardened

            [Service]
            ExecStart=/usr/bin/hardened
            ProtectSystem=strict
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestSystemdRootNoHarden:
    """PF-SYSD-003: Running as root without hardening."""

    def test_detects_root_without_nnp(self, make_file):
        path = make_file(
            "root.service",
            """\
            [Unit]
            Description=Root Service

            [Service]
            User=root
            ExecStart=/usr/bin/rootsvc
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_root_with_nnp(self, make_file):
        path = make_file(
            "root.service",
            """\
            [Service]
            User=root
            NoNewPrivileges=yes
            ExecStart=/usr/bin/rootsvc
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0

    def test_safe_non_root_user(self, make_file):
        path = make_file(
            "app.service",
            """\
            [Service]
            User=appuser
            ExecStart=/usr/bin/app
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


# =========================================================================
# Docker (PF-DOCK-*)
# =========================================================================


class TestDockerRunAsRoot:
    """PF-DOCK-001: Container running as root."""

    def test_detects_no_user_directive(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:3.12-slim
            WORKDIR /app
            COPY . .
            CMD ["python", "app.py"]
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_with_user_directive(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:3.12-slim
            RUN useradd -m appuser
            USER appuser
            WORKDIR /app
            CMD ["python", "app.py"]
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-001"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestDockerSocket:
    """PF-DOCK-002: Docker socket mounted."""

    def test_detects_docker_socket_mount(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              agent:
                image: portainer/agent:2.19.4
                volumes:
                  - /var/run/docker.sock:/var/run/docker.sock
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].severity.name == "CRITICAL"


class TestDockerPrivileged:
    """PF-DOCK-003: Privileged mode."""

    def test_detects_privileged_true(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp:1.0
                privileged: true
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-003"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1


class TestDockerSecrets:
    """PF-DOCK-007: Secrets in ENV/ARG."""

    def test_detects_env_password(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:3.12
            ENV DB_PASSWORD=hunter2
            CMD ["python", "app.py"]
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-007"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_arg_secret(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:3.12
            ARG API_SECRET_KEY=mysecret123
            CMD ["python", "app.py"]
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-007"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1


class TestDockerHealthcheck:
    """PF-DOCK-008: No health check."""

    def test_detects_missing_healthcheck(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:3.12
            CMD ["python", "app.py"]
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-008"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_with_healthcheck(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:3.12
            HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1
            CMD ["python", "app.py"]
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-008"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


# =========================================================================
# Permissions (PF-PERM-*)
# =========================================================================


class TestPermWorldWritable:
    """PF-PERM-001: World-writable file."""

    def test_detects_world_writable(self, tmp_path):
        fpath = tmp_path / "script.py"
        fpath.write_text("# world writable\n")
        os.chmod(str(fpath), 0o777)
        scanner = Scanner(selected_rules=["PF-PERM-001"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-PERM-001"

    def test_safe_normal_perms(self, tmp_path):
        fpath = tmp_path / "script.py"
        fpath.write_text("# safe\n")
        os.chmod(str(fpath), 0o644)
        scanner = Scanner(selected_rules=["PF-PERM-001"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 0


class TestPermSecretFile:
    """PF-PERM-002: Secret files not 0600."""

    def test_detects_loose_env_file(self, tmp_path):
        fpath = tmp_path / "app.env"
        fpath.write_text("SECRET=foo\n")
        os.chmod(str(fpath), 0o644)
        scanner = Scanner(selected_rules=["PF-PERM-002"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 1

    def test_safe_0600_env_file(self, tmp_path):
        fpath = tmp_path / "app.env"
        fpath.write_text("SECRET=foo\n")
        os.chmod(str(fpath), 0o600)
        scanner = Scanner(selected_rules=["PF-PERM-002"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 0
