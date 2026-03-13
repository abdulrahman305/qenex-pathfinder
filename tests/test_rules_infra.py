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


# =========================================================================
# Network (PF-NET-002, PF-NET-004) — gap coverage
# =========================================================================


class TestNetBindIPv6:
    """PF-NET-002: Binding to :: (IPv6 wildcard)."""

    def test_detects_ipv6_wildcard(self, make_file):
        path = make_file(
            "config.yml",
            """\
            host: ::
            port: 8080
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-NET-002"

    def test_safe_ipv6_localhost(self, make_file):
        path = make_file(
            "config.yml",
            """\
            host: ::1
            port: 8080
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-002"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestNetDangerousPort:
    """PF-NET-004: Dangerous ports exposed without localhost bind."""

    def test_detects_redis_port_exposed(self, make_file):
        path = make_file(
            "config.yml",
            """\
            port: 6379
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-NET-004"

    def test_detects_postgres_port(self, make_file):
        path = make_file(
            "db.conf",
            """\
            port: 5432
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_with_localhost(self, make_file):
        path = make_file(
            "config.yml",
            """\
            host: 127.0.0.1
            port: 6379
            """,
        )
        scanner = Scanner(selected_rules=["PF-NET-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


# =========================================================================
# Systemd (PF-SYSD-004, PF-SYSD-005) — gap coverage
# =========================================================================


class TestSystemdWorldReadableEnvFile:
    """PF-SYSD-004: World-readable EnvironmentFile."""

    def test_detects_world_readable_envfile(self, tmp_path):
        # Create an env file with loose permissions
        env_file = tmp_path / "secrets.env"
        env_file.write_text("DB_PASSWORD=secret\n")
        os.chmod(str(env_file), 0o644)

        # Create a service file pointing to it
        svc = tmp_path / "app.service"
        svc.write_text(f"[Service]\nEnvironmentFile={env_file}\nExecStart=/usr/bin/app\n")

        scanner = Scanner(selected_rules=["PF-SYSD-004"])
        findings = scanner.scan_path(str(svc))
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-SYSD-004"

    def test_safe_0600_envfile(self, tmp_path):
        env_file = tmp_path / "secrets.env"
        env_file.write_text("DB_PASSWORD=secret\n")
        os.chmod(str(env_file), 0o600)

        svc = tmp_path / "app.service"
        svc.write_text(f"[Service]\nEnvironmentFile={env_file}\nExecStart=/usr/bin/app\n")

        scanner = Scanner(selected_rules=["PF-SYSD-004"])
        findings = scanner.scan_path(str(svc))
        assert len(findings) == 0


class TestSystemdExecStartElevated:
    """PF-SYSD-005: ExecStart with sudo/su."""

    def test_detects_sudo_in_execstart(self, make_file):
        path = make_file(
            "elevated.service",
            """\
            [Unit]
            Description=Elevated Service

            [Service]
            ExecStart=sudo /usr/bin/app
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-SYSD-005"

    def test_detects_full_sudo_path(self, make_file):
        path = make_file(
            "elevated.service",
            """\
            [Service]
            ExecStart=/usr/bin/sudo /opt/app/run.sh
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_direct_exec(self, make_file):
        path = make_file(
            "normal.service",
            """\
            [Service]
            User=appuser
            ExecStart=/usr/bin/app
            """,
        )
        scanner = Scanner(selected_rules=["PF-SYSD-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


# =========================================================================
# Docker (PF-DOCK-004, PF-DOCK-005, PF-DOCK-006) — gap coverage
# =========================================================================


class TestDockerNoSecurityOpt:
    """PF-DOCK-004: Missing security_opt: no-new-privileges."""

    def test_detects_missing_nnp(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp:1.0
                ports:
                  - "8080:8080"
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-DOCK-004"

    def test_safe_with_nnp(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp:1.0
                security_opt:
                  - no-new-privileges:true
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-004"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestDockerHostNetwork:
    """PF-DOCK-005: Host network mode."""

    def test_detects_host_network(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp:1.0
                network_mode: host
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-DOCK-005"

    def test_safe_bridge_network(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp:1.0
                network_mode: bridge
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-005"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


class TestDockerLatestTag:
    """PF-DOCK-006: Latest tag usage."""

    def test_detects_latest_in_compose(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp:latest
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-006"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-DOCK-006"

    def test_detects_no_tag_in_compose(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              web:
                image: nginx
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-006"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_detects_latest_in_dockerfile(self, make_file):
        path = make_file(
            "Dockerfile",
            """\
            FROM python:latest
            WORKDIR /app
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-006"])
        findings = scanner.scan_path(path)
        assert len(findings) == 1

    def test_safe_pinned_version(self, make_file):
        path = make_file(
            "docker-compose.yml",
            """\
            services:
              app:
                image: myapp:2.1.0
            """,
        )
        scanner = Scanner(selected_rules=["PF-DOCK-006"])
        findings = scanner.scan_path(path)
        assert len(findings) == 0


# =========================================================================
# Permissions (PF-PERM-003, PF-PERM-004) — gap coverage
# =========================================================================


class TestPermSuidSgid:
    """PF-PERM-003: SUID/SGID on scripts."""

    def test_detects_suid_on_script(self, tmp_path):
        fpath = tmp_path / "deploy.sh"
        fpath.write_text("#!/bin/bash\necho deploy\n")
        os.chmod(str(fpath), 0o4755)  # SUID bit set
        scanner = Scanner(selected_rules=["PF-PERM-003"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-PERM-003"
        assert findings[0].severity.name == "CRITICAL"

    def test_detects_sgid_on_python(self, tmp_path):
        fpath = tmp_path / "admin.py"
        fpath.write_text("# admin script\n")
        os.chmod(str(fpath), 0o2755)  # SGID bit set
        scanner = Scanner(selected_rules=["PF-PERM-003"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 1

    def test_safe_normal_permissions(self, tmp_path):
        fpath = tmp_path / "script.sh"
        fpath.write_text("#!/bin/bash\n")
        os.chmod(str(fpath), 0o755)
        scanner = Scanner(selected_rules=["PF-PERM-003"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 0


class TestPermPrivateKeyWorldReadable:
    """PF-PERM-004: Private key files world-readable."""

    def test_detects_world_readable_pem(self, tmp_path):
        fpath = tmp_path / "server.pem"
        fpath.write_text("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n")
        os.chmod(str(fpath), 0o644)
        scanner = Scanner(selected_rules=["PF-PERM-004"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 1
        assert findings[0].rule_id == "PF-PERM-004"
        assert findings[0].severity.name == "CRITICAL"

    def test_detects_group_readable_key(self, tmp_path):
        fpath = tmp_path / "server.key"
        fpath.write_text("key content\n")
        os.chmod(str(fpath), 0o640)
        scanner = Scanner(selected_rules=["PF-PERM-004"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 1

    def test_safe_0600_key(self, tmp_path):
        fpath = tmp_path / "server.pem"
        fpath.write_text("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n")
        os.chmod(str(fpath), 0o600)
        scanner = Scanner(selected_rules=["PF-PERM-004"])
        findings = scanner.scan_path(str(fpath))
        assert len(findings) == 0
