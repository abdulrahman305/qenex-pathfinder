"""systemd unit file security rules (PF-SYSD-001 .. PF-SYSD-005)."""

import os
import re
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule


def _is_systemd(fn: str) -> bool:
    lower = fn.lower()
    return lower.endswith((".service", ".timer", ".socket", ".conf"))


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


# ---------------------------------------------------------------------------
# PF-SYSD-001  Secret in Environment= directive
# ---------------------------------------------------------------------------

_ENV_SECRET_RE = re.compile(
    r"^Environment\s*=.*(?:KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE)\s*=\S+",
    re.IGNORECASE | re.MULTILINE,
)


@register_rule
class SecretInEnvironmentDirective(BaseRule):
    rule_id = "PF-SYSD-001"
    name = "Secret in systemd Environment="
    description = "Sensitive value embedded directly in a systemd Environment= directive (visible via systemctl show)."
    severity = Severity.HIGH
    cwe = 522

    def applies_to(self, filename: str) -> bool:
        return _is_systemd(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _ENV_SECRET_RE.match(stripped):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=self.description,
                        file_path=filepath,
                        line_number=i,
                        snippet=stripped[:120],
                        cwe=self.cwe,
                        recommendation="Use EnvironmentFile= with a 0600-permissioned file instead of inline Environment=.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-SYSD-002  Missing ProtectSystem
# ---------------------------------------------------------------------------

@register_rule
class MissingProtectSystem(BaseRule):
    rule_id = "PF-SYSD-002"
    name = "Missing ProtectSystem"
    description = "systemd service file lacks ProtectSystem=, leaving the filesystem unprotected."
    severity = Severity.LOW
    cwe = 522

    def applies_to(self, filename: str) -> bool:
        return filename.endswith(".service")

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        has_service = "[Service]" in content
        has_protect = "ProtectSystem" in content

        if has_service and not has_protect:
            # Find the [Service] line for a reference
            for i, line in enumerate(content.splitlines(), 1):
                if "[Service]" in line:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=self.description,
                            file_path=filepath,
                            line_number=i,
                            snippet=line.strip(),
                            cwe=self.cwe,
                            recommendation="Add ProtectSystem=strict (or at least ProtectSystem=full) to the [Service] section.",
                        )
                    )
                    break
        return findings


# ---------------------------------------------------------------------------
# PF-SYSD-003  Running as root without hardening
# ---------------------------------------------------------------------------

@register_rule
class RootWithoutHardening(BaseRule):
    rule_id = "PF-SYSD-003"
    name = "Root Without Hardening"
    description = "Service runs as root without NoNewPrivileges=yes."
    severity = Severity.MEDIUM
    cwe = 522

    def applies_to(self, filename: str) -> bool:
        return filename.endswith(".service")

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        has_service = "[Service]" in content
        if not has_service:
            return findings

        # Check if User= is set to a non-root user
        user_match = re.search(r"^User\s*=\s*(\S+)", content, re.MULTILINE)
        is_root = True
        if user_match:
            user = user_match.group(1)
            if user != "root":
                is_root = False

        if not is_root:
            return findings

        has_nnp = bool(re.search(r"NoNewPrivileges\s*=\s*(yes|true|1)", content, re.IGNORECASE))
        if not has_nnp:
            for i, line in enumerate(content.splitlines(), 1):
                if "[Service]" in line:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=self.description,
                            file_path=filepath,
                            line_number=i,
                            snippet=line.strip(),
                            cwe=self.cwe,
                            recommendation="Add NoNewPrivileges=yes, or run as a dedicated non-root user.",
                        )
                    )
                    break
        return findings


# ---------------------------------------------------------------------------
# PF-SYSD-004  World-readable secret file in EnvironmentFile
# ---------------------------------------------------------------------------

_ENV_FILE_RE = re.compile(r"^EnvironmentFile\s*=\s*-?\s*(.+)", re.MULTILINE)


@register_rule
class WorldReadableEnvFile(BaseRule):
    rule_id = "PF-SYSD-004"
    name = "World-Readable EnvironmentFile"
    description = "EnvironmentFile points to a file that may contain secrets and is world-readable."
    severity = Severity.HIGH
    cwe = 522

    def applies_to(self, filename: str) -> bool:
        return _is_systemd(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = _ENV_FILE_RE.match(stripped)
            if not match:
                continue
            env_path = match.group(1).strip()
            # Skip if prefixed with - (optional)
            if env_path.startswith("-"):
                env_path = env_path[1:].strip()
            if not os.path.isabs(env_path):
                continue
            try:
                st = os.stat(env_path)
                mode = st.st_mode
                if mode & 0o044:  # world or group readable
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=f"EnvironmentFile {env_path} is readable by group/others (mode {oct(mode & 0o777)}).",
                            file_path=filepath,
                            line_number=i,
                            snippet=stripped,
                            cwe=self.cwe,
                            recommendation=f"chmod 0600 {env_path} to restrict access to the owning user only.",
                        )
                    )
            except OSError:
                pass  # file may not exist on the scanning machine
        return findings


# ---------------------------------------------------------------------------
# PF-SYSD-005  ExecStart with elevated privileges without restrictions
# ---------------------------------------------------------------------------

_EXEC_ELEVATED_RE = re.compile(
    r"^ExecStart\s*=\s*.*(?:sudo|/usr/bin/sudo|/bin/su\b)", re.MULTILINE
)


@register_rule
class ExecStartElevated(BaseRule):
    rule_id = "PF-SYSD-005"
    name = "ExecStart with Elevated Privileges"
    description = "ExecStart uses sudo or su, which is unnecessary in systemd and may bypass security controls."
    severity = Severity.MEDIUM
    cwe = 522

    def applies_to(self, filename: str) -> bool:
        return filename.endswith(".service")

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _EXEC_ELEVATED_RE.match(stripped):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=self.description,
                        file_path=filepath,
                        line_number=i,
                        snippet=stripped[:120],
                        cwe=self.cwe,
                        recommendation="Use User=, Group=, and systemd capabilities instead of sudo/su in ExecStart.",
                    )
                )
        return findings
