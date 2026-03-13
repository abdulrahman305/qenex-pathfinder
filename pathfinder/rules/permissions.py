"""File permission rules (PF-PERM-001 .. PF-PERM-004)."""

import os
import re
import stat
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


# ---------------------------------------------------------------------------
# PF-PERM-001  World-writable files
# ---------------------------------------------------------------------------

@register_rule
class WorldWritableFile(BaseRule):
    rule_id = "PF-PERM-001"
    name = "World-Writable File"
    description = "File is world-writable, allowing any user to modify it."
    severity = Severity.HIGH
    cwe = 732

    def applies_to(self, filename: str) -> bool:
        return True  # check all files

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            st = os.stat(filepath)
            if st.st_mode & stat.S_IWOTH:
                mode_str = oct(st.st_mode & 0o777)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=f"File {filepath} has world-writable permissions ({mode_str}).",
                        file_path=filepath,
                        line_number=1,
                        snippet=f"permissions: {mode_str}",
                        cwe=self.cwe,
                        recommendation=f"Remove world-write bit: chmod o-w {filepath}",
                    )
                )
        except OSError:
            pass
        return findings


# ---------------------------------------------------------------------------
# PF-PERM-002  Secret files not 0600
# ---------------------------------------------------------------------------

_SECRET_FILE_PATTERNS = re.compile(
    r"(?:secret|key|password|credential|token|\.env|\.pem|\.key|id_rsa|id_ed25519)",
    re.IGNORECASE,
)


@register_rule
class SecretFilePermissions(BaseRule):
    rule_id = "PF-PERM-002"
    name = "Secret File Not 0600"
    description = "A file that likely contains secrets does not have restrictive (0600) permissions."
    severity = Severity.HIGH
    cwe = 732

    def applies_to(self, filename: str) -> bool:
        basename = os.path.basename(filename)
        return bool(_SECRET_FILE_PATTERNS.search(basename))

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            st = os.stat(filepath)
            mode = st.st_mode & 0o777
            if mode != 0o600 and mode != 0o400:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=f"Secret file {filepath} has permissions {oct(mode)} instead of 0600.",
                        file_path=filepath,
                        line_number=1,
                        snippet=f"permissions: {oct(mode)}",
                        cwe=self.cwe,
                        recommendation=f"chmod 0600 {filepath}",
                    )
                )
        except OSError:
            pass
        return findings


# ---------------------------------------------------------------------------
# PF-PERM-003  SUID/SGID on scripts
# ---------------------------------------------------------------------------

@register_rule
class SuidSgidScript(BaseRule):
    rule_id = "PF-PERM-003"
    name = "SUID/SGID on Script"
    description = "Script file has SUID or SGID bit set, allowing privilege escalation."
    severity = Severity.CRITICAL
    cwe = 732

    def applies_to(self, filename: str) -> bool:
        return filename.endswith((".py", ".sh", ".bash", ".pl", ".rb"))

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            st = os.stat(filepath)
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                mode_str = oct(st.st_mode & 0o7777)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=f"Script {filepath} has SUID/SGID bit set ({mode_str}).",
                        file_path=filepath,
                        line_number=1,
                        snippet=f"permissions: {mode_str}",
                        cwe=self.cwe,
                        recommendation=f"Remove SUID/SGID bits: chmod ug-s {filepath}",
                    )
                )
        except OSError:
            pass
        return findings


# ---------------------------------------------------------------------------
# PF-PERM-004  Private key files world-readable
# ---------------------------------------------------------------------------

_KEY_FILE_PATTERNS = re.compile(
    r"(?:\.pem|\.key|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.p12|\.pfx)$",
    re.IGNORECASE,
)


@register_rule
class PrivateKeyWorldReadable(BaseRule):
    rule_id = "PF-PERM-004"
    name = "Private Key File World-Readable"
    description = "A private key file is readable by group or others."
    severity = Severity.CRITICAL
    cwe = 732

    def applies_to(self, filename: str) -> bool:
        return bool(_KEY_FILE_PATTERNS.search(filename))

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            st = os.stat(filepath)
            mode = st.st_mode & 0o777
            if mode & 0o044:  # group or other readable
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=f"Private key file {filepath} is readable by group/others ({oct(mode)}).",
                        file_path=filepath,
                        line_number=1,
                        snippet=f"permissions: {oct(mode)}",
                        cwe=self.cwe,
                        recommendation=f"chmod 0600 {filepath} to restrict access.",
                    )
                )
        except OSError:
            pass
        return findings
