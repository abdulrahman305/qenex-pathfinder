"""Dependency security rules (PF-DEP-001 .. PF-DEP-003)."""

import os
import re
from typing import Dict, List, Optional, Tuple

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


# ---------------------------------------------------------------------------
# PF-DEP-001  Unpinned dependency in requirements.txt
# ---------------------------------------------------------------------------

_PINNED_RE = re.compile(r"^[A-Za-z0-9_\-\[\]]+\s*==")
_SKIP_RE = re.compile(r"^\s*(#|$|-)")  # comments, blanks, options


@register_rule
class UnpinnedDependency(BaseRule):
    rule_id = "PF-DEP-001"
    name = "Unpinned Dependency"
    description = "Dependency is not pinned to an exact version (missing ==), risking supply-chain attacks."
    severity = Severity.LOW
    cwe = 1104

    def applies_to(self, filename: str) -> bool:
        return os.path.basename(filename) == "requirements.txt"

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if _SKIP_RE.match(stripped):
                continue
            if not _PINNED_RE.match(stripped):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=f"Dependency '{stripped.split()[0]}' is not pinned with ==.",
                        file_path=filepath,
                        line_number=i,
                        snippet=stripped,
                        cwe=self.cwe,
                        recommendation="Pin dependencies with == (e.g., requests==2.32.3) and use pip-audit.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-DEP-002  Unpinned Docker base image
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)", re.IGNORECASE)


@register_rule
class UnpinnedDockerImage(BaseRule):
    rule_id = "PF-DEP-002"
    name = "Unpinned Docker Base Image"
    description = "Docker base image is not pinned to a digest (@sha256:) or specific tag."
    severity = Severity.MEDIUM
    cwe = 1104

    def applies_to(self, filename: str) -> bool:
        basename = os.path.basename(filename)
        return basename.startswith("Dockerfile") or basename == "Containerfile"

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            match = _FROM_RE.match(line)
            if not match:
                continue
            image = match.group(1)
            if image.lower() == "scratch":
                continue
            has_digest = "@sha256:" in image
            has_tag = ":" in image.split("@")[0]

            if not has_digest and not has_tag:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=f"Image '{image}' has no tag or digest pin.",
                        file_path=filepath,
                        line_number=i,
                        snippet=line.strip(),
                        cwe=self.cwe,
                        recommendation="Pin with a digest: FROM image@sha256:... or at minimum a versioned tag.",
                    )
                )
            elif has_tag and not has_digest:
                tag = image.split(":")[-1]
                if tag in ("latest", "stable", "nightly"):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=f"Image '{image}' uses a floating tag '{tag}'.",
                            file_path=filepath,
                            line_number=i,
                            snippet=line.strip(),
                            cwe=self.cwe,
                            recommendation="Pin to a specific version tag or digest instead of a floating tag.",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-DEP-003  Known vulnerable package
# ---------------------------------------------------------------------------

# Mapping: package_name_lower -> (vulnerable_spec, fixed_version)
_KNOWN_VULNERABLE: Dict[str, Tuple[str, str]] = {
    "pyyaml": ("<6.0", "6.0+"),
    "cryptography": ("<42.0", "42.0+"),
    "requests": ("<2.32", "2.32+"),
    "pillow": ("<10.3", "10.3+"),
    "urllib3": ("<2.0.7", "2.0.7+"),
    "django": ("<4.2.11", "4.2.11+"),
    "flask": ("<3.0", "3.0+"),
    "jinja2": ("<3.1.3", "3.1.3+"),
    "werkzeug": ("<3.0.1", "3.0.1+"),
    "certifi": ("<2023.7.22", "2023.7.22+"),
}


def _parse_version(ver_str: str) -> Optional[Tuple[int, ...]]:
    """Parse a version string into a tuple of ints for comparison."""
    try:
        parts = ver_str.strip().split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return None


def _parse_vuln_version(spec: str) -> Optional[Tuple[int, ...]]:
    """Parse '<X.Y.Z' into (X, Y, Z)."""
    cleaned = spec.lstrip("<").strip()
    return _parse_version(cleaned)


@register_rule
class KnownVulnerablePackage(BaseRule):
    rule_id = "PF-DEP-003"
    name = "Known Vulnerable Package"
    description = "A dependency is at a version known to have security vulnerabilities."
    severity = Severity.HIGH
    cwe = 1104

    def applies_to(self, filename: str) -> bool:
        return os.path.basename(filename) == "requirements.txt"

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if _SKIP_RE.match(stripped):
                continue
            # Parse package==version
            eq_match = re.match(r"^([A-Za-z0-9_\-]+)\s*==\s*([^\s;#]+)", stripped)
            if not eq_match:
                # Try >=, <=, ~= patterns too
                ineq_match = re.match(r"^([A-Za-z0-9_\-]+)\s*[><=~!]+\s*([^\s;#,]+)", stripped)
                if ineq_match:
                    eq_match = ineq_match
            if not eq_match:
                continue
            pkg_name = eq_match.group(1).lower().replace("-", "").replace("_", "")
            pkg_version = eq_match.group(2)

            # Normalize package name for lookup
            for known_pkg, (vuln_spec, fixed) in _KNOWN_VULNERABLE.items():
                normalized_known = known_pkg.lower().replace("-", "").replace("_", "")
                if pkg_name != normalized_known:
                    continue
                installed = _parse_version(pkg_version)
                threshold = _parse_vuln_version(vuln_spec)
                if installed is not None and threshold is not None:
                    if installed < threshold:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                title=f"{self.name}: {known_pkg}",
                                description=f"{known_pkg}=={pkg_version} has known vulnerabilities (fixed in {fixed}).",
                                file_path=filepath,
                                line_number=i,
                                snippet=stripped,
                                cwe=self.cwe,
                                recommendation=f"Upgrade {known_pkg} to {fixed} or later.",
                            )
                        )
        return findings
