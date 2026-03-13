"""Docker security rules (PF-DOCK-001 .. PF-DOCK-008)."""

import os
import re
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _is_dockerfile(fn: str) -> bool:
    basename = os.path.basename(fn)
    return basename.startswith("Dockerfile") or basename == "Containerfile"


def _is_compose(fn: str) -> bool:
    basename = os.path.basename(fn).lower()
    return basename in (
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    )


def _is_docker_related(fn: str) -> bool:
    return _is_dockerfile(fn) or _is_compose(fn)


# ---------------------------------------------------------------------------
# PF-DOCK-001  Container running as root (no USER in Dockerfile)
# ---------------------------------------------------------------------------

@register_rule
class DockerRunAsRoot(BaseRule):
    rule_id = "PF-DOCK-001"
    name = "Container Running as Root"
    description = "Dockerfile has no USER directive, so the container runs as root."
    severity = Severity.MEDIUM
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_dockerfile(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        has_user = bool(re.search(r"^\s*USER\s+\S+", content, re.MULTILINE | re.IGNORECASE))
        has_from = bool(re.search(r"^\s*FROM\s+", content, re.MULTILINE | re.IGNORECASE))
        if has_from and not has_user:
            # Report at the last FROM line
            last_from_line = 1
            for i, line in enumerate(content.splitlines(), 1):
                if re.match(r"^\s*FROM\s+", line, re.IGNORECASE):
                    last_from_line = i
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.name,
                    description=self.description,
                    file_path=filepath,
                    line_number=last_from_line,
                    snippet=_get_line(content, last_from_line).strip(),
                    cwe=self.cwe,
                    recommendation="Add a USER directive to run as a non-root user.",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# PF-DOCK-002  Docker socket mounted
# ---------------------------------------------------------------------------

_DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock")


@register_rule
class DockerSocketMounted(BaseRule):
    rule_id = "PF-DOCK-002"
    name = "Docker Socket Mounted"
    description = "Docker socket is bind-mounted, granting container full host Docker API access."
    severity = Severity.CRITICAL
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_compose(filename) or _is_dockerfile(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if _DOCKER_SOCK_RE.search(line):
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
                        recommendation="Avoid mounting the Docker socket. Use Docker-in-Docker or a Docker proxy with ACLs.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-DOCK-003  Privileged mode
# ---------------------------------------------------------------------------

_PRIVILEGED_RE = re.compile(r"privileged\s*:\s*true", re.IGNORECASE)


@register_rule
class DockerPrivilegedMode(BaseRule):
    rule_id = "PF-DOCK-003"
    name = "Docker Privileged Mode"
    description = "Container runs in privileged mode, disabling all security isolation."
    severity = Severity.CRITICAL
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_compose(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if _PRIVILEGED_RE.search(line):
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
                        recommendation="Remove privileged: true. Use specific capabilities with cap_add if needed.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-DOCK-004  No security_opt (no-new-privileges)
# ---------------------------------------------------------------------------

@register_rule
class DockerNoSecurityOpt(BaseRule):
    rule_id = "PF-DOCK-004"
    name = "Missing security_opt: no-new-privileges"
    description = "Compose service lacks security_opt with no-new-privileges."
    severity = Severity.LOW
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_compose(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        # Look for services that do not have no-new-privileges
        # Simple heuristic: find service blocks (indentation-based)
        in_services = False
        current_service = None
        current_service_line = 0
        has_nnp = False
        service_blocks: List[dict] = []

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped == "services:":
                in_services = True
                continue
            if in_services and stripped and not line.startswith(" ") and not line.startswith("\t"):
                in_services = False

            if in_services:
                # Detect service names (2-space indent, not a list item)
                indent = len(line) - len(line.lstrip())
                if indent == 2 and stripped.endswith(":") and not stripped.startswith("-"):
                    # Save previous service
                    if current_service is not None:
                        service_blocks.append({
                            "name": current_service,
                            "line": current_service_line,
                            "has_nnp": has_nnp,
                        })
                    current_service = stripped.rstrip(":")
                    current_service_line = i
                    has_nnp = False
                if "no-new-privileges" in stripped:
                    has_nnp = True

        # Save last service
        if current_service is not None:
            service_blocks.append({
                "name": current_service,
                "line": current_service_line,
                "has_nnp": has_nnp,
            })

        for svc in service_blocks:
            if not svc["has_nnp"]:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=f"{self.name} ({svc['name']})",
                        description=f"Service '{svc['name']}' lacks security_opt: no-new-privileges.",
                        file_path=filepath,
                        line_number=svc["line"],
                        snippet=_get_line(content, svc["line"]).strip(),
                        cwe=self.cwe,
                        recommendation="Add security_opt: [no-new-privileges:true] to each service.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-DOCK-005  Host network mode with ports
# ---------------------------------------------------------------------------

_NET_HOST_RE = re.compile(r"network_mode\s*:\s*[\"']?host", re.IGNORECASE)


@register_rule
class DockerHostNetwork(BaseRule):
    rule_id = "PF-DOCK-005"
    name = "Host Network Mode"
    description = "Container uses host network mode, bypassing Docker network isolation."
    severity = Severity.HIGH
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_compose(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if _NET_HOST_RE.search(line):
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
                        recommendation="Use bridge networking with explicit port mappings instead of host mode.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-DOCK-006  Latest tag usage
# ---------------------------------------------------------------------------

_LATEST_TAG_RE = re.compile(r"(?:FROM\s+\S+|image\s*:\s*\S+):latest\b", re.IGNORECASE)
_IMAGE_NO_TAG_RE = re.compile(r"image\s*:\s*([A-Za-z0-9_/.\-]+)\s*$")


@register_rule
class DockerLatestTag(BaseRule):
    rule_id = "PF-DOCK-006"
    name = "Latest Tag Usage"
    description = "Using ':latest' or no tag makes builds non-reproducible and vulnerable to supply-chain attacks."
    severity = Severity.LOW
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_docker_related(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _LATEST_TAG_RE.search(line):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=self.description,
                        file_path=filepath,
                        line_number=i,
                        snippet=stripped,
                        cwe=self.cwe,
                        recommendation="Pin to a specific version tag or digest.",
                    )
                )
            elif _IMAGE_NO_TAG_RE.search(stripped):
                image_name = _IMAGE_NO_TAG_RE.search(stripped).group(1)
                if image_name.lower() not in ("scratch",):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=f"Image '{image_name}' has no explicit tag (defaults to :latest).",
                            file_path=filepath,
                            line_number=i,
                            snippet=stripped,
                            cwe=self.cwe,
                            recommendation="Pin to a specific version tag or digest.",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-DOCK-007  Secrets in ENV/ARG
# ---------------------------------------------------------------------------

_DOCKER_SECRET_ENV_RE = re.compile(
    r"^\s*(?:ENV|ARG)\s+\S*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\S*\s*=\s*\S+",
    re.IGNORECASE,
)


@register_rule
class DockerSecretsInEnv(BaseRule):
    rule_id = "PF-DOCK-007"
    name = "Secrets in Docker ENV/ARG"
    description = "Sensitive values are baked into the Docker image via ENV or ARG directives."
    severity = Severity.HIGH
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_dockerfile(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _DOCKER_SECRET_ENV_RE.match(stripped):
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
                        recommendation="Pass secrets at runtime via docker run --env-file or Docker secrets.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-DOCK-008  No health check
# ---------------------------------------------------------------------------

@register_rule
class DockerNoHealthcheck(BaseRule):
    rule_id = "PF-DOCK-008"
    name = "No Docker HEALTHCHECK"
    description = "Dockerfile has no HEALTHCHECK, so Docker cannot detect an unhealthy container."
    severity = Severity.LOW
    cwe = 250

    def applies_to(self, filename: str) -> bool:
        return _is_dockerfile(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        has_healthcheck = bool(
            re.search(r"^\s*HEALTHCHECK\s+", content, re.MULTILINE | re.IGNORECASE)
        )
        has_from = bool(
            re.search(r"^\s*FROM\s+", content, re.MULTILINE | re.IGNORECASE)
        )
        if has_from and not has_healthcheck:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.name,
                    description=self.description,
                    file_path=filepath,
                    line_number=1,
                    snippet="(no HEALTHCHECK directive found)",
                    cwe=self.cwe,
                    recommendation="Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1 (or equivalent).",
                )
            )
        return findings
