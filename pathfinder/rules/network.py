"""Network exposure rules (PF-NET-001 .. PF-NET-004)."""

import re
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _is_relevant(fn: str) -> bool:
    lower = fn.lower()
    return any(
        lower.endswith(ext)
        for ext in (
            ".py", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".json",
            ".service",
        )
    )


# ---------------------------------------------------------------------------
# PF-NET-001  Binding to 0.0.0.0
# ---------------------------------------------------------------------------

_BIND_ALL_RE = re.compile(
    r"""(?:host|bind|address|listen)\s*[=:]\s*["']?0\.0\.0\.0""",
    re.IGNORECASE,
)


@register_rule
class BindAllInterfaces(BaseRule):
    rule_id = "PF-NET-001"
    name = "Binding to 0.0.0.0"
    description = "Service binds to all network interfaces (0.0.0.0), exposing it to the network."
    severity = Severity.MEDIUM
    cwe = 668

    def applies_to(self, filename: str) -> bool:
        return _is_relevant(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if _BIND_ALL_RE.search(line):
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
                        recommendation="Bind to 127.0.0.1 unless external access is explicitly required.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-NET-002  Binding to :: (IPv6 wildcard)
# ---------------------------------------------------------------------------

_BIND_IPV6_ALL_RE = re.compile(
    r"""(?:host|bind|address|listen)\s*[=:]\s*["']?::(?:["'\s]|$)""",
    re.IGNORECASE,
)


@register_rule
class BindAllIPv6(BaseRule):
    rule_id = "PF-NET-002"
    name = "Binding to :: (IPv6 Wildcard)"
    description = "Service binds to all IPv6 interfaces (::), exposing it to the network."
    severity = Severity.MEDIUM
    cwe = 668

    def applies_to(self, filename: str) -> bool:
        return _is_relevant(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if _BIND_IPV6_ALL_RE.search(line):
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
                        recommendation="Bind to ::1 (IPv6 localhost) unless external access is explicitly required.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-NET-003  Debug mode enabled
# ---------------------------------------------------------------------------

_DEBUG_RE = re.compile(
    r"""(?:^|\s)debug\s*=\s*(?:True|true|1|"true"|'true')""",
    re.IGNORECASE,
)


@register_rule
class DebugEnabled(BaseRule):
    rule_id = "PF-NET-003"
    name = "Debug Mode Enabled"
    description = "Debug mode is enabled, which may expose stack traces, secrets, or performance data."
    severity = Severity.MEDIUM
    cwe = 668

    def applies_to(self, filename: str) -> bool:
        return _is_relevant(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if _DEBUG_RE.search(line):
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
                        recommendation="Disable debug mode in production. Use environment-based configuration.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-NET-004  Dangerous ports exposed without localhost bind
# ---------------------------------------------------------------------------

_DANGEROUS_PORTS = {
    "5432": "PostgreSQL",
    "3306": "MySQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "6380": "Redis",
    "11211": "Memcached",
    "9200": "Elasticsearch",
    "5672": "RabbitMQ",
    "2379": "etcd",
    "8500": "Consul",
}

_PORT_EXPOSE_RE = re.compile(
    r"""(?:port|ports)\s*[=:]\s*["']?(\d{4,5})(?:["'\s:/-]|$)""",
    re.IGNORECASE,
)


@register_rule
class DangerousPortExposed(BaseRule):
    rule_id = "PF-NET-004"
    name = "Dangerous Port Exposed"
    description = "A database or cache port is exposed without explicit localhost binding."
    severity = Severity.MEDIUM
    cwe = 668

    def applies_to(self, filename: str) -> bool:
        return _is_relevant(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            match = _PORT_EXPOSE_RE.search(line)
            if match:
                port = match.group(1)
                if port in _DANGEROUS_PORTS:
                    # Check if the same line or surrounding context has 127.0.0.1 or localhost
                    context = line
                    if i > 1:
                        context = lines[i - 2] + " " + context
                    if i < len(lines):
                        context = context + " " + lines[i]
                    if "127.0.0.1" not in context and "localhost" not in context and "::1" not in context:
                        svc_name = _DANGEROUS_PORTS[port]
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                title=f"{self.name} ({svc_name}:{port})",
                                description=f"{svc_name} port {port} appears exposed without localhost binding.",
                                file_path=filepath,
                                line_number=i,
                                snippet=stripped,
                                cwe=self.cwe,
                                recommendation=f"Bind {svc_name} to 127.0.0.1:{port} to prevent network exposure.",
                            )
                        )
        return findings
