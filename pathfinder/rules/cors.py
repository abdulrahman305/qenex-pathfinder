"""CORS misconfiguration rules (PF-CORS-001 .. PF-CORS-003)."""

import ast
import re
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _is_python(fn: str) -> bool:
    return fn.endswith(".py")


# ---------------------------------------------------------------------------
# PF-CORS-001  allow_origins=["*"]
# ---------------------------------------------------------------------------

@register_rule
class CorsAllowAllOrigins(BaseRule):
    rule_id = "PF-CORS-001"
    name = "CORS Allow All Origins"
    description = "allow_origins is set to ['*'], permitting requests from any origin."
    severity = Severity.MEDIUM
    cwe = 942

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.keyword):
                continue
            if node.arg not in ("allow_origins", "allowed_origins", "origins"):
                continue
            val = node.value
            # Check for ["*"]
            if isinstance(val, ast.List):
                for elt in val.elts:
                    if isinstance(elt, ast.Constant) and elt.value == "*":
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                title=self.name,
                                description=self.description,
                                file_path=filepath,
                                line_number=node.value.lineno,
                                snippet=_get_line(content, node.value.lineno),
                                cwe=self.cwe,
                                recommendation="Restrict allow_origins to specific trusted domains.",
                            )
                        )
                        break
            # Check for "*" directly
            elif isinstance(val, ast.Constant) and val.value == "*":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=self.description,
                        file_path=filepath,
                        line_number=node.value.lineno,
                        snippet=_get_line(content, node.value.lineno),
                        cwe=self.cwe,
                        recommendation="Restrict allow_origins to specific trusted domains.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-CORS-002  Access-Control-Allow-Origin: * in headers
# ---------------------------------------------------------------------------

_ACAO_RE = re.compile(
    r"""Access-Control-Allow-Origin['":\s]+\*""",
    re.IGNORECASE,
)


@register_rule
class CorsHeaderWildcard(BaseRule):
    rule_id = "PF-CORS-002"
    name = "CORS Header Wildcard"
    description = "Access-Control-Allow-Origin header is set to *, permitting any origin."
    severity = Severity.MEDIUM
    cwe = 942

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename) or filename.endswith((".yml", ".yaml", ".conf"))

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if _ACAO_RE.search(line):
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
                        recommendation="Set Access-Control-Allow-Origin to specific trusted origins.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-CORS-003  allow_credentials with wildcard origin
# ---------------------------------------------------------------------------

@register_rule
class CorsCredentialsWildcard(BaseRule):
    rule_id = "PF-CORS-003"
    name = "CORS Credentials with Wildcard"
    description = "allow_credentials=True combined with a wildcard origin is a critical misconfiguration."
    severity = Severity.HIGH
    cwe = 942

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # Collect keyword arguments
            has_wildcard_origin = False
            has_allow_credentials = False
            call_lineno = node.lineno

            for kw in node.keywords:
                # Check for allow_origins=["*"]
                if kw.arg in ("allow_origins", "allowed_origins", "origins"):
                    val = kw.value
                    if isinstance(val, ast.List):
                        for elt in val.elts:
                            if isinstance(elt, ast.Constant) and elt.value == "*":
                                has_wildcard_origin = True
                    elif isinstance(val, ast.Constant) and val.value == "*":
                        has_wildcard_origin = True
                # Check for allow_credentials=True
                if kw.arg in ("allow_credentials", "supports_credentials"):
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_allow_credentials = True

            if has_wildcard_origin and has_allow_credentials:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=self.description,
                        file_path=filepath,
                        line_number=call_lineno,
                        snippet=_get_line(content, call_lineno),
                        cwe=self.cwe,
                        recommendation="Never combine allow_credentials=True with wildcard origins. Specify trusted origins explicitly.",
                    )
                )
        return findings
