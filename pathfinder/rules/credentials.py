"""Credential and secret detection rules (PF-CRED-001 .. PF-CRED-006)."""

import ast
import re
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_line(content: str, lineno: int) -> str:
    """Return the *lineno*-th line (1-based) or an empty string."""
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _is_python(filename: str) -> bool:
    return filename.endswith(".py")


def _is_config_file(filename: str) -> bool:
    lower = filename.lower()
    return any(
        lower.endswith(ext)
        for ext in (".env", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".json")
    )


# ---------------------------------------------------------------------------
# PF-CRED-001  Private key in env / config
# ---------------------------------------------------------------------------

_PRIVATE_KEY_HEX_RE = re.compile(
    r"PRIVATE_KEY\s*=\s*[\"']?0x[0-9a-fA-F]{64}", re.IGNORECASE
)


@register_rule
class PrivateKeyInConfig(BaseRule):
    rule_id = "PF-CRED-001"
    name = "Private Key in Config"
    description = "A hexadecimal private key is embedded directly in a configuration or source file."
    severity = Severity.CRITICAL
    cwe = 798

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename) or _is_config_file(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if _PRIVATE_KEY_HEX_RE.search(line):
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
                        recommendation="Store private keys in a secrets manager or encrypted vault, never in source/config files.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-CRED-002  API key in source
# ---------------------------------------------------------------------------

_API_KEY_RE = re.compile(
    r"""(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}""",
    re.IGNORECASE,
)


@register_rule
class ApiKeyInSource(BaseRule):
    rule_id = "PF-CRED-002"
    name = "API Key in Source"
    description = "An API key, secret, or access token appears to be hardcoded."
    severity = Severity.HIGH
    cwe = 798

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename) or _is_config_file(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            # Skip comment-only lines
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if _API_KEY_RE.search(line):
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
                        recommendation="Use environment variables or a secrets manager instead of hardcoding API keys.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-CRED-003  Password with default fallback (AST)
# ---------------------------------------------------------------------------

@register_rule
class PasswordDefaultFallback(BaseRule):
    rule_id = "PF-CRED-003"
    name = "Password Default Fallback"
    description = "os.getenv() for a password/secret variable has a hardcoded default value."
    severity = Severity.HIGH
    cwe = 798

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
            # Match os.getenv("...", "default") or os.environ.get("...", "default")
            func = node.func
            is_getenv = False
            if isinstance(func, ast.Attribute) and func.attr in ("getenv", "get"):
                is_getenv = True
            if not is_getenv:
                continue
            if len(node.args) < 1:
                continue
            # First arg should be a string containing PASS, SECRET, KEY, TOKEN
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant) or not isinstance(first_arg.value, str):
                continue
            var_name = first_arg.value.upper()
            sensitive_keywords = ("PASS", "SECRET", "KEY", "TOKEN", "CREDENTIAL")
            if not any(kw in var_name for kw in sensitive_keywords):
                continue
            # Must have a non-empty default (2nd arg or default kwarg)
            default_val = None
            if len(node.args) >= 2:
                default_val = node.args[1]
            else:
                for kw in node.keywords:
                    if kw.arg == "default":
                        default_val = kw.value
                        break
            if default_val is None:
                continue
            if isinstance(default_val, ast.Constant) and isinstance(default_val.value, str):
                if default_val.value.strip():
                    lineno = node.lineno
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=self.description,
                            file_path=filepath,
                            line_number=lineno,
                            snippet=_get_line(content, lineno),
                            cwe=self.cwe,
                            recommendation="Remove default password values. Fail explicitly when credentials are missing.",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-CRED-004  Hardcoded JWT / Bearer token
# ---------------------------------------------------------------------------

_JWT_RE = re.compile(
    r"""(?:bearer|jwt|authorization)\s*[=:]\s*["'](?:Bearer\s+)?eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+""",
    re.IGNORECASE,
)


@register_rule
class HardcodedJwtToken(BaseRule):
    rule_id = "PF-CRED-004"
    name = "Hardcoded JWT/Bearer Token"
    description = "A JWT or Bearer token is hardcoded in source."
    severity = Severity.HIGH
    cwe = 798

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename) or _is_config_file(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if _JWT_RE.search(line):
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
                        recommendation="Never embed tokens in code. Retrieve them at runtime from a secure token store.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-CRED-005  AWS / GCP / Azure credential patterns
# ---------------------------------------------------------------------------

_CLOUD_CRED_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                                              # AWS access key
    re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S{30,}"),  # AWS secret
    re.compile(r'"type"\s*:\s*"service_account"'),                                 # GCP service account JSON
    re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),                                # GCP key file  # pathfinder: ignore
    re.compile(r"(?:AZURE_CLIENT_SECRET|AZURE_TENANT_ID)\s*[=:]\s*\S{10,}", re.IGNORECASE),
]


@register_rule
class CloudCredentials(BaseRule):
    rule_id = "PF-CRED-005"
    name = "Cloud Provider Credentials"
    description = "AWS, GCP, or Azure credentials detected in source or configuration."
    severity = Severity.CRITICAL
    cwe = 798

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename) or _is_config_file(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            for pat in _CLOUD_CRED_PATTERNS:
                if pat.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=self.description,
                            file_path=filepath,
                            line_number=i,
                            snippet=line.strip()[:120],
                            cwe=self.cwe,
                            recommendation="Rotate exposed credentials immediately. Use IAM roles, managed identities, or a vault.",
                        )
                    )
                    break  # one match per line is enough
        return findings


# ---------------------------------------------------------------------------
# PF-CRED-006  SSH private key content
# ---------------------------------------------------------------------------

_SSH_KEY_RE = re.compile(r"-----BEGIN\s+\S*\s*PRIVATE KEY-----")


@register_rule
class SshPrivateKey(BaseRule):
    rule_id = "PF-CRED-006"
    name = "SSH Private Key Content"
    description = "An SSH or other private key block is present in this file."
    severity = Severity.CRITICAL
    cwe = 798

    def applies_to(self, filename: str) -> bool:
        return True  # Any file type

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if _SSH_KEY_RE.search(line):
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
                        recommendation="Remove the private key from source. Store in a secrets manager with strict ACLs.",
                    )
                )
        return findings
