"""Weak cryptography rules (PF-CRYP-001 .. PF-CRYP-005)."""

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
# PF-CRYP-001  MD5 usage
# ---------------------------------------------------------------------------

@register_rule
class Md5Usage(BaseRule):
    rule_id = "PF-CRYP-001"
    name = "MD5 Hash Usage"
    description = "MD5 is cryptographically broken and should not be used for security purposes."
    severity = Severity.MEDIUM
    cwe = 328

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
            func = node.func
            # hashlib.md5(...)
            if isinstance(func, ast.Attribute) and func.attr == "md5":
                if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=self.description,
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet=_get_line(content, node.lineno),
                            cwe=self.cwe,
                            recommendation="Use hashlib.sha256() or hashlib.sha3_256() instead of MD5.",
                        )
                    )
            # hashlib.new("md5")
            if isinstance(func, ast.Attribute) and func.attr == "new":
                if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if arg.value.lower() == "md5":
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        severity=self.severity,
                                        title=self.name,
                                        description=self.description,
                                        file_path=filepath,
                                        line_number=node.lineno,
                                        snippet=_get_line(content, node.lineno),
                                        cwe=self.cwe,
                                        recommendation="Use hashlib.sha256() or hashlib.sha3_256() instead of MD5.",
                                    )
                                )
        return findings


# ---------------------------------------------------------------------------
# PF-CRYP-002  SHA1 usage
# ---------------------------------------------------------------------------

@register_rule
class Sha1Usage(BaseRule):
    rule_id = "PF-CRYP-002"
    name = "SHA1 Hash Usage"
    description = "SHA1 is cryptographically weakened and should not be used for security purposes."
    severity = Severity.MEDIUM
    cwe = 328

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
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "sha1":
                if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=self.description,
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet=_get_line(content, node.lineno),
                            cwe=self.cwe,
                            recommendation="Use hashlib.sha256() or hashlib.sha3_256() instead of SHA1.",
                        )
                    )
            if isinstance(func, ast.Attribute) and func.attr == "new":
                if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                    if node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if arg.value.lower() == "sha1":
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        severity=self.severity,
                                        title=self.name,
                                        description=self.description,
                                        file_path=filepath,
                                        line_number=node.lineno,
                                        snippet=_get_line(content, node.lineno),
                                        cwe=self.cwe,
                                        recommendation="Use hashlib.sha256() or hashlib.sha3_256() instead of SHA1.",
                                    )
                                )
        return findings


# ---------------------------------------------------------------------------
# PF-CRYP-003  DES / 3DES usage
# ---------------------------------------------------------------------------

@register_rule
class DesUsage(BaseRule):
    rule_id = "PF-CRYP-003"
    name = "DES/3DES Usage"
    description = "DES and 3DES are deprecated ciphers with known weaknesses."
    severity = Severity.HIGH
    cwe = 327

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        _DES_NAMES = {"DES", "DES3", "TripleDES", "DES_EDE3"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr in _DES_NAMES:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.name,
                        description=self.description,
                        file_path=filepath,
                        line_number=node.lineno,
                        snippet=_get_line(content, node.lineno),
                        cwe=self.cwe,
                        recommendation="Use AES-256-GCM or ChaCha20-Poly1305 instead of DES/3DES.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-CRYP-004  random module for crypto
# ---------------------------------------------------------------------------

_CRYPTO_CONTEXT_RE = re.compile(
    r"\b(password|token|key|secret|nonce|salt|otp|pin)\b", re.IGNORECASE
)


@register_rule
class RandomForCrypto(BaseRule):
    rule_id = "PF-CRYP-004"
    name = "Random Module for Crypto"
    description = "The 'random' module is not cryptographically secure and should not be used for security-sensitive values."
    severity = Severity.HIGH
    cwe = 327

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        _RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample", "getrandbits"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _RANDOM_FUNCS:
                if isinstance(func.value, ast.Name) and func.value.id == "random":
                    # Check if the surrounding lines mention crypto-related words
                    line = _get_line(content, node.lineno)
                    # Also check a few lines around for context
                    context_lines = []
                    lines = content.splitlines()
                    for offset in range(-3, 4):
                        idx = node.lineno - 1 + offset
                        if 0 <= idx < len(lines):
                            context_lines.append(lines[idx])
                    context = " ".join(context_lines)
                    if _CRYPTO_CONTEXT_RE.search(context):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                title=self.name,
                                description=self.description,
                                file_path=filepath,
                                line_number=node.lineno,
                                snippet=line.strip(),
                                cwe=self.cwe,
                                recommendation="Use secrets.token_hex(), secrets.token_urlsafe(), or os.urandom() for security purposes.",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# PF-CRYP-005  Hardcoded encryption key
# ---------------------------------------------------------------------------

_HARDCODED_KEY_RE = re.compile(
    r"""(?:encryption[_-]?key|aes[_-]?key|secret[_-]?key|cipher[_-]?key)\s*[=:]\s*["'][A-Za-z0-9+/=]{16,}["']""",
    re.IGNORECASE,
)


@register_rule
class HardcodedEncryptionKey(BaseRule):
    rule_id = "PF-CRYP-005"
    name = "Hardcoded Encryption Key"
    description = "An encryption key is hardcoded in source code."
    severity = Severity.CRITICAL
    cwe = 327

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename) or filename.endswith((".yml", ".yaml", ".toml", ".cfg", ".ini", ".env", ".conf"))

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if _HARDCODED_KEY_RE.search(line):
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
                        recommendation="Store encryption keys in a vault or KMS. Never hardcode them.",
                    )
                )
        return findings
