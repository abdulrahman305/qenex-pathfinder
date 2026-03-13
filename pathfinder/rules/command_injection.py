"""Command injection detection rules (PF-CMDI-001 .. PF-CMDI-005)."""

import ast
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule

_SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_output", "check_call"}


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _is_python(fn: str) -> bool:
    return fn.endswith(".py")


def _has_shell_true(node: ast.Call) -> bool:
    """Return True if the call has ``shell=True``."""
    for kw in node.keywords:
        if kw.arg == "shell":
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
            if isinstance(kw.value, ast.NameConstant):  # Python 3.7 compat
                if getattr(kw.value, "value", None) is True:
                    return True
    return False


def _arg_has_interpolation(node: ast.AST) -> bool:
    """Return True if *node* involves f-strings, .format(), or % formatting."""
    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            return True
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Attribute) and func.attr == "format":
                return True
        if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Mod):
            return True
    return False


def _is_subprocess_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr in _SUBPROCESS_FUNCS
    if isinstance(func, ast.Name):
        return func.id in _SUBPROCESS_FUNCS
    return False


# ---------------------------------------------------------------------------
# PF-CMDI-001  shell=True with variable / interpolation
# ---------------------------------------------------------------------------

@register_rule
class ShellTrueWithVariable(BaseRule):
    rule_id = "PF-CMDI-001"
    name = "shell=True with Variable Input"
    description = "subprocess call uses shell=True with string interpolation, enabling command injection."
    severity = Severity.CRITICAL
    cwe = 78

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
            if not _is_subprocess_call(node):
                continue
            if not _has_shell_true(node):
                continue
            # Check if the command argument has interpolation or is a variable
            if node.args:
                first_arg = node.args[0]
                if _arg_has_interpolation(first_arg) or isinstance(first_arg, ast.Name):
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
                            recommendation="Use subprocess with a list of arguments and shell=False (default).",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-CMDI-002  os.system() call
# ---------------------------------------------------------------------------

@register_rule
class OsSystemCall(BaseRule):
    rule_id = "PF-CMDI-002"
    name = "os.system() Call"
    description = "os.system() passes the command through the shell, enabling command injection."
    severity = Severity.HIGH
    cwe = 78

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
            if isinstance(func, ast.Attribute):
                if func.attr == "system":
                    # Check that the object is os (or at least named os)
                    if isinstance(func.value, ast.Name) and func.value.id == "os":
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
                                recommendation="Replace os.system() with subprocess.run() using a list of arguments.",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# PF-CMDI-003  os.popen() call
# ---------------------------------------------------------------------------

@register_rule
class OsPopenCall(BaseRule):
    rule_id = "PF-CMDI-003"
    name = "os.popen() Call"
    description = "os.popen() passes the command through the shell, enabling command injection."
    severity = Severity.HIGH
    cwe = 78

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
            if isinstance(func, ast.Attribute):
                if func.attr == "popen":
                    if isinstance(func.value, ast.Name) and func.value.id == "os":
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
                                recommendation="Replace os.popen() with subprocess.run() using a list of arguments.",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# PF-CMDI-004  eval() with user input
# ---------------------------------------------------------------------------

@register_rule
class EvalCall(BaseRule):
    rule_id = "PF-CMDI-004"
    name = "eval() Call"
    description = "eval() executes arbitrary code and is dangerous with untrusted input."
    severity = Severity.HIGH
    cwe = 78

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
            if isinstance(func, ast.Name) and func.id == "eval":
                # Check if the argument is a variable, f-string, or .format()
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Name) or _arg_has_interpolation(arg):
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
                                recommendation="Replace eval() with ast.literal_eval() or a safe parser.",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# PF-CMDI-005  exec() with user input
# ---------------------------------------------------------------------------

@register_rule
class ExecCall(BaseRule):
    rule_id = "PF-CMDI-005"
    name = "exec() Call"
    description = "exec() executes arbitrary code and is dangerous with untrusted input."
    severity = Severity.HIGH
    cwe = 78

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
            if isinstance(func, ast.Name) and func.id == "exec":
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Name) or _arg_has_interpolation(arg):
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
                                recommendation="Avoid exec(). Use safer alternatives or a sandboxed environment.",
                            )
                        )
        return findings
