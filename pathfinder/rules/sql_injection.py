"""SQL injection detection rules (PF-SQLI-001 .. PF-SQLI-004)."""

import ast
import re
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule

_SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|MERGE|TRUNCATE)\b",
    re.IGNORECASE,
)

_EXECUTE_NAMES = {"execute", "executemany", "executescript", "mogrify"}


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _is_python(fn: str) -> bool:
    return fn.endswith(".py")


def _node_has_fstring(node: ast.AST) -> bool:
    """Return True if *node* is or contains a JoinedStr (f-string)."""
    if isinstance(node, ast.JoinedStr):
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            return True
    return False


def _node_has_format_call(node: ast.AST) -> bool:
    """Return True if *node* is a ``str.format(...)`` call."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return True
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Attribute) and func.attr == "format":
                return True
    return False


def _node_has_percent_format(node: ast.AST) -> bool:
    """Return True if *node* is a ``str % (...)`` expression."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Mod):
            return True
    return False


def _node_has_sql_keyword(node: ast.AST) -> bool:
    """Return True if *node* contains a string constant with SQL keywords."""
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if _SQL_KEYWORDS_RE.search(child.value):
                return True
        if isinstance(child, ast.JoinedStr):
            for val in child.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    if _SQL_KEYWORDS_RE.search(val.value):
                        return True
    return False


def _is_execute_call(node: ast.Call) -> bool:
    """Return True if the call looks like ``cursor.execute(...)``."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr in _EXECUTE_NAMES
    if isinstance(func, ast.Name):
        return func.id in _EXECUTE_NAMES
    return False


# ---------------------------------------------------------------------------
# PF-SQLI-001  f-string in SQL execute
# ---------------------------------------------------------------------------

@register_rule
class FStringInSqlExecute(BaseRule):
    rule_id = "PF-SQLI-001"
    name = "f-string in SQL Execute"
    description = "An f-string is used inside a SQL execute() call, allowing SQL injection."
    severity = Severity.CRITICAL
    cwe = 89

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
            if not _is_execute_call(node):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            if _node_has_fstring(first_arg) and _node_has_sql_keyword(first_arg):
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
                        recommendation="Use parameterized queries: cursor.execute('SELECT ... WHERE id = ?', (user_id,))",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-SQLI-002  .format() in SQL execute
# ---------------------------------------------------------------------------

@register_rule
class FormatInSqlExecute(BaseRule):
    rule_id = "PF-SQLI-002"
    name = ".format() in SQL Execute"
    description = "str.format() is used inside a SQL execute() call, allowing SQL injection."
    severity = Severity.CRITICAL
    cwe = 89

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
            if not _is_execute_call(node):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            if _node_has_format_call(first_arg) and _node_has_sql_keyword(first_arg):
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
                        recommendation="Use parameterized queries instead of .format().",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-SQLI-003  String concatenation in SQL
# ---------------------------------------------------------------------------

@register_rule
class ConcatInSql(BaseRule):
    rule_id = "PF-SQLI-003"
    name = "String Concatenation in SQL"
    description = "String concatenation (+) is used to build a SQL query, risking injection."
    severity = Severity.HIGH
    cwe = 89

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
            if not _is_execute_call(node):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                if _node_has_sql_keyword(first_arg):
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
                            recommendation="Use parameterized queries instead of string concatenation.",
                        )
                    )
            # Also detect percent-format: "SELECT ... %s" % val
            if _node_has_percent_format(first_arg) and _node_has_sql_keyword(first_arg):
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
                        recommendation="Use parameterized queries instead of % string formatting.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# PF-SQLI-004  subprocess sqlite3 with interpolation
# ---------------------------------------------------------------------------

_SUBPROCESS_NAMES = {"run", "Popen", "call", "check_output", "check_call"}


@register_rule
class SubprocessSqlite(BaseRule):
    rule_id = "PF-SQLI-004"
    name = "Subprocess sqlite3 with Interpolation"
    description = "sqlite3 CLI invoked via subprocess with string interpolation in the SQL."
    severity = Severity.HIGH
    cwe = 89

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
            func_name = None
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id
            if func_name not in _SUBPROCESS_NAMES:
                continue
            # Check if any argument references sqlite3 and has interpolation
            for arg in node.args:
                if _node_has_fstring(arg) or _node_has_format_call(arg):
                    # Check for sqlite3 reference
                    for child in ast.walk(arg):
                        if isinstance(child, ast.Constant) and isinstance(child.value, str):
                            if "sqlite3" in child.value:
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
                                        recommendation="Use the sqlite3 Python module with parameterized queries instead of subprocess.",
                                    )
                                )
                                break
        return findings
