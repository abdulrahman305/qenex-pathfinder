"""XXE and deserialization rules (PF-XXE-001 .. PF-XXE-005)."""

import ast
from typing import List, Set

from pathfinder.finding import Finding, Severity
from pathfinder.rules import BaseRule, register_rule


def _get_line(content: str, lineno: int) -> str:
    lines = content.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _is_python(fn: str) -> bool:
    return fn.endswith(".py")


def _collect_imports(tree: ast.Module) -> Set[str]:
    """Return all imported module/name strings in the file."""
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# PF-XXE-001  xml.etree.ElementTree without defusedxml
# ---------------------------------------------------------------------------

@register_rule
class UnsafeElementTree(BaseRule):
    rule_id = "PF-XXE-001"
    name = "Unsafe xml.etree.ElementTree"
    description = "xml.etree.ElementTree is imported without defusedxml, which is vulnerable to XXE."
    severity = Severity.MEDIUM
    cwe = 611

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        imports = _collect_imports(tree)
        has_defused = any("defusedxml" in imp for imp in imports)
        if has_defused:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "xml.etree.ElementTree" in alias.name:
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
                                recommendation="Use defusedxml.ElementTree instead of xml.etree.ElementTree.",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and "xml.etree.ElementTree" in node.module:
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
                            recommendation="Use defusedxml.ElementTree instead of xml.etree.ElementTree.",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-XXE-002  xml.sax without defusedxml
# ---------------------------------------------------------------------------

@register_rule
class UnsafeXmlSax(BaseRule):
    rule_id = "PF-XXE-002"
    name = "Unsafe xml.sax"
    description = "xml.sax is imported without defusedxml, which is vulnerable to XXE."
    severity = Severity.MEDIUM
    cwe = 611

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        imports = _collect_imports(tree)
        has_defused = any("defusedxml" in imp for imp in imports)
        if has_defused:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("xml.sax"):
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
                                recommendation="Use defusedxml.sax instead of xml.sax.",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("xml.sax"):
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
                            recommendation="Use defusedxml.sax instead of xml.sax.",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-XXE-003  lxml without safe parser
# ---------------------------------------------------------------------------

@register_rule
class UnsafeLxml(BaseRule):
    rule_id = "PF-XXE-003"
    name = "Unsafe lxml Parser"
    description = "lxml.etree.parse/fromstring called without explicitly disabling entity resolution."
    severity = Severity.MEDIUM
    cwe = 611

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        # First check if lxml is imported at all
        imports = _collect_imports(tree)
        if not any("lxml" in imp for imp in imports):
            return findings

        # Look for etree.parse / etree.fromstring / etree.XML calls
        _UNSAFE_LXML = {"parse", "fromstring", "XML", "iterparse"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _UNSAFE_LXML:
                # Check if parser keyword disables entities
                has_safe_parser = False
                for kw in node.keywords:
                    if kw.arg == "parser":
                        has_safe_parser = True
                    if kw.arg in ("resolve_entities", "no_network"):
                        has_safe_parser = True
                if not has_safe_parser:
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
                            recommendation="Pass a parser with resolve_entities=False: etree.XMLParser(resolve_entities=False).",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-XXE-004  pickle.loads usage (CWE-502)
# ---------------------------------------------------------------------------

@register_rule
class PickleLoads(BaseRule):
    rule_id = "PF-XXE-004"
    name = "Unsafe pickle Deserialization"
    description = "pickle.loads/load can execute arbitrary code during deserialization."
    severity = Severity.HIGH
    cwe = 502

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        _PICKLE_FUNCS = {"loads", "load", "Unpickler"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _PICKLE_FUNCS:
                # Check if the object is pickle / _pickle / cPickle
                if isinstance(func.value, ast.Name) and func.value.id in (
                    "pickle",
                    "_pickle",
                    "cPickle",
                ):
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
                            recommendation="Use JSON or a safer serialization format. If pickle is required, validate the source.",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-XXE-005  yaml.load without SafeLoader
# ---------------------------------------------------------------------------

@register_rule
class UnsafeYamlLoad(BaseRule):
    rule_id = "PF-XXE-005"
    name = "Unsafe yaml.load()"
    description = "yaml.load() without Loader=SafeLoader can execute arbitrary Python objects."
    severity = Severity.HIGH
    cwe = 502

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
            # yaml.load(...)
            if isinstance(func, ast.Attribute) and func.attr == "load":
                if isinstance(func.value, ast.Name) and func.value.id == "yaml":
                    # Check for Loader keyword
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            # Check if the Loader is SafeLoader, CSafeLoader, BaseLoader
                            if isinstance(kw.value, ast.Attribute):
                                if kw.value.attr in (
                                    "SafeLoader",
                                    "CSafeLoader",
                                    "BaseLoader",
                                    "FullLoader",
                                ):
                                    has_safe_loader = True
                            elif isinstance(kw.value, ast.Name):
                                if kw.value.id in (
                                    "SafeLoader",
                                    "CSafeLoader",
                                    "BaseLoader",
                                    "FullLoader",
                                ):
                                    has_safe_loader = True
                    if not has_safe_loader:
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
                                recommendation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                            )
                        )
        return findings
