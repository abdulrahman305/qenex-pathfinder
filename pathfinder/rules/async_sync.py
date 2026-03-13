"""Async/sync mixing rules (PF-ASYN-001 .. PF-ASYN-005)."""

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


# Known blocking calls that should not appear in async functions.
_BLOCKING_CALLS: Set[str] = {
    "time.sleep",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.options",
    "requests.request",
    "urllib.request.urlopen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
    "os.system",
}


def _call_to_dotted(node: ast.Call) -> str:
    """Try to reconstruct a dotted name from a Call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _is_inside_async(node: ast.AST, parent_map: dict) -> bool:
    """Walk up the parent chain to see if we are inside an async def."""
    current = node
    while current in parent_map:
        current = parent_map[current]
        if isinstance(current, ast.AsyncFunctionDef):
            return True
        if isinstance(current, ast.FunctionDef):
            return False  # regular def breaks the chain
    return False


def _build_parent_map(tree: ast.Module) -> dict:
    """Return a child -> parent mapping for every node in the AST."""
    parent_map = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[child] = node
    return parent_map


# ---------------------------------------------------------------------------
# PF-ASYN-001  Sync call in async def
# ---------------------------------------------------------------------------

@register_rule
class SyncCallInAsync(BaseRule):
    rule_id = "PF-ASYN-001"
    name = "Sync Call in async def"
    description = "A known blocking/synchronous call is used inside an async function, which will block the event loop."
    severity = Severity.MEDIUM
    cwe = 834

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        parent_map = _build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _call_to_dotted(node)
            if dotted in _BLOCKING_CALLS:
                if _is_inside_async(node, parent_map):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=f"Blocking call {dotted}() inside async function blocks the event loop.",
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet=_get_line(content, node.lineno),
                            cwe=self.cwe,
                            recommendation=f"Use an async alternative or run via asyncio.to_thread() / loop.run_in_executor().",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-ASYN-002  Missing await on coroutine
# ---------------------------------------------------------------------------

@register_rule
class MissingAwait(BaseRule):
    rule_id = "PF-ASYN-002"
    name = "Missing await on Coroutine"
    description = "A coroutine is called without await, so it will not execute."
    severity = Severity.HIGH
    cwe = 834

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        # Collect names of async defs in the file
        async_func_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                async_func_names.add(node.name)

        parent_map = _build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            func_name = None
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr
            if func_name and func_name in async_func_names:
                # Check if the Call is wrapped in an Await
                parent = parent_map.get(node)
                if not isinstance(parent, ast.Await):
                    if _is_inside_async(node, parent_map):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                title=self.name,
                                description=f"Coroutine {func_name}() called without await.",
                                file_path=filepath,
                                line_number=node.lineno,
                                snippet=_get_line(content, node.lineno),
                                cwe=self.cwe,
                                recommendation=f"Add 'await' before {func_name}().",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# PF-ASYN-003  Blocking I/O in event loop (open() in async def)
# ---------------------------------------------------------------------------

@register_rule
class BlockingIOInAsync(BaseRule):
    rule_id = "PF-ASYN-003"
    name = "Blocking I/O in async def"
    description = "open() or file I/O in an async function blocks the event loop."
    severity = Severity.LOW
    cwe = 834

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        parent_map = _build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id == "open":
                if _is_inside_async(node, parent_map):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description="open() in async function performs blocking disk I/O.",
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet=_get_line(content, node.lineno),
                            cwe=self.cwe,
                            recommendation="Use aiofiles.open() or run_in_executor() for file I/O in async code.",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-ASYN-004  run_in_executor missing for CPU-bound
# ---------------------------------------------------------------------------

_CPU_HEAVY_PATTERNS = {
    "json.loads",
    "json.dumps",
    "hashlib.pbkdf2_hmac",
    "bcrypt.hashpw",
    "bcrypt.checkpw",
}


@register_rule
class CpuBoundInAsync(BaseRule):
    rule_id = "PF-ASYN-004"
    name = "CPU-Bound Work in async def"
    description = "CPU-intensive work in an async function may starve other coroutines."
    severity = Severity.LOW
    cwe = 834

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        parent_map = _build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _call_to_dotted(node)
            if dotted in _CPU_HEAVY_PATTERNS:
                if _is_inside_async(node, parent_map):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.name,
                            description=f"{dotted}() is CPU-intensive and may block the event loop.",
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet=_get_line(content, node.lineno),
                            cwe=self.cwe,
                            recommendation="Offload to run_in_executor(None, ...) or asyncio.to_thread().",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# PF-ASYN-005  asyncio.sleep(0) busy loop
# ---------------------------------------------------------------------------

@register_rule
class AsyncioSleepZeroLoop(BaseRule):
    rule_id = "PF-ASYN-005"
    name = "asyncio.sleep(0) Busy Loop"
    description = "asyncio.sleep(0) inside a tight loop creates a busy-wait pattern."
    severity = Severity.LOW
    cwe = 834

    def applies_to(self, filename: str) -> bool:
        return _is_python(filename)

    def scan(self, filepath: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        parent_map = _build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _call_to_dotted(node)
            if dotted == "asyncio.sleep":
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and arg.value == 0:
                        # Check if inside a while loop
                        current = node
                        in_loop = False
                        while current in parent_map:
                            current = parent_map[current]
                            if isinstance(current, (ast.While, ast.AsyncFor, ast.For)):
                                in_loop = True
                                break
                        if in_loop:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=self.severity,
                                    title=self.name,
                                    description="asyncio.sleep(0) in a loop is a busy-wait anti-pattern.",
                                    file_path=filepath,
                                    line_number=node.lineno,
                                    snippet=_get_line(content, node.lineno),
                                    cwe=self.cwe,
                                    recommendation="Use asyncio.sleep() with a positive delay, or use an Event/Condition.",
                                )
                            )
        return findings
