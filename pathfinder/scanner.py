"""Core scanner that orchestrates rules across a file tree."""

import logging
import os
from fnmatch import fnmatch
from typing import List, Optional, Set

from pathfinder.config import Config, DEFAULT_DOCKER_FILES, load_config
from pathfinder.finding import Finding, Severity
from pathfinder.rules import get_all_rules, BaseRule

logger = logging.getLogger("pathfinder")


def _exc_oneliner() -> str:
    """Return a compact one-line description of the current exception."""
    import sys

    exc = sys.exc_info()[1]
    return f"{type(exc).__name__}: {exc}" if exc else "unknown error"


class Scanner:
    """Walk a directory (or single file) and apply all registered rules."""

    def __init__(
        self,
        config: Optional[Config] = None,
        severity_filter: Optional[Severity] = None,
        selected_rules: Optional[List[str]] = None,
    ) -> None:
        self.config = config or Config()
        self.severity_filter = severity_filter
        self.selected_rules = selected_rules
        self._rules = self._resolve_rules()

    # ------------------------------------------------------------------
    # Rule resolution
    # ------------------------------------------------------------------

    def _resolve_rules(self) -> List[BaseRule]:
        rules = get_all_rules()
        if self.selected_rules:
            selected = {r.strip() for r in self.selected_rules}
            rules = [r for r in rules if r.rule_id in selected]
        if self.config.exclude_rules:
            excluded = set(self.config.exclude_rules)
            rules = [r for r in rules if r.rule_id not in excluded]
        return rules

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _is_excluded(self, path: str) -> bool:
        for exc in self.config.exclude_paths:
            if exc in path.split(os.sep):
                return True
            if fnmatch(os.path.basename(path), exc):
                return True
        return False

    def _is_scannable(self, filepath: str) -> bool:
        basename = os.path.basename(filepath)
        # Docker / compose files matched by name
        if basename in self.config.docker_files:
            return True
        # requirements.txt matched by name
        if basename == "requirements.txt":
            return True
        _, ext = os.path.splitext(filepath)
        return ext in self.config.all_extensions

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_path(self, path: str) -> List[Finding]:
        """Scan a file or directory tree and return sorted findings."""
        path = os.path.abspath(path)
        findings: List[Finding] = []
        files_scanned = 0

        logger.info("Scanning %s with %d rules", path, len(self._rules))

        if os.path.isfile(path):
            findings.extend(self._scan_single_file(path))
            files_scanned = 1
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                # Prune excluded directories in-place
                dirs[:] = [
                    d for d in dirs if not self._is_excluded(os.path.join(root, d))
                ]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if self._is_excluded(fpath):
                        continue
                    if not self._is_scannable(fpath):
                        continue
                    findings.extend(self._scan_single_file(fpath))
                    files_scanned += 1

        results = self._filter_and_sort(findings)
        logger.info(
            "Scan complete: %d files scanned, %d findings", files_scanned, len(results)
        )
        return results

    def scan_file_content(self, content: str, filename: str) -> List[Finding]:
        """Scan in-memory content as if it were the given filename."""
        findings: List[Finding] = []
        for rule in self._rules:
            if rule.applies_to(filename):
                try:
                    findings.extend(rule.scan(filename, content))
                except Exception:
                    logger.debug(
                        "Rule %s failed on %s: %s",
                        rule.rule_id, filename, _exc_oneliner(),
                    )
        return self._filter_and_sort(findings)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scan_single_file(self, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(filepath, "r", errors="replace") as fh:
                content = fh.read()
        except (OSError, IOError):
            return findings

        for rule in self._rules:
            if rule.applies_to(filepath):
                try:
                    findings.extend(rule.scan(filepath, content))
                except Exception:
                    logger.debug(
                        "Rule %s failed on %s: %s",
                        rule.rule_id, filepath, _exc_oneliner(),
                    )
        return findings

    def _filter_and_sort(self, findings: List[Finding]) -> List[Finding]:
        if self.severity_filter is not None:
            findings = [f for f in findings if f.severity >= self.severity_filter]
        # Sort by severity descending, then file path, then line number
        findings.sort(key=lambda f: (-f.severity, f.file_path, f.line_number))
        return findings
