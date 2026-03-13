"""Plain-text (ANSI color) formatter."""

from collections import Counter
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.formatters import register_formatter

# ANSI colour codes -- no external dependency needed.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # bright red
    Severity.HIGH: "\033[31m",      # red
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.LOW: "\033[36m",       # cyan
    Severity.INFO: "\033[37m",      # white / light grey
}


def _sev_label(sev: Severity) -> str:
    color = _SEVERITY_COLORS.get(sev, "")
    return f"{color}{_BOLD}[{sev.name}]{_RESET}"


@register_formatter("text")
def format_text(findings: List[Finding]) -> str:
    if not findings:
        return f"\n{_BOLD}Pathfinder scan complete.{_RESET} No findings.\n"

    lines: List[str] = []
    lines.append(f"\n{_BOLD}Pathfinder Security Scan Results{_RESET}")
    lines.append("=" * 60)

    current_severity = None
    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            color = _SEVERITY_COLORS.get(f.severity, "")
            lines.append(f"\n{color}{_BOLD}--- {f.severity.name} ---{_RESET}")

        lines.append("")
        lines.append(f"  {_sev_label(f.severity)} {_BOLD}{f.rule_id}{_RESET}: {f.title}")
        lines.append(f"  {_DIM}File:{_RESET} {f.file_path}:{f.line_number}")
        lines.append(f"  {_DIM}CWE:{_RESET}  CWE-{f.cwe}  |  Confidence: {f.confidence}")
        if f.snippet:
            snippet = f.snippet.strip()
            if len(snippet) > 200:
                snippet = snippet[:200] + "..."
            lines.append(f"  {_DIM}Code:{_RESET} {snippet}")
        lines.append(f"  {_DIM}Fix:{_RESET}  {f.recommendation}")

    # Summary
    counts = Counter(f.severity for f in findings)
    lines.append("")
    lines.append("=" * 60)
    summary_parts = []
    for sev in Severity:
        if counts.get(sev, 0):
            color = _SEVERITY_COLORS.get(sev, "")
            summary_parts.append(f"{color}{sev.name}: {counts[sev]}{_RESET}")
    lines.append(f"{_BOLD}Summary:{_RESET} {', '.join(summary_parts)}  |  Total: {len(findings)}")
    lines.append("")

    return "\n".join(lines)
