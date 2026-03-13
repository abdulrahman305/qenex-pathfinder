"""JSON formatter."""

import json
from collections import Counter
from typing import List

from pathfinder.finding import Finding, Severity
from pathfinder.formatters import register_formatter


@register_formatter("json")
def format_json(findings: List[Finding]) -> str:
    counts = Counter(f.severity.name for f in findings)
    payload = {
        "tool": "qenex-pathfinder",
        "version": "0.1.0",
        "summary": {
            "total": len(findings),
            "critical": counts.get("CRITICAL", 0),
            "high": counts.get("HIGH", 0),
            "medium": counts.get("MEDIUM", 0),
            "low": counts.get("LOW", 0),
            "info": counts.get("INFO", 0),
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
