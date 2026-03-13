"""SARIF 2.1.0 formatter for GitHub Code Scanning and VS Code integration."""

import json
from typing import Dict, List

from pathfinder.finding import Finding, Severity
from pathfinder.formatters import register_formatter

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_SARIF_LEVEL: Dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SEVERITY_TO_SARIF_RANK: Dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}


def _build_rule(finding: Finding) -> dict:
    return {
        "id": finding.rule_id,
        "name": finding.title.replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe}.html",
        "properties": {
            "security-severity": str(_SEVERITY_TO_SARIF_RANK.get(finding.severity, 5.0)),
        },
    }


def _build_result(finding: Finding, rule_index: int) -> dict:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": f"{finding.description}\n\nRecommendation: {finding.recommendation}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {
                        "startLine": max(finding.line_number, 1),
                        "snippet": {"text": finding.snippet},
                    },
                }
            }
        ],
        "properties": {
            "confidence": finding.confidence,
        },
    }


@register_formatter("sarif")
def format_sarif(findings: List[Finding]) -> str:
    # Deduplicate rules by rule_id, maintaining order.
    seen_rules: Dict[str, int] = {}
    rules: List[dict] = []
    results: List[dict] = []

    for f in findings:
        if f.rule_id not in seen_rules:
            seen_rules[f.rule_id] = len(rules)
            rules.append(_build_rule(f))
        results.append(_build_result(f, seen_rules[f.rule_id]))

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "qenex-pathfinder",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/qenex/qenex-pathfinder",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
