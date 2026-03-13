"""MCP (Model Context Protocol) server for Pathfinder.

Exposes Pathfinder scanning capabilities as MCP tools so that Claude Code
(and other MCP clients) can invoke security scans interactively.

Install the optional dependency:  pip install qenex-pathfinder[mcp]
"""

import json
from typing import Optional


def _get_scanner():
    """Lazy-import to avoid circular deps and keep MCP optional."""
    from pathfinder.config import load_config
    from pathfinder.scanner import Scanner

    return Scanner(config=load_config())


def _get_rule_map():
    from pathfinder.rules import get_all_rules

    return {r.rule_id: r for r in get_all_rules()}


def run_server() -> None:
    """Start the MCP server (stdio transport by default)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "ERROR: The 'mcp' package is not installed.\n"
            "Install with:  pip install qenex-pathfinder[mcp]\n"
            "Then run:  pathfinder --mcp"
        )
        raise SystemExit(1)

    mcp = FastMCP(
        "qenex-pathfinder",
        description="Security audit tool for Python codebases",
    )

    @mcp.tool()
    def scan_path(path: str, severity: str = "low") -> str:
        """Scan a file or directory for security issues.

        Args:
            path: Absolute or relative path to scan.
            severity: Minimum severity filter (critical, high, medium, low, info).
        """
        from pathfinder.finding import Severity
        from pathfinder.formatters.json_fmt import format_json

        scanner = _get_scanner()
        scanner.severity_filter = Severity.from_string(severity)
        findings = scanner.scan_path(path)
        return format_json(findings)

    @mcp.tool()
    def scan_file_content(content: str, filename: str) -> str:
        """Scan the provided source code text for security issues.

        Args:
            content: The file content to scan.
            filename: A filename hint (e.g., "app.py") so rules know what checks to run.
        """
        from pathfinder.formatters.json_fmt import format_json

        scanner = _get_scanner()
        findings = scanner.scan_file_content(content, filename)
        return format_json(findings)

    @mcp.tool()
    def list_rules() -> str:
        """List all available security rules with their IDs and descriptions."""
        rules = _get_rule_map()
        result = []
        for rule_id in sorted(rules):
            r = rules[rule_id]
            result.append(
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "severity": r.severity.name,
                    "cwe": r.cwe,
                    "description": r.description,
                }
            )
        return json.dumps(result, indent=2)

    @mcp.tool()
    def explain_finding(rule_id: str) -> str:
        """Get a detailed explanation of a specific rule.

        Args:
            rule_id: The rule identifier (e.g., PF-CRED-001).
        """
        rules = _get_rule_map()
        rule = rules.get(rule_id)
        if rule is None:
            return json.dumps({"error": f"Unknown rule: {rule_id}"})
        return json.dumps(
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity.name,
                "cwe": rule.cwe,
                "cwe_url": f"https://cwe.mitre.org/data/definitions/{rule.cwe}.html",
                "description": rule.description,
            },
            indent=2,
        )

    mcp.run(transport="stdio")
