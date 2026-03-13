"""Command-line interface for Pathfinder."""

import argparse
import sys
from typing import List, Optional

from pathfinder import __version__
from pathfinder.config import load_config
from pathfinder.finding import Severity
from pathfinder.formatters import FORMATTER_REGISTRY
from pathfinder.scanner import Scanner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pathfinder",
        description="Pathfinder -- security audit tool for Python codebases",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=list(FORMATTER_REGISTRY.keys()),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to .pathfinder.yml config file",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Comma-separated list of rule IDs to run",
    )
    parser.add_argument(
        "--exclude",
        default=None,
        help="Comma-separated list of additional paths to exclude",
    )
    parser.add_argument(
        "--mcp",
        action="store_true",
        help="Start the MCP server instead of running a scan",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"pathfinder {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ---- MCP mode ----
    if args.mcp:
        try:
            from pathfinder.mcp_server import run_server

            run_server()
        except ImportError:
            print(
                "ERROR: MCP dependencies not installed.\n"
                "Install with:  pip install qenex-pathfinder[mcp]",
                file=sys.stderr,
            )
            sys.exit(1)
        return

    # ---- Normal scan mode ----
    config = load_config(args.config)

    if args.exclude:
        config.exclude_paths.extend(args.exclude.split(","))

    severity_filter = Severity.from_string(args.severity)
    selected_rules = args.rules.split(",") if args.rules else None

    scanner = Scanner(
        config=config,
        severity_filter=severity_filter,
        selected_rules=selected_rules,
    )

    findings = scanner.scan_path(args.path)

    formatter = FORMATTER_REGISTRY[args.output_format]
    output = formatter(findings)
    print(output)

    # Exit code: 1 if any finding meets or exceeds the requested severity
    has_actionable = any(f.severity >= severity_filter for f in findings)
    sys.exit(1 if has_actionable else 0)
