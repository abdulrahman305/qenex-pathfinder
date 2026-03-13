"""Output formatters for scan findings."""

from typing import Callable, Dict, List

from pathfinder.finding import Finding

# Formatter signature: (List[Finding]) -> str
FormatterFunc = Callable[[List[Finding]], str]

FORMATTER_REGISTRY: Dict[str, FormatterFunc] = {}


def register_formatter(name: str):
    """Decorator to register a formatter function by name."""

    def decorator(fn: FormatterFunc) -> FormatterFunc:
        FORMATTER_REGISTRY[name] = fn
        return fn

    return decorator


# Import sub-modules so decorators run at import time.
from pathfinder.formatters.text import format_text  # noqa: E402, F401
from pathfinder.formatters.json_fmt import format_json  # noqa: E402, F401
from pathfinder.formatters.sarif import format_sarif  # noqa: E402, F401
