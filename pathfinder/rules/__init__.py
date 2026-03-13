"""Rule engine: base class, registry, and auto-import of all rule modules."""

from abc import ABC, abstractmethod
from typing import List, Type

from pathfinder.finding import Finding, Severity

# Global registry of rule *instances*.
RULE_REGISTRY: List["BaseRule"] = []


class BaseRule(ABC):
    """Abstract base class every rule must implement."""

    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cwe: int = 0

    @abstractmethod
    def applies_to(self, filename: str) -> bool:
        """Return True if this rule should run against *filename*."""
        ...

    @abstractmethod
    def scan(self, filepath: str, content: str) -> List[Finding]:
        """Analyse *content* (from *filepath*) and return findings."""
        ...


def register_rule(cls: Type[BaseRule]) -> Type[BaseRule]:
    """Class decorator -- instantiate and add to the global registry."""
    RULE_REGISTRY.append(cls())
    return cls


def get_all_rules() -> List[BaseRule]:
    """Return a copy of the global rule registry."""
    return list(RULE_REGISTRY)


# Import every rule module so that @register_rule decorators fire.
from pathfinder.rules.credentials import *        # noqa: E402, F401, F403
from pathfinder.rules.sql_injection import *       # noqa: E402, F401, F403
from pathfinder.rules.command_injection import *   # noqa: E402, F401, F403
from pathfinder.rules.xxe import *                 # noqa: E402, F401, F403
from pathfinder.rules.cors import *                # noqa: E402, F401, F403
from pathfinder.rules.network import *             # noqa: E402, F401, F403
from pathfinder.rules.crypto import *              # noqa: E402, F401, F403
from pathfinder.rules.systemd import *             # noqa: E402, F401, F403
from pathfinder.rules.permissions import *         # noqa: E402, F401, F403
from pathfinder.rules.async_sync import *          # noqa: E402, F401, F403
from pathfinder.rules.dependencies import *        # noqa: E402, F401, F403
from pathfinder.rules.docker import *              # noqa: E402, F401, F403
