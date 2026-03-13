"""Finding model for security scan results."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    """Severity levels ordered from most to least severe."""

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse a severity string (case-insensitive)."""
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
        }
        normalized = value.strip().lower()
        if normalized not in mapping:
            raise ValueError(
                f"Invalid severity: {value!r}. "
                f"Must be one of: {', '.join(mapping.keys())}"
            )
        return mapping[normalized]


@dataclass
class Finding:
    """A single security finding from a scan."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    snippet: str
    cwe: int
    recommendation: str
    confidence: str = "high"

    def to_dict(self) -> dict:
        """Serialize the finding to a plain dictionary."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "cwe": self.cwe,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }
