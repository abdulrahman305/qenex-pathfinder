"""Configuration loading for Pathfinder."""

import os
from dataclasses import dataclass, field
from typing import List, Optional

import yaml


DEFAULT_EXTENSIONS = [
    ".py",
    ".service",
    ".yml",
    ".yaml",
    ".txt",
    ".toml",
    ".conf",
    ".ini",
    ".env",
    ".cfg",
]

DEFAULT_DOCKER_FILES = [
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
]

DEFAULT_EXCLUDE_PATHS = [
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "*.egg-info",
]


@dataclass
class Config:
    """Pathfinder scan configuration."""

    exclude_paths: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS))
    exclude_rules: List[str] = field(default_factory=list)
    min_severity: str = "low"
    extensions: List[str] = field(default_factory=lambda: list(DEFAULT_EXTENSIONS))
    custom_extensions: List[str] = field(default_factory=list)
    docker_files: List[str] = field(default_factory=lambda: list(DEFAULT_DOCKER_FILES))

    @property
    def all_extensions(self) -> List[str]:
        """All file extensions to scan (default + custom)."""
        return list(set(self.extensions + self.custom_extensions))


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from a YAML file.

    If *config_path* is ``None``, try ``.pathfinder.yml`` in the current
    directory.  If the file does not exist, return the default configuration.
    """
    if config_path is None:
        config_path = ".pathfinder.yml"

    if not os.path.isfile(config_path):
        return Config()

    with open(config_path, "r") as fh:
        raw = yaml.safe_load(fh) or {}

    kwargs = {}
    if "exclude_paths" in raw:
        kwargs["exclude_paths"] = list(DEFAULT_EXCLUDE_PATHS) + raw["exclude_paths"]
    if "exclude_rules" in raw:
        kwargs["exclude_rules"] = raw["exclude_rules"]
    if "min_severity" in raw:
        kwargs["min_severity"] = raw["min_severity"]
    if "extensions" in raw:
        kwargs["extensions"] = raw["extensions"]
    if "custom_extensions" in raw:
        kwargs["custom_extensions"] = raw["custom_extensions"]
    if "docker_files" in raw:
        kwargs["docker_files"] = raw["docker_files"]

    return Config(**kwargs)
