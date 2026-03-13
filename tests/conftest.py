"""Shared fixtures for Pathfinder tests."""

import os
import textwrap

import pytest


@pytest.fixture
def make_file(tmp_path):
    """Factory fixture: create a temp file with the given content and return its path."""

    def _make(filename: str, content: str) -> str:
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))
        return str(path)

    return _make


@pytest.fixture
def make_tree(tmp_path):
    """Factory fixture: create a directory tree from a dict of {relpath: content}."""

    def _make(files: dict) -> str:
        for relpath, content in files.items():
            fpath = tmp_path / relpath
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(textwrap.dedent(content))
        return str(tmp_path)

    return _make
