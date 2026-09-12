"""Bounded repository traversal shared by evidence-gathering tools."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from .evidence import ToolHardFailure
from .limits import positive_int_env

DEFAULT_MAX_SCAN_FILES = 100_000
DEFAULT_IGNORED_DIRS = {".git", ".engineeringos", "__pycache__", ".pytest_cache", "node_modules", "target", ".venv", "venv"}


def repository_files(repo: Path, *, ignored_dirs: set[str] | None = None) -> Iterator[Path]:
    """Yield repository files without following links, failing closed at the configured cap."""
    ignored = DEFAULT_IGNORED_DIRS if ignored_dirs is None else ignored_dirs
    try:
        maximum = positive_int_env("ENGINEERINGOS_MAX_SCAN_FILES", DEFAULT_MAX_SCAN_FILES, maximum=1_000_000)
    except RuntimeError as exc:
        raise ToolHardFailure(str(exc)) from exc
    seen = 0
    for root, dirs, files in os.walk(repo, topdown=True, followlinks=False):
        dirs[:] = [name for name in dirs if name not in ignored]
        for name in files:
            seen += 1
            if seen > maximum:
                raise ToolHardFailure(
                    f"Can't scan repository — candidate files exceed the configured limit of {maximum}. "
                    "Narrow the repository or deliberately raise ENGINEERINGOS_MAX_SCAN_FILES."
                )
            yield Path(root) / name
