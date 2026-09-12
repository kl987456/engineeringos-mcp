"""Shared validation for operator-controlled resource limits."""
from __future__ import annotations

import os


def positive_int_env(name: str, default: int, *, maximum: int | None = None) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer") from exc
    if value <= 0 or (maximum is not None and value > maximum):
        suffix = f" no greater than {maximum}" if maximum is not None else ""
        raise RuntimeError(f"{name} must be a positive integer{suffix}")
    return value
