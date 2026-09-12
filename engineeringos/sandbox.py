"""Execution boundary contract for tools that run customer code.

The local worker is intentionally conservative. Production deployments should
replace it with a microVM/container worker and keep this interface unchanged.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class SandboxPolicy:
    timeout_seconds: int = 60
    network: bool = False
    read_only_checkout: bool = True
    max_output_bytes: int = 1_000_000

DEFAULT_TEST_POLICY = SandboxPolicy()
