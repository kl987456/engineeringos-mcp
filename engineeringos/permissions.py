"""
Permission tier enforcement (spec §3).

Two layers, on purpose:
  1. Our own permissions.yaml — the tier table WE define and enforce
     server-side, regardless of which client is calling us.
  2. The MCP protocol's own native tool annotations (read_only_hint,
     destructive_hint, idempotent_hint) — advisory hints some clients use
     to decide whether to prompt the user before calling a tool.

Relying on (2) alone would mean trusting every client to implement that
prompt correctly and consistently, which real-world MCP security research
shows is not a safe assumption. So (1) is the actual enforcement; (2) is
just us being a good citizen of the protocol on top of it.
"""

from __future__ import annotations

import yaml
from pathlib import Path
from mcp.types import ToolAnnotations

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "permissions.yaml"
if not _CONFIG_PATH.exists():
    _CONFIG_PATH = Path(__file__).resolve().parent / "config" / "permissions.yaml"


class PermissionError_(Exception):
    """Raised when a tool is called at a tier it isn't approved for."""
    pass


def _load_config() -> dict:
    with open(_CONFIG_PATH) as f:
        return yaml.safe_load(f)


_CONFIG = _load_config()
TIERS = _CONFIG["tiers"]
TOOL_TIERS = _CONFIG["tools"]


def tier_for(tool_name: str) -> str:
    if tool_name not in TOOL_TIERS:
        # Fail closed: an unregistered tool defaults to the strictest tier
        # rather than silently being treated as safe.
        return "HIGH_RISK"
    return TOOL_TIERS[tool_name]


def requires_approval(tool_name: str) -> bool:
    tier = tier_for(tool_name)
    return TIERS[tier]["requires_human_approval"]


def annotations_for(tool_name: str) -> ToolAnnotations:
    """
    Translate our tier into the protocol's native hints, so clients that
    honor these get a second, independent signal beyond our own gating.
    """
    tier = tier_for(tool_name)
    if tier == "READ":
        return ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
    if tier == "SAFE_WRITE":
        return ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False)
    if tier == "RESTRICTED_WRITE":
        return ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False)
    # HIGH_RISK
    return ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)
