"""Secret-safe production configuration preflight."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from .limits import positive_int_env


def check_environment() -> dict:
    checks: list[dict] = []

    def add(name: str, ok: bool, message: str, required: bool = True) -> None:
        checks.append({"name": name, "ok": bool(ok), "required": required, "message": message})

    for variable, label in (
        ("ENGINEERINGOS_OIDC_ISSUER", "OIDC issuer"),
        ("ENGINEERINGOS_OIDC_AUDIENCE", "OIDC audience"),
        ("ENGINEERINGOS_ALLOWED_HOSTS", "HTTP host allowlist"),
    ):
        add(variable, bool(os.environ.get(variable)), f"{label} is {'configured' if os.environ.get(variable) else 'missing'}")

    tenant_value = os.environ.get("ENGINEERINGOS_TENANT_ROOT")
    tenant = Path(tenant_value).expanduser().resolve() if tenant_value else None
    add("ENGINEERINGOS_TENANT_ROOT", bool(tenant and tenant.is_dir()), "Tenant root is available" if tenant and tenant.is_dir() else "Tenant root is missing or unavailable")

    index_value = os.environ.get("ENGINEERINGOS_INDEX_ROOT")
    index = Path(index_value).expanduser().resolve() if index_value else None
    index_ok = bool(index and index.is_dir() and os.access(index, os.W_OK))
    add("ENGINEERINGOS_INDEX_ROOT", index_ok, "Index root is writable" if index_ok else "Index root is missing, unavailable, or not writable")
    if tenant and index:
        separate = not (index == tenant or tenant in index.parents or index in tenant.parents)
        add("storage_topology", separate, "Tenant and index roots are separate" if separate else "Tenant and index roots overlap")
    map_value = os.environ.get("ENGINEERINGOS_MAP_ROOT") or index_value
    map_root = Path(map_value).expanduser().resolve() if map_value else None
    map_ok = bool(map_root and map_root.is_dir() and os.access(map_root, os.W_OK))
    add("map_storage", map_ok, "Map root is writable" if map_ok else "Map root is missing, unavailable, or not writable")
    if tenant and map_root:
        separate = not (map_root == tenant or tenant in map_root.parents or map_root in tenant.parents)
        add("map_storage_topology", separate, "Tenant and map roots are separate" if separate else "Tenant and map roots overlap")

    worker = bool(os.environ.get("ENGINEERINGOS_TEST_WORKER"))
    add("ENGINEERINGOS_TEST_WORKER", worker, "Sandbox worker is configured" if worker else "Sandbox worker is missing")
    scanner = bool(os.environ.get("ENGINEERINGOS_MCP_SCANNER") or shutil.which("mcp-scan") or shutil.which("agent-scan"))
    add("security_scanner", scanner, "Security scanner is available" if scanner else "Security scanner is unavailable", required=False)
    lsp = bool(os.environ.get("ENGINEERINGOS_LSP_ADAPTER"))
    add("structural_symbol_adapter", lsp, "Structural symbol adapter is configured" if lsp else "Structural symbol adapter is unavailable", required=False)
    sem = bool(os.environ.get("ENGINEERINGOS_SEM_BIN") or shutil.which("sem"))
    add("semantic_impact", sem, "Semantic impact adapter is available" if sem else "Semantic impact adapter is unavailable", required=False)
    for variable, default, maximum in (
        ("ENGINEERINGOS_RATE_LIMIT_PER_MINUTE", 120, 1_000_000),
        ("ENGINEERINGOS_RATE_LIMIT_KEYS", 10_000, 1_000_000),
        ("ENGINEERINGOS_MAX_BODY_BYTES", 4 * 1024 * 1024, 64 * 1024 * 1024),
        ("ENGINEERINGOS_MAX_SESSIONS", 1_000, 100_000),
        ("ENGINEERINGOS_MAX_SCAN_FILES", 100_000, 1_000_000),
    ):
        try:
            positive_int_env(variable, default, maximum=maximum)
        except RuntimeError:
            add(variable, False, "Configured value is outside the accepted positive integer range")
        else:
            add(variable, True, "Configured value is within the accepted range")
    ready = all(item["ok"] for item in checks if item["required"])
    return {"ready": ready, "checks": checks}


def main() -> int:
    result = check_environment()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
