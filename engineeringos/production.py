"""Authenticated Streamable HTTP entrypoint for production deployments."""
from __future__ import annotations

import os
from pathlib import Path

from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from .auth import OIDCVerifier, auth_env
from . import __version__
from .limits import positive_int_env
from .permissions import annotations_for
from .security import PermissionEnforcementMiddleware, RequestRateLimitMiddleware, SecurityHeadersMiddleware, TenantIsolationMiddleware, TenantPathPolicy
from .server import (
    analyze_change,
    find_symbol,
    git_diff,
    health,
    index_code,
    investigate,
    recent_changes,
    run_tests,
    test_plan,
    software_inventory,
    cyclonedx_sbom,
    search_code,
    search_logs,
    production_readiness,
    security_scan,
    repo_overview,
    language_profile,
    dependency_health,
    diagnostics,
    dependency_graph,
    export_code_map,
    ingest_code_map,
    map_find_symbol,
    map_dependency_graph,
    map_status,
    lsp_symbols,
    capabilities,
    investigation_plan,
)
from starlette.requests import Request
from starlette.responses import JSONResponse


def _required_csv(name: str) -> list[str]:
    values = [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]
    if not values:
        raise RuntimeError(f"Set {name} to a comma-separated allowlist for the production HTTP server")
    return values


async def production_readiness_route(_: Request) -> JSONResponse:
    """Report runtime dependencies that can degrade after a successful startup."""
    index_value = os.environ.get("ENGINEERINGOS_INDEX_ROOT")
    index = Path(index_value).expanduser().resolve() if index_value else None
    map_value = os.environ.get("ENGINEERINGOS_MAP_ROOT") or index_value
    map_root = Path(map_value).expanduser().resolve() if map_value else None
    checks = {
        "index_storage": bool(index and index.is_dir() and os.access(index, os.W_OK)),
        "map_storage": bool(map_root and map_root.is_dir() and os.access(map_root, os.W_OK)),
        "sandbox_worker": bool(os.environ.get("ENGINEERINGOS_TEST_WORKER"))
        or os.environ.get("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "1").lower() in {"0", "false", "no"},
    }
    ready = all(checks.values())
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", "service": "engineeringos-mcp", "checks": checks},
        status_code=200 if ready else 503,
    )


def _register(server: MCPServer) -> None:
    server.custom_route("/healthz", methods=["GET"], name="health")(health)
    server.custom_route("/readyz", methods=["GET"], name="readiness")(production_readiness_route)
    server.tool(
        name="recent_changes",
        description="Commits touching a repo (or one file) within a time window, with subjects and refs.",
        annotations=annotations_for("recent_changes"),
    )(recent_changes)
    server.tool(
        name="git_diff",
        description="Show the stat-and-patch diff for a single Git commit, as evidence for a specific change.",
        annotations=annotations_for("git_diff"),
    )(git_diff)
    server.tool(
        name="search_code",
        description="Bounded text search across supported source and configuration files; returns file-and-line evidence.",
        annotations=annotations_for("search_code"),
    )(search_code)
    server.tool(
        name="run_tests",
        description="Runs detected project-native test suites in a sandbox worker or disposable local copy and reports bounded evidence.",
        annotations=annotations_for("run_tests"),
    )(run_tests)
    server.tool(name="test_plan", description="Detect allow-listed test runners and report whether each required toolchain is locally available without executing project code.", annotations=annotations_for("test_plan"))(test_plan)
    server.tool(name="software_inventory", description="Extract bounded cross-language dependency coordinates and Package URLs from local manifests and lockfiles without network access.", annotations=annotations_for("software_inventory"))(software_inventory)
    server.tool(name="cyclonedx_sbom", description="Generate a deterministic CycloneDX 1.6 component inventory from supported local manifests and lockfiles; performs no vulnerability enrichment.", annotations=annotations_for("cyclonedx_sbom"))(cyclonedx_sbom)
    server.tool(
        name="search_logs",
        description="Searches a log file for lines matching a query.",
        annotations=annotations_for("search_logs"),
    )(search_logs)
    server.tool(
        name="investigate",
        description="Gathers code, Git, log, and test evidence without making a root-cause claim.",
        annotations=annotations_for("investigate"),
    )(investigate)
    server.tool(
        name="index_code",
        description="Build or update the local symbol map for a repository.",
        annotations=annotations_for("index_code"),
    )(index_code)
    server.tool(
        name="find_symbol",
        description="Find indexed symbols across all supported languages by name.",
        annotations=annotations_for("find_symbol"),
    )(find_symbol)
    server.tool(
        name="analyze_change",
        description="List files changed by a Git revision as evidence for downstream impact reasoning.",
        annotations=annotations_for("analyze_change"),
    )(analyze_change)
    server.tool(name="production_readiness", description="Gather deterministic evidence for production readiness; makes no release decision.", annotations=annotations_for("production_readiness"))(production_readiness)
    server.tool(name="security_scan", description="Run the operator-configured MCP security scanner and return findings as evidence.", annotations=annotations_for("security_scan"))(security_scan)
    server.tool(name="repo_overview", description="Gather a fast evidence-only inventory of repository shape, languages, tests, index freshness, and deployment artifacts.", annotations=annotations_for("repo_overview"))(repo_overview)
    server.tool(name="language_profile", description="Inventory languages, test files, parser backends, source size, and build ecosystems in a polyglot repository.", annotations=annotations_for("language_profile"))(language_profile)
    server.tool(name="dependency_health", description="Inventory supported dependency manifests and lockfiles; does not make vulnerability claims.", annotations=annotations_for("dependency_health"))(dependency_health)
    server.tool(name="diagnostics", description="Run detected project-native diagnostics in a disposable copy; returns evidence only and never accepts arbitrary commands.", annotations=annotations_for("diagnostics"))(diagnostics)
    server.tool(name="dependency_graph", description="Query indexed symbol-reference edges for direct callers or callees; evidence is limited to the local index.", annotations=annotations_for("dependency_graph"))(dependency_graph)
    server.tool(name="export_code_map", description="Export a strict source-free map of indexed paths, hashes, symbols, and graph edges; never includes raw source.", annotations=annotations_for("export_code_map"))(export_code_map)
    server.tool(name="ingest_code_map", description="Validate and transactionally store a source-free code map for one tenant project.", annotations=annotations_for("ingest_code_map"))(ingest_code_map)
    server.tool(name="map_find_symbol", description="Find symbols in a hosted source-free code map without accessing a customer checkout.", annotations=annotations_for("map_find_symbol"))(map_find_symbol)
    server.tool(name="map_dependency_graph", description="Query callers or callees from a hosted source-free code map.", annotations=annotations_for("map_dependency_graph"))(map_dependency_graph)
    server.tool(name="map_status", description="Report hosted source-free map counts and compare an optional local source fingerprint for staleness.", annotations=annotations_for("map_status"))(map_status)
    server.tool(name="lsp_symbols", description="Use the operator-configured structural symbol adapter for one repository file; returns bounded symbol evidence only.", annotations=annotations_for("lsp_symbols"))(lsp_symbols)
    server.resource("engineeringos://capabilities", name="capabilities", title="EngineeringOS capabilities", mime_type="application/json")(capabilities)
    server.prompt(name="investigation_plan", title="Investigation plan", description="Create a disciplined evidence-gathering plan for an engineering failure.")(investigation_plan)


def build_application() -> tuple[MCPServer, object]:
    """Create an authenticated server and its ASGI application."""
    issuer, audience, scopes = auth_env()
    tenant_root = os.environ.get("ENGINEERINGOS_TENANT_ROOT")
    index_root = os.environ.get("ENGINEERINGOS_INDEX_ROOT")
    tenant_claim = os.environ.get("ENGINEERINGOS_TENANT_CLAIM", "tenant_id")
    if not tenant_root:
        raise RuntimeError("Set ENGINEERINGOS_TENANT_ROOT to the directory containing one subdirectory per tenant")
    if not index_root:
        raise RuntimeError("Set ENGINEERINGOS_INDEX_ROOT to a dedicated writable directory outside read-only tenant repositories")
    tenant_root_path = Path(tenant_root).expanduser().resolve()
    index_root_path = Path(index_root).expanduser().resolve()
    if index_root_path == tenant_root_path or tenant_root_path in index_root_path.parents or index_root_path in tenant_root_path.parents:
        raise RuntimeError("ENGINEERINGOS_INDEX_ROOT and ENGINEERINGOS_TENANT_ROOT must be separate, non-overlapping directories")
    try:
        index_root_path.mkdir(parents=True, exist_ok=True)
        if not index_root_path.is_dir() or not os.access(index_root_path, os.W_OK):
            raise OSError("directory is not writable")
    except OSError as exc:
        raise RuntimeError(f"ENGINEERINGOS_INDEX_ROOT is not writable: {exc}") from exc
    map_root_path = Path(os.environ.get("ENGINEERINGOS_MAP_ROOT", index_root)).expanduser().resolve()
    if map_root_path == tenant_root_path or tenant_root_path in map_root_path.parents or map_root_path in tenant_root_path.parents:
        raise RuntimeError("ENGINEERINGOS_MAP_ROOT and ENGINEERINGOS_TENANT_ROOT must be separate, non-overlapping directories")
    try:
        map_root_path.mkdir(parents=True, exist_ok=True)
        if not map_root_path.is_dir() or not os.access(map_root_path, os.W_OK):
            raise OSError("directory is not writable")
    except OSError as exc:
        raise RuntimeError(f"ENGINEERINGOS_MAP_ROOT is not writable: {exc}") from exc
    require_worker = os.environ.get("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "1").lower() not in {"0", "false", "no"}
    if require_worker and not os.environ.get("ENGINEERINGOS_TEST_WORKER"):
        raise RuntimeError("Set ENGINEERINGOS_TEST_WORKER to an isolated worker command, or explicitly set ENGINEERINGOS_REQUIRE_SANDBOX_WORKER=0 for local development only")

    auth_settings = AuthSettings(
        issuer_url=AnyHttpUrl(issuer),
        resource_server_url=AnyHttpUrl(audience),
        required_scopes=scopes,
        validate_token_resource=True,
    )
    policy = TenantPathPolicy(tenant_root, tenant_claim)
    rate_limit = RequestRateLimitMiddleware(
        requests=positive_int_env("ENGINEERINGOS_RATE_LIMIT_PER_MINUTE", 120, maximum=1_000_000),
        window_seconds=60,
        max_keys=positive_int_env("ENGINEERINGOS_RATE_LIMIT_KEYS", 10_000, maximum=1_000_000),
        tenant_claim=tenant_claim,
    )
    server = MCPServer(
        "EngineeringOS",
        version=__version__,
        auth=auth_settings,
        token_verifier=OIDCVerifier(
            issuer,
            audience,
            scopes,
            os.environ.get("ENGINEERINGOS_OIDC_JWKS_URI"),
        ),
        middleware=[rate_limit, PermissionEnforcementMiddleware(os.environ.get("ENGINEERINGOS_APPROVAL_CLAIM", "engineeringos_approvals")), TenantIsolationMiddleware(policy)],
    )
    _register(server)
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_required_csv("ENGINEERINGOS_ALLOWED_HOSTS"),
        allowed_origins=[
            item.strip()
            for item in os.environ.get("ENGINEERINGOS_ALLOWED_ORIGINS", "").split(",")
            if item.strip()
        ],
    )
    application = server.streamable_http_app(
        streamable_http_path=os.environ.get("ENGINEERINGOS_MCP_PATH", "/mcp"),
        stateless_http=False,
        max_request_body_size=positive_int_env("ENGINEERINGOS_MAX_BODY_BYTES", 4 * 1024 * 1024, maximum=64 * 1024 * 1024),
        max_sessions=positive_int_env("ENGINEERINGOS_MAX_SESSIONS", 1_000, maximum=100_000),
        transport_security=transport_security,
    )
    application = SecurityHeadersMiddleware(application, hsts=os.environ.get("ENGINEERINGOS_ENABLE_HSTS", "0").lower() in {"1", "true", "yes"})
    return server, application


app, application = build_application()


if __name__ == "__main__":  # pragma: no cover
    app.run(transport="streamable-http")
