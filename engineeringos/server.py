"""
EngineeringOS MCP server — V0.

Run locally over stdio for testing (this file):
    python -m engineeringos.server

For the hosted/remote deployment (spec §9.3), swap the last line's
`run_stdio_async()` for `run_streamable_http_async()` and add the SDK's
built-in `auth`/`token_verifier` settings on MCPServer(...) — the tool
definitions below don't change at all.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

from .permissions import annotations_for
from .evidence import ToolHardFailure
from .tools import git_tools, search_tools, test_tools, log_tools
from .tools import impact_tools, security_tools, dependency_tools, diagnostic_tools, inventory_tools, lsp_tools, language_tools
from .tools import code_security_tools, vulnerability_tools
from . import indexer
from . import code_maps
from . import __version__
from .audit import record as audit_record
from .workflows import investigate as investigate_workflow
from .workflows import readiness as readiness_workflow
from .workflows import overview as overview_workflow

app = MCPServer("EngineeringOS", version=__version__)


@app.resource("engineeringos://capabilities", name="capabilities", title="EngineeringOS capabilities", mime_type="application/json")
def capabilities() -> str:
    scanner = bool(os.environ.get("ENGINEERINGOS_MCP_SCANNER") or shutil.which("mcp-scanner") or shutil.which("mcp-scan") or shutil.which("agent-scan"))
    semantic = bool(os.environ.get("ENGINEERINGOS_SEM_BIN") or shutil.which("sem"))
    worker = bool(os.environ.get("ENGINEERINGOS_TEST_WORKER"))
    lsp_adapter = bool(os.environ.get("ENGINEERINGOS_LSP_ADAPTER"))
    semgrep = bool(os.environ.get("ENGINEERINGOS_SEMGREP_BIN") or shutil.which("semgrep"))
    semgrep_configured = semgrep and bool(os.environ.get("ENGINEERINGOS_SEMGREP_CONFIG"))
    gitleaks = bool(os.environ.get("ENGINEERINGOS_GITLEAKS_BIN") or shutil.which("gitleaks"))
    osv_scanner = bool(os.environ.get("ENGINEERINGOS_OSV_SCANNER_BIN") or shutil.which("osv-scanner"))
    parsers = {language: indexer.parser_backend(language) for language in sorted(set(indexer.LANGUAGES.values()))}
    return json.dumps({
        "server": "EngineeringOS",
        "principles": ["read before write", "evidence before conclusions", "human approval for risky actions"],
        "features": ["investigate", "repo_overview", "language_profile", "test_plan", "polyglot_tests", "software_inventory", "package_urls", "cyclonedx_1_6_sbom", "index_code", "find_symbol", "dependency_graph", "export_code_map", "ingest_code_map", "map_find_symbol", "map_dependency_graph", "map_status", "lsp_symbols", "production_readiness", "diagnostics", "security_scan", "code_security_scan", "vulnerability_scan", "sandbox_worker_protocol", "local_dashboard"],
        "integrations": {
            "semantic_impact": semantic,
            "security_scanner": scanner,
            "sandbox_worker": worker,
            "structural_symbol_adapter": lsp_adapter,
            "sast_semgrep": semgrep_configured,
            "secret_scan_gitleaks": gitleaks,
            "vulnerability_scan_osv": osv_scanner,
            "parser_backends": parsers,
        },
        "claim_policy": "Deterministic tools return evidence; calling models form claims.",
    }, sort_keys=True)


@app.prompt(name="investigation_plan", title="Investigation plan", description="Create a disciplined evidence-gathering plan for an engineering failure.")
def investigation_plan(question: str, repo_path: str) -> str:
    return (f"Investigate this engineering question: {question}\nRepository: {repo_path}\n\n"
            "Use recent changes, code search, logs, tests, index freshness, and change impact. "
            "Separate hard failures from thin evidence. Cite every conclusion to returned evidence. "
            "Do not invent a root cause when evidence is incomplete.")


@app.custom_route("/healthz", methods=["GET"], name="health")
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "engineeringos-mcp"})


@app.custom_route("/readyz", methods=["GET"], name="readiness")
async def readiness(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ready", "service": "engineeringos-mcp"})


def _as_result(items, tool_name: str = "unknown") -> dict:
    audit_record(tool_name, status="success")
    return {"evidence": [i.to_dict() for i in items]}


@app.tool(
    name="recent_changes",
    description="Commits touching a repo (or one file) within a time window, with subjects and refs.",
    annotations=annotations_for("recent_changes"),
)
def recent_changes(repo_path: str, file_path: str | None = None, since: str = "30d") -> dict:
    try:
        return _as_result(git_tools.recent_changes(repo_path, file_path, since), "recent_changes")
    except ToolHardFailure as e:
        audit_record("recent_changes", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="git_diff",
    description="Show the stat-and-patch diff for a single Git commit, as evidence for a specific change.",
    annotations=annotations_for("git_diff"),
)
def git_diff(repo_path: str, commit: str = "HEAD") -> dict:
    try:
        return _as_result([git_tools.git_diff(repo_path, commit)], "git_diff")
    except ToolHardFailure as e:
        audit_record("git_diff", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="search_code",
    description="Bounded text search across supported source and configuration files; returns file-and-line evidence.",
    annotations=annotations_for("search_code"),
)
def search_code(repo_path: str, query: str, max_results: int = 20) -> dict:
    try:
        return _as_result(search_tools.search_code(repo_path, query, max_results), "search_code")
    except ToolHardFailure as e:
        audit_record("search_code", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="run_tests",
    description="Runs detected project-native test suites in a sandbox worker or disposable local copy and reports bounded evidence.",
    annotations=annotations_for("run_tests"),
)
def run_tests(repo_path: str, scope: str | None = None, runner: str | None = None, timeout: int = 60) -> dict:
    try:
        return _as_result(test_tools.run_tests(repo_path, scope, timeout, runner), "run_tests")
    except ToolHardFailure as e:
        audit_record("run_tests", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="test_plan", description="Detect allow-listed test runners and report whether each required toolchain is locally available without executing project code.", annotations=annotations_for("test_plan"))
def test_plan(repo_path: str) -> dict:
    try:
        return _as_result(test_tools.test_plan(repo_path), "test_plan")
    except ToolHardFailure as e:
        audit_record("test_plan", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="software_inventory", description="Extract bounded cross-language dependency coordinates and Package URLs from local manifests and lockfiles without network access.", annotations=annotations_for("software_inventory"))
def software_inventory(repo_path: str) -> dict:
    try:
        return _as_result(inventory_tools.software_inventory(repo_path), "software_inventory")
    except ToolHardFailure as e:
        audit_record("software_inventory", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="cyclonedx_sbom", description="Generate a deterministic CycloneDX 1.6 component inventory from supported local manifests and lockfiles; performs no vulnerability enrichment.", annotations=annotations_for("cyclonedx_sbom"))
def cyclonedx_sbom(repo_path: str) -> dict:
    try:
        bom, evidence = inventory_tools.cyclonedx_sbom(repo_path)
        audit_record("cyclonedx_sbom", status="success")
        return {"sbom": bom, "evidence": [evidence.to_dict()]}
    except ToolHardFailure as e:
        audit_record("cyclonedx_sbom", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="search_logs",
    description="Searches a log file for lines matching a query.",
    annotations=annotations_for("search_logs"),
)
def search_logs(log_path: str, query: str, max_results: int = 20) -> dict:
    try:
        return _as_result(log_tools.search_logs(log_path, query, max_results), "search_logs")
    except ToolHardFailure as e:
        audit_record("search_logs", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="investigate",
    description=(
        "Gathers evidence (recent commits + diffs, code search, log search, test results) "
        "relevant to an engineering question. Returns evidence only — it does not claim a "
        "root cause; reason over the returned evidence yourself."
    ),
    annotations=annotations_for("investigate"),
)
def investigate(
    question: str,
    repo_path: str,
    search_query: str | None = None,
    log_path: str | None = None,
    log_query: str | None = None,
    since: str = "30d",
) -> dict:
    try:
        result = investigate_workflow.investigate(
            question, repo_path, search_query, log_path, log_query, since
        )
        stale = any("Index status: stale" in item.get("summary", "") for item in result.get("evidence", []))
        audit_record("investigate", status="index_stale" if stale else "success")
        return result
    except ToolHardFailure as e:
        audit_record("investigate", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="index_code",
    description="Build or update the local symbol map for a repository. Raw source is not stored in the index.",
    annotations=annotations_for("index_code"),
)
def index_code(repo_path: str) -> dict:
    try:
        return _as_result(indexer.index_repo(repo_path), "index_code")
    except ToolHardFailure as e:
        audit_record("index_code", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="find_symbol",
    description="Find indexed symbols across all supported languages by name.",
    annotations=annotations_for("find_symbol"),
)
def find_symbol(repo_path: str, name: str, max_results: int = 20) -> dict:
    try:
        return _as_result(indexer.find_symbol(repo_path, name, max_results), "find_symbol")
    except ToolHardFailure as e:
        audit_record("find_symbol", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="dependency_graph", description="Query indexed symbol-reference edges for direct callers or callees; evidence is limited to the local index.", annotations=annotations_for("dependency_graph"))
def dependency_graph(repo_path: str, symbol: str, direction: str = "out", max_results: int = 50) -> dict:
    try:
        return _as_result(indexer.dependency_graph(repo_path, symbol, direction, max_results), "dependency_graph")
    except ToolHardFailure as e:
        audit_record("dependency_graph", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="export_code_map", description="Export a strict source-free map of indexed paths, hashes, symbols, and graph edges; never includes raw source.", annotations=annotations_for("export_code_map"))
def export_code_map(repo_path: str) -> dict:
    try:
        result = code_maps.export_code_map(repo_path)
        audit_record("export_code_map", status="success", detail=f"files={len(result['files'])};symbols={len(result['symbols'])};edges={len(result['edges'])}")
        return result
    except ToolHardFailure as e:
        audit_record("export_code_map", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="ingest_code_map", description="Validate and transactionally store a source-free code map for one tenant project.", annotations=annotations_for("ingest_code_map"))
def ingest_code_map(project_id: str, code_map: dict) -> dict:
    try:
        return _as_result(code_maps.ingest_code_map(project_id, code_map), "ingest_code_map")
    except ToolHardFailure as e:
        audit_record("ingest_code_map", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="map_find_symbol", description="Find symbols in a hosted source-free code map without accessing a customer checkout.", annotations=annotations_for("map_find_symbol"))
def map_find_symbol(project_id: str, name: str, max_results: int = 20) -> dict:
    try:
        return _as_result(code_maps.map_find_symbol(project_id, name, max_results), "map_find_symbol")
    except ToolHardFailure as e:
        audit_record("map_find_symbol", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="map_dependency_graph", description="Query callers or callees from a hosted source-free code map.", annotations=annotations_for("map_dependency_graph"))
def map_dependency_graph(project_id: str, symbol: str, direction: str = "out", max_results: int = 50) -> dict:
    try:
        return _as_result(code_maps.map_dependency_graph(project_id, symbol, direction, max_results), "map_dependency_graph")
    except ToolHardFailure as e:
        audit_record("map_dependency_graph", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="map_status", description="Report hosted source-free map counts and compare an optional local source fingerprint for staleness.", annotations=annotations_for("map_status"))
def map_status(project_id: str, source_fingerprint: str | None = None) -> dict:
    try:
        return _as_result(code_maps.map_status(project_id, source_fingerprint), "map_status")
    except ToolHardFailure as e:
        audit_record("map_status", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(
    name="analyze_change",
    description="List files changed by a Git revision as evidence for downstream impact reasoning.",
    annotations=annotations_for("analyze_change"),
)
def analyze_change(repo_path: str, revision: str = "HEAD", entity: str | None = None) -> dict:
    try:
        return _as_result(impact_tools.change_impact(repo_path, revision, entity), "analyze_change")
    except ToolHardFailure as e:
        audit_record("analyze_change", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="production_readiness", description="Gather deterministic evidence for production readiness; makes no release decision.", annotations=annotations_for("production_readiness"))
def production_readiness(repo_path: str) -> dict:
    try:
        result = readiness_workflow.production_readiness(repo_path)
        audit_record("production_readiness", status="success")
        return result
    except ToolHardFailure as e:
        audit_record("production_readiness", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="security_scan", description="Run the operator-configured MCP security scanner and return findings as evidence.", annotations=annotations_for("security_scan"))
def security_scan(server_path: str) -> dict:
    try:
        return _as_result(security_tools.scan_server(server_path), "security_scan")
    except ToolHardFailure as e:
        audit_record("security_scan", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="code_security_scan", description="Run operator-installed Semgrep (SAST) and Gitleaks (secret detection) against the target repository from a disposable copy; each is independently optional and reports an honest fallback when not configured.", annotations=annotations_for("code_security_scan"))
def code_security_scan(repo_path: str, timeout: int = 120) -> dict:
    try:
        return _as_result(code_security_tools.code_security_scan(repo_path, timeout), "code_security_scan")
    except ToolHardFailure as e:
        audit_record("code_security_scan", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="vulnerability_scan", description="Run the operator-installed OSV-Scanner against detected dependency manifests for known-vulnerability matches. By default this queries the public osv.dev database over the network; set ENGINEERINGOS_OSV_SCANNER_OFFLINE=1 to use a pre-downloaded local database instead.", annotations=annotations_for("vulnerability_scan"))
def vulnerability_scan(repo_path: str, timeout: int = 120) -> dict:
    try:
        return _as_result(vulnerability_tools.vulnerability_scan(repo_path, timeout), "vulnerability_scan")
    except ToolHardFailure as e:
        audit_record("vulnerability_scan", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="repo_overview", description="Gather a fast evidence-only inventory of repository shape, languages, tests, index freshness, and deployment artifacts.", annotations=annotations_for("repo_overview"))
def repo_overview(repo_path: str) -> dict:
    try:
        result = overview_workflow.repo_overview(repo_path)
        audit_record("repo_overview", status="success")
        return result
    except ToolHardFailure as e:
        audit_record("repo_overview", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="language_profile", description="Inventory languages, test files, parser backends, source size, and build ecosystems in a polyglot repository.", annotations=annotations_for("language_profile"))
def language_profile(repo_path: str) -> dict:
    try:
        return _as_result(language_tools.language_profile(repo_path), "language_profile")
    except ToolHardFailure as e:
        audit_record("language_profile", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="dependency_health", description="Inventory supported dependency manifests and lockfiles; does not make vulnerability claims.", annotations=annotations_for("dependency_health"))
def dependency_health(repo_path: str) -> dict:
    try:
        return _as_result(dependency_tools.dependency_health(repo_path), "dependency_health")
    except ToolHardFailure as e:
        audit_record("dependency_health", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="diagnostics", description="Run detected project-native diagnostics in a disposable copy; returns evidence only and never accepts arbitrary commands.", annotations=annotations_for("diagnostics"))
def diagnostics(repo_path: str, timeout: int = 60) -> dict:
    try:
        return _as_result(diagnostic_tools.diagnostics(repo_path, timeout), "diagnostics")
    except ToolHardFailure as e:
        audit_record("diagnostics", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


@app.tool(name="lsp_symbols", description="Use the operator-configured structural symbol adapter for one repository file; returns bounded symbol evidence only.", annotations=annotations_for("lsp_symbols"))
def lsp_symbols(repo_path: str, file_path: str, language: str | None = None, timeout: int = 30) -> dict:
    try:
        return _as_result(lsp_tools.symbols(repo_path, file_path, language, timeout), "lsp_symbols")
    except ToolHardFailure as e:
        audit_record("lsp_symbols", status="error", detail=str(e))
        return {"isError": True, "error": str(e)}


if __name__ == "__main__":
    asyncio.run(app.run_stdio_async())
