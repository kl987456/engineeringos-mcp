import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from mcp import Client
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from types import SimpleNamespace
from engineeringos.auth import OIDCVerifier
from engineeringos import test_runners, worker_client
from engineeringos import code_maps
from engineeringos.indexer import index_repo, find_symbol, freshness, parser_backend, dependency_graph
from engineeringos.tools.dependency_tools import dependency_health
from engineeringos.tools.diagnostic_tools import diagnostics
from engineeringos.tools.search_tools import search_code
from engineeringos.workflows.overview import repo_overview
from engineeringos.workflows.readiness import production_readiness
from engineeringos.tools.impact_tools import change_impact
from engineeringos.tools.git_tools import git_diff
from engineeringos.tools.log_tools import search_logs
from engineeringos.tools import lsp_tools
from engineeringos.tools import lsp_default
from engineeringos.tools import security_tools
from engineeringos.tools import test_tools
from engineeringos.tools.language_tools import language_profile
from engineeringos.tools.inventory_tools import cyclonedx_sbom, software_inventory
from engineeringos.evaluations import run_golden
from dashboard import server as dashboard_server
from engineeringos.audit import record as audit_record
from engineeringos.cli import main as mcp_cli_main
from engineeringos.map_cli import main as map_cli_main
from engineeringos.preflight import check_environment
from engineeringos.audit import tenant_context

from engineeringos.security import MCPError, PermissionEnforcementMiddleware, RequestRateLimitMiddleware, TenantIsolationMiddleware, TenantPathPolicy, allowed_path
from engineeringos.server import app, capabilities


def test_health_and_readiness_routes():
    async def run():
        transport = httpx.ASGITransport(app=app.streamable_http_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/healthz")).json()["status"] == "ok"
            assert (await client.get("/readyz")).json()["status"] == "ready"
    asyncio.run(run())


def test_installed_entrypoint_targets_are_callable():
    assert callable(mcp_cli_main)
    assert callable(dashboard_server.main)
    assert callable(map_cli_main)


def test_shared_client_configuration_targets_installed_stdio_server():
    import json
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "examples" / "mcp-stdio.json").read_text(encoding="utf-8"))
    server = config["mcpServers"]["engineeringos"]
    assert server["command"] == "python"
    assert server["args"] == ["-m", "engineeringos.server"]


def test_preflight_reports_readiness_without_secret_values(tmp_path, monkeypatch):
    tenant = tmp_path / "tenants"
    index = tmp_path / "indexes"
    tenant.mkdir(); index.mkdir()
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "super-secret-audience")
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "mcp.example")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tenant))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(index))
    monkeypatch.setenv("ENGINEERINGOS_TEST_WORKER", "operator-worker --safe")
    result = check_environment()
    assert result["ready"] is True
    serialized = __import__("json").dumps(result)
    assert "super-secret-audience" not in serialized
    assert "operator-worker --safe" not in serialized


def test_preflight_rejects_invalid_numeric_limits(tmp_path, monkeypatch):
    tenant = tmp_path / "tenants"
    index = tmp_path / "indexes"
    tenant.mkdir(); index.mkdir()
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "engineeringos")
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "mcp.example")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tenant))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(index))
    monkeypatch.setenv("ENGINEERINGOS_TEST_WORKER", "operator-worker")
    monkeypatch.setenv("ENGINEERINGOS_MAX_BODY_BYTES", "unbounded")
    result = check_environment()
    assert result["ready"] is False
    assert any(item["name"] == "ENGINEERINGOS_MAX_BODY_BYTES" and not item["ok"] for item in result["checks"])


def test_container_context_excludes_secrets_and_build_artifacts():
    root = Path(__file__).resolve().parents[1]
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "**/.env*" in dockerignore
    assert dockerignore.startswith("**")
    assert "HEALTHCHECK" in dockerfile


def test_audit_redacts_credentials_and_bounds_event_text(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ENGINEERINGOS_AUDIT_LOG", str(audit))
    audit_record("test", status="error", detail="Authorization: Bearer abc123 token=secret-value password=hunter2")
    event = __import__("json").loads(audit.read_text(encoding="utf-8"))
    assert "abc123" not in event["detail"]
    assert "secret-value" not in event["detail"]
    assert "hunter2" not in event["detail"]
    assert len(event["detail"]) <= 500


def test_log_evidence_redacts_credentials_before_return(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("Authorization: Bearer abc123 token=secret-value\n", encoding="utf-8")
    evidence = search_logs(str(log), "Authorization")
    assert "abc123" not in evidence[0].summary
    assert "secret-value" not in evidence[0].summary


def test_lsp_adapter_contract_is_bounded_and_path_scoped(monkeypatch, tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def checkout():\n    return True\n", encoding="utf-8")
    monkeypatch.setenv("ENGINEERINGOS_LSP_ADAPTER", "operator-lsp-adapter")
    class Result:
        returncode = 0
        stdout = '{"symbols":[{"name":"checkout","kind":"function","line":1,"end_line":2}]}'
    calls = {}
    def fake_run(command, **kwargs):
        calls["request"] = kwargs["input"]
        return Result()
    monkeypatch.setattr(lsp_tools.subprocess, "run", fake_run)
    evidence = lsp_tools.symbols(str(tmp_path), "app.py", "python")
    assert evidence[0].summary == "function checkout"
    assert '"file_path": "app.py"' in calls["request"]


def test_lsp_symbols_falls_through_to_default_backend_when_adapter_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("ENGINEERINGOS_LSP_ADAPTER", raising=False)
    (tmp_path / "app.py").write_text("def f():\n    pass\n", encoding="utf-8")
    with pytest.raises(Exception) as excinfo:
        lsp_tools.symbols(str(tmp_path), "app.py", "python")
    # The old immediate hard-fail (no fallback at all) must be gone now that
    # a default backend seam exists, whatever this environment's actual
    # multilspy/platform availability happens to be.
    assert "operator-configured LSP adapter is installed" not in str(excinfo.value)


def test_lsp_default_is_available_gates_by_language_and_platform(monkeypatch):
    monkeypatch.setattr(lsp_default.platform, "system", lambda: "Linux")
    assert lsp_default.is_available("go") is False  # not in DEFAULT_LANGUAGES regardless of platform
    assert lsp_default.is_available(None) is False
    monkeypatch.setattr(lsp_default.platform, "system", lambda: "Windows")
    monkeypatch.delenv("ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS", raising=False)
    assert lsp_default.is_available("python") is False  # Windows gate, regardless of multilspy install state


def test_lsp_default_symbols_reports_windows_disabled_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(lsp_default.platform, "system", lambda: "Windows")
    monkeypatch.delenv("ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS", raising=False)
    (tmp_path / "app.py").write_text("def f():\n    pass\n", encoding="utf-8")
    with pytest.raises(Exception, match="disabled on Windows"):
        lsp_default.symbols(tmp_path, "app.py", "python", 30)


def test_lsp_default_convert_symbols_maps_real_multilspy_shape():
    # Field shape confirmed empirically against a real multilspy run on
    # Linux (see ROADMAP.md) — not guessed.
    raw = [
        {"name": "Worker", "kind": 5, "range": {"start": {"line": 0, "character": 0}, "end": {"line": 2, "character": 19}}, "detail": "class Worker"},
        {"name": "execute", "kind": 6, "range": {"start": {"line": 1, "character": 4}, "end": {"line": 2, "character": 19}}, "detail": "def execute"},
        {"name": "helper", "kind": 12, "range": {"start": {"line": 4, "character": 0}, "end": {"line": 5, "character": 29}}, "detail": "def helper"},
    ]
    evidence = lsp_default._convert_symbols(raw, "app.py")
    assert [e.summary for e in evidence] == ["class Worker", "method execute", "function helper"]
    assert evidence[0].ref == "app.py#L1-L3"
    assert evidence[2].ref == "app.py#L5-L6"


def test_lsp_default_convert_symbols_rejects_unbounded_list():
    raw = [{"name": "x", "kind": 12}] * (lsp_default.MAX_SYMBOLS + 1)
    with pytest.raises(Exception, match="unbounded"):
        lsp_default._convert_symbols(raw, "app.py")


def test_security_scanner_rejects_unbounded_output(monkeypatch, tmp_path):
    monkeypatch.setenv("ENGINEERINGOS_MCP_SCANNER", "operator-scanner")
    class Result:
        returncode = 0
        stdout = "x" * (security_tools.MAX_OUTPUT_BYTES + 1)
    monkeypatch.setattr(security_tools.subprocess, "run", lambda *args, **kwargs: Result())
    import pytest
    with pytest.raises(Exception, match="too much output"):
        security_tools.scan_server(str(tmp_path))


def test_mcp_scanner_command_shape_depends_on_recognized_binary_name(tmp_path):
    assert security_tools._command_for("/usr/local/bin/mcp-scanner", tmp_path) == ["/usr/local/bin/mcp-scanner", "behavioral", str(tmp_path), "--format", "raw"]
    assert security_tools._command_for("mcp-scanner.exe", tmp_path) == ["mcp-scanner.exe", "behavioral", str(tmp_path), "--format", "raw"]
    assert security_tools._command_for("/usr/local/bin/agent-scan", tmp_path) == ["/usr/local/bin/agent-scan", str(tmp_path), "--json"]
    assert security_tools._command_for("operator-scanner", tmp_path) == ["operator-scanner", str(tmp_path), "--json"]


def test_mcp_scanner_findings_extraction_covers_known_output_shapes():
    assert security_tools._findings_from({"findings": [{"a": 1}]}, 1) == [{"a": 1}]
    assert security_tools._findings_from({"issues": [{"b": 2}]}, 1) == [{"b": 2}]
    analyzer = security_tools._findings_from({"analyzer_results": {"api_analyzer": {"severity": "HIGH", "total_findings": 2}}}, 1)
    assert analyzer == [{"analyzer": "api_analyzer", "severity": "HIGH", "total_findings": 2}]
    assert security_tools._findings_from({"unrecognized": True}, 0) == [{"status": "clean", "result": {"unrecognized": True}}]
    assert security_tools._findings_from({"unrecognized": True}, 1) == [{"status": "findings", "result": {"unrecognized": True}}]


def test_tenant_root_rejects_outside_paths(tmp_path, monkeypatch):
    tenant = tmp_path / "tenant"
    tenant.mkdir()
    monkeypatch.setenv("ENGINEERINGOS_REPO_ROOT", str(tenant))
    allowed_path(str(tenant))
    try:
        allowed_path(str(tmp_path / "other"))
    except Exception as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("outside-tenant path was accepted")


def test_workflows_share_tenant_path_boundary(tmp_path, monkeypatch):
    tenant = tmp_path / "tenant"
    tenant.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("ENGINEERINGOS_REPO_ROOT", str(tenant))
    for workflow in (repo_overview, production_readiness):
        try:
            workflow(str(outside))
        except Exception as exc:
            assert "outside" in str(exc)
        else:
            raise AssertionError(f"{workflow.__name__} accepted a path outside the tenant root")


def test_change_impact_labels_semantic_fallback(tmp_path, monkeypatch):
    import subprocess
    monkeypatch.delenv("ENGINEERINGOS_SEM_BIN", raising=False)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "app.py").write_text("def checkout():\n    return True\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-qm", "initial"], cwd=tmp_path, check=True)
    (tmp_path / "app.py").write_text("def checkout():\n    return False\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-qm", "change"], cwd=tmp_path, check=True)
    evidence = change_impact(str(tmp_path), "HEAD", "checkout")
    assert any("Semantic impact is unavailable" in item.summary for item in evidence)


def test_code_security_scan_reports_absent_scanners_without_hard_failure(tmp_path, monkeypatch):
    import engineeringos.tools.code_security_tools as code_security_tools
    monkeypatch.delenv("ENGINEERINGOS_SEMGREP_BIN", raising=False)
    monkeypatch.delenv("ENGINEERINGOS_SEMGREP_CONFIG", raising=False)
    monkeypatch.delenv("ENGINEERINGOS_GITLEAKS_BIN", raising=False)
    monkeypatch.setattr(code_security_tools.shutil, "which", lambda name: None)
    with pytest.raises(Exception, match="neither Semgrep nor Gitleaks"):
        code_security_tools.code_security_scan(str(tmp_path))


def test_code_security_scan_uses_configured_semgrep_and_gitleaks(tmp_path, monkeypatch):
    import json
    import engineeringos.tools.code_security_tools as code_security_tools
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("ENGINEERINGOS_SEMGREP_BIN", "semgrep-bin")
    monkeypatch.setenv("ENGINEERINGOS_SEMGREP_CONFIG", "p/security-audit")
    monkeypatch.setenv("ENGINEERINGOS_GITLEAKS_BIN", "gitleaks-bin")

    class Result:
        returncode = 0
        stderr = ""

    def fake_run(command, **kwargs):
        result = Result()
        if command[0] == "semgrep-bin":
            result.stdout = json.dumps({"results": [{"check_id": "py.rule", "path": "app.py", "start": {"line": 1}, "extra": {"message": "issue found", "severity": "WARNING"}}]})
        else:
            result.stdout = json.dumps([{"RuleID": "generic-secret", "File": "app.py", "StartLine": 1, "Description": "a leaked secret"}])
        return result

    monkeypatch.setattr(code_security_tools.subprocess, "run", fake_run)
    evidence = code_security_tools.code_security_scan(str(tmp_path))
    assert {item.source for item in evidence} == {"semgrep", "gitleaks"}
    assert any("py.rule" in item.summary and "issue found" in item.summary for item in evidence)
    assert any("generic-secret" in item.summary and "a leaked secret" in item.summary for item in evidence)


def test_vulnerability_scan_reports_absent_scanner(tmp_path, monkeypatch):
    import engineeringos.tools.vulnerability_tools as vulnerability_tools
    monkeypatch.delenv("ENGINEERINGOS_OSV_SCANNER_BIN", raising=False)
    monkeypatch.setattr(vulnerability_tools.shutil, "which", lambda name: None)
    with pytest.raises(Exception, match="osv-scanner is not installed"):
        vulnerability_tools.vulnerability_scan(str(tmp_path))


def test_vulnerability_scan_treats_null_results_as_no_findings(tmp_path, monkeypatch):
    # Found by actually running osv-scanner against a repo with zero
    # dependency manifests: it emits {"results": null} (a JSON null, not a
    # missing key or an empty list). dict.get's default only kicks in for a
    # missing key, so this previously misread a normal "nothing to scan"
    # response as an invalid result shape.
    import json
    import engineeringos.tools.vulnerability_tools as vulnerability_tools
    monkeypatch.setenv("ENGINEERINGOS_OSV_SCANNER_BIN", "osv-scanner-bin")
    monkeypatch.delenv("ENGINEERINGOS_OSV_SCANNER_OFFLINE", raising=False)

    class Result:
        returncode = 0
        stdout = json.dumps({"results": None, "experimental_config": {"licenses": {"summary": False, "allowlist": None}}})
        stderr = ""

    monkeypatch.setattr(vulnerability_tools.subprocess, "run", lambda *a, **k: Result())
    evidence = vulnerability_tools.vulnerability_scan(str(tmp_path))
    assert len(evidence) == 1
    assert "no known-vulnerable dependencies" in evidence[0].summary


def test_vulnerability_scan_summarizes_findings_and_labels_network_source(tmp_path, monkeypatch):
    import json
    import engineeringos.tools.vulnerability_tools as vulnerability_tools
    monkeypatch.setenv("ENGINEERINGOS_OSV_SCANNER_BIN", "osv-scanner-bin")
    monkeypatch.delenv("ENGINEERINGOS_OSV_SCANNER_OFFLINE", raising=False)
    payload = {
        "results": [{
            "source": {"path": "package-lock.json"},
            "packages": [{
                "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                "groups": [{"aliases": ["CVE-2020-8203", "GHSA-p6mc-m468-83gw"], "max_severity": "7.4"}],
            }],
        }],
    }

    class Result:
        returncode = 1
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(vulnerability_tools.subprocess, "run", lambda *a, **k: Result())
    evidence = vulnerability_tools.vulnerability_scan(str(tmp_path))
    assert len(evidence) == 1
    assert "lodash@4.17.15" in evidence[0].summary
    assert "CVE-2020-8203" in evidence[0].summary
    assert "live network query" in evidence[0].source


def test_vulnerability_scan_offline_mode_adds_flags_and_label(tmp_path, monkeypatch):
    import json
    import engineeringos.tools.vulnerability_tools as vulnerability_tools
    monkeypatch.setenv("ENGINEERINGOS_OSV_SCANNER_BIN", "osv-scanner-bin")
    monkeypatch.setenv("ENGINEERINGOS_OSV_SCANNER_OFFLINE", "1")
    captured = {}

    class Result:
        returncode = 0
        stdout = json.dumps({"results": []})
        stderr = ""

    def fake_run(command, **kwargs):
        captured["command"] = command
        return Result()

    monkeypatch.setattr(vulnerability_tools.subprocess, "run", fake_run)
    evidence = vulnerability_tools.vulnerability_scan(str(tmp_path))
    assert "--offline" in captured["command"]
    assert "--offline-vulnerabilities" in captured["command"]
    assert "offline local database" in evidence[0].source


def test_golden_investigation_preserves_evidence_only_contract():
    result = run_golden(str(Path(__file__).resolve().parents[1] / "sample-repo"))
    assert result["passed"] is True
    assert result["checks"]["claim_is_unset"] is True


def test_oidc_verifier_validates_claims(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = OIDCVerifier("https://issuer.test", "engineeringos", ["engineering:read"])
    verifier._jwks.get_signing_key_from_jwt = lambda token: SimpleNamespace(key=key.public_key())
    import time
    token = jwt.encode({"iss": "https://issuer.test", "aud": "engineeringos", "sub": "alice", "exp": int(time.time()) + 60, "scope": "engineering:read"}, key, algorithm="RS256")
    access = asyncio.run(verifier.verify_token(token))
    assert access is not None and access.subject == "alice"
    bad = jwt.encode({"iss": "https://wrong.test", "aud": "engineeringos", "sub": "alice", "exp": int(time.time()) + 60, "scope": "engineering:read"}, key, algorithm="RS256")
    assert asyncio.run(verifier.verify_token(bad)) is None


def test_oidc_insecure_override_is_loopback_only(monkeypatch):
    monkeypatch.setenv("ENGINEERINGOS_ALLOW_INSECURE_OIDC", "1")
    import pytest
    with pytest.raises(ValueError, match="loopback"):
        OIDCVerifier("http://issuer.example", "engineeringos", ["engineering:read"])
    verifier = OIDCVerifier("http://127.0.0.1:9000", "engineeringos", ["engineering:read"])
    assert verifier.issuer == "http://127.0.0.1:9000"


def test_oidc_rejects_oversized_bearer_token():
    verifier = OIDCVerifier("https://issuer.test", "engineeringos", ["engineering:read"])
    assert asyncio.run(verifier.verify_token("x" * (16 * 1024 + 1))) is None


@dataclass
class _Context:
    method: str
    params: dict
    request: object


def test_tenant_middleware_rewrites_paths_and_rejects_escape(tmp_path):
    (tmp_path / "tenant-a" / "repo").mkdir(parents=True)
    (tmp_path / "tenant-b" / "repo").mkdir(parents=True)
    request = type(
        "Request",
        (),
        {
            "scope": {
                "user": type(
                    "User",
                    (),
                    {"access_token": type("Token", (), {"claims": {"tenant_id": "tenant-a"}})()},
                )()
            }
        },
    )()
    middleware = TenantIsolationMiddleware(TenantPathPolicy(tmp_path))

    async def call_next(ctx):
        return ctx

    context = _Context(
        "tools/call",
        {"arguments": {"repo_path": "repo", "scope": "tests/test.py::test_ok"}},
        request,
    )
    result = asyncio.run(middleware(context, call_next))
    assert result.params["arguments"]["repo_path"] == str((tmp_path / "tenant-a" / "repo").resolve())
    assert result.params["arguments"]["scope"].startswith("tests")

    escape = _Context("tools/call", {"arguments": {"repo_path": "../tenant-b/repo"}}, request)
    try:
        asyncio.run(middleware(escape, call_next))
    except MCPError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("cross-tenant path was accepted")


def test_tenant_context_flows_into_audit_events(tmp_path, monkeypatch):
    (tmp_path / "tenant-a" / "repo").mkdir(parents=True)
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ENGINEERINGOS_AUDIT_LOG", str(audit))
    request = type("Request", (), {"scope": {"user": type("User", (), {"access_token": type("Token", (), {"claims": {"tenant_id": "tenant-a"}})()})()}})()
    context = _Context("tools/call", {"arguments": {"repo_path": "repo"}}, request)
    middleware = TenantIsolationMiddleware(TenantPathPolicy(tmp_path))

    async def call_next(ctx):
        audit_record("repo_overview", status="success")
        return ctx

    asyncio.run(middleware(context, call_next))
    event = __import__("json").loads(audit.read_text(encoding="utf-8"))
    assert event["tenant"] == "tenant-a"


def test_request_rate_limit_is_scoped_to_authenticated_identity():
    request = type(
        "Request",
        (),
        {"scope": {"user": type("User", (), {"access_token": type("Token", (), {"claims": {"tenant_id": "acme", "sub": "alice"}})()})()}},
    )()
    context = _Context("tools/call", {"name": "repo_overview", "arguments": {}}, request)
    limiter = RequestRateLimitMiddleware(requests=2, window_seconds=60)

    async def call_next(ctx):
        return ctx

    asyncio.run(limiter(context, call_next))
    asyncio.run(limiter(context, call_next))
    try:
        asyncio.run(limiter(context, call_next))
    except MCPError as exc:
        assert "Rate limit exceeded" in str(exc)
    else:
        raise AssertionError("third call was not rate limited")


def test_permission_middleware_requires_trusted_approval_claim(monkeypatch):
    import engineeringos.security as security_module
    monkeypatch.setattr(security_module, "requires_approval", lambda name: name == "dangerous_tool")
    token = type("Token", (), {"claims": {"engineeringos_approvals": []}})()
    request = type("Request", (), {"scope": {"user": type("User", (), {"access_token": token})()}})()
    context = _Context("tools/call", {"name": "dangerous_tool", "arguments": {}}, request)
    middleware = PermissionEnforcementMiddleware()

    async def call_next(ctx):
        return ctx

    try:
        asyncio.run(middleware(context, call_next))
    except MCPError as exc:
        assert "Human approval is required" in str(exc)
    else:
        raise AssertionError("approval-required tool was allowed without a trusted claim")
    token.claims["engineeringos_approvals"] = ["dangerous_tool"]
    assert asyncio.run(middleware(context, call_next)) is context


def test_tool_registration_stays_in_sync_across_server_production_and_permissions(tmp_path, monkeypatch):
    """Regression guard: git_diff was tiered in permissions.yaml but never
    registered as a callable tool in either server.py or production.py.
    Every tool declared in permissions.yaml must be registered in both the
    stdio server and the production HTTP server, and vice versa, and both
    copies of permissions.yaml must agree — nothing else catches this drift."""
    import importlib
    import yaml
    import engineeringos.permissions as permissions_module
    import engineeringos.server as server_module

    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "https://mcp.test")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tmp_path))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(tmp_path.parent / f"{tmp_path.name}-indexes"))
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "test:80")
    monkeypatch.setenv("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "0")
    import engineeringos.production as production
    production = importlib.reload(production)

    root_config = yaml.safe_load(Path(__file__).resolve().parent.parent.joinpath("config", "permissions.yaml").read_text())
    packaged_config = yaml.safe_load(Path(__file__).resolve().parent.parent.joinpath("engineeringos", "config", "permissions.yaml").read_text())
    assert root_config["tools"] == packaged_config["tools"], "the two permissions.yaml copies have drifted apart"

    permission_tools = set(permissions_module.TOOL_TIERS)
    stdio_tools = {t.name for t in asyncio.run(server_module.app.list_tools())}
    production_tools = {t.name for t in asyncio.run(production.app.list_tools())}
    assert permission_tools == stdio_tools, f"mismatch: {permission_tools ^ stdio_tools}"
    assert permission_tools == production_tools, f"mismatch: {permission_tools ^ production_tools}"


def test_production_http_requires_bearer_and_allows_health(tmp_path, monkeypatch):
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "https://mcp.test")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tmp_path))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(tmp_path.parent / f"{tmp_path.name}-indexes"))
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "test:80")
    monkeypatch.setenv("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "0")
    import importlib
    import engineeringos.production as production
    production = importlib.reload(production)

    async def run():
        transport = httpx.ASGITransport(app=production.application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/healthz")).status_code == 200
            headers = (await client.get("/healthz")).headers
            assert headers["cache-control"] == "no-store"
            assert headers["x-content-type-options"] == "nosniff"
            assert headers["referrer-policy"] == "no-referrer"
            response = await client.get("/mcp")
            assert response.status_code == 401
            assert response.headers["www-authenticate"].startswith("Bearer")

    asyncio.run(run())


def test_production_readiness_degrades_when_index_storage_disappears(tmp_path, monkeypatch):
    index = tmp_path.parent / f"{tmp_path.name}-indexes"
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "https://mcp.test")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tmp_path))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(index))
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "test:80")
    monkeypatch.setenv("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "0")
    import importlib
    import engineeringos.production as production
    production = importlib.reload(production)
    index.rmdir()

    async def run():
        transport = httpx.ASGITransport(app=production.application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/readyz")
            assert response.status_code == 503
            assert response.json()["checks"]["index_storage"] is False

    asyncio.run(run())


def test_production_http_rejects_anonymous_requests(monkeypatch, tmp_path):
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "https://mcp.test")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tmp_path))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(tmp_path.parent / f"{tmp_path.name}-indexes"))
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "test:80")
    monkeypatch.setenv("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "0")
    import importlib
    production = importlib.import_module("engineeringos.production")
    importlib.reload(production)

    async def run():
        transport = httpx.ASGITransport(app=production.application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/mcp")
            assert response.status_code == 401
            assert "Bearer" in response.headers.get("www-authenticate", "")
    asyncio.run(run())


def test_production_entrypoint_requires_worker_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "https://mcp.test")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tmp_path))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(tmp_path.parent / f"{tmp_path.name}-indexes"))
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "test:80")
    monkeypatch.delenv("ENGINEERINGOS_TEST_WORKER", raising=False)
    monkeypatch.setenv("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "1")
    import importlib
    import pytest
    import engineeringos.production as production
    with pytest.raises(RuntimeError, match="ENGINEERINGOS_TEST_WORKER"):
        importlib.reload(production)


def test_production_rejects_index_storage_inside_tenant_root(monkeypatch, tmp_path):
    tenant_root = tmp_path / "tenants"
    tenant_root.mkdir()
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "https://mcp.test")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tenant_root))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(tenant_root / "indexes"))
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "test:80")
    monkeypatch.setenv("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "0")
    import importlib
    import pytest
    import engineeringos.production as production
    with pytest.raises(RuntimeError, match="non-overlapping"):
        importlib.reload(production)


def test_production_rejects_map_storage_inside_tenant_root(monkeypatch, tmp_path):
    tenant_root = tmp_path / "tenants"
    tenant_root.mkdir()
    monkeypatch.setenv("ENGINEERINGOS_OIDC_ISSUER", "https://issuer.test")
    monkeypatch.setenv("ENGINEERINGOS_OIDC_AUDIENCE", "https://mcp.test")
    monkeypatch.setenv("ENGINEERINGOS_TENANT_ROOT", str(tenant_root))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(tmp_path / "indexes"))
    monkeypatch.setenv("ENGINEERINGOS_MAP_ROOT", str(tenant_root / "maps"))
    monkeypatch.setenv("ENGINEERINGOS_ALLOWED_HOSTS", "test:80")
    monkeypatch.setenv("ENGINEERINGOS_REQUIRE_SANDBOX_WORKER", "0")
    import importlib
    import pytest
    import engineeringos.production as production
    with pytest.raises(RuntimeError, match="ENGINEERINGOS_MAP_ROOT.*non-overlapping"):
        importlib.reload(production)


def test_external_worker_protocol(monkeypatch, tmp_path):
    monkeypatch.setenv("ENGINEERINGOS_TEST_WORKER", "worker-command")
    class Result:
        returncode = 0
        stdout = '{"evidence":[{"type":"test_result","source":"worker","summary":"PASSED: smoke","ref":"smoke"}]}'
    calls = {}
    def fake_run(command, **kwargs):
        calls["command"] = command; calls["request"] = kwargs["input"]; return Result()
    monkeypatch.setattr(worker_client.subprocess, "run", fake_run)
    evidence = worker_client.run(tmp_path, "tests", 10, "go")
    assert evidence[0].summary == "PASSED: smoke"
    assert '"network": false' in calls["request"]
    assert '"runner": "go"' in calls["request"]


def test_external_worker_rejects_oversized_or_malformed_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("ENGINEERINGOS_TEST_WORKER", "worker-command")
    class Result:
        returncode = 0
        stdout = '{"evidence":[{"type":"test_result","source":"worker","summary":"' + ("x" * 2001) + '","ref":"smoke"}]}'
    monkeypatch.setattr(worker_client.subprocess, "run", lambda *args, **kwargs: Result())
    try:
        worker_client.run(tmp_path, "tests", 10)
    except Exception as exc:
        assert "invalid evidence" in str(exc)
    else:
        raise AssertionError("oversized worker evidence was accepted")


def test_polyglot_test_plan_detects_fixed_allowlisted_runners(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text('{"scripts":{"test":"vitest run; echo repository-text"}}', encoding="utf-8")
    (tmp_path / "go.mod").write_text("module example.test/project\n", encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
    (tmp_path / "Demo.csproj").write_text("<Project />", encoding="utf-8")
    (tmp_path / "mix.exs").write_text("defmodule Demo.MixProject do end", encoding="utf-8")
    monkeypatch.setattr(test_runners.shutil, "which", lambda name: f"/tools/{name}")

    runners = {item.name: item for item in test_runners.detect(tmp_path)}
    assert {"npm", "go", "cargo", "dotnet", "mix"} <= runners.keys()
    assert runners["npm"].command == ("npm", "test", "--ignore-scripts")
    assert "repository-text" not in " ".join(runners["npm"].command)
    assert runners["go"].command == ("go", "test", "-json", "-count=1", "./...")
    assert runners["cargo"].command == ("cargo", "test", "--locked", "--offline", "--no-fail-fast")
    assert all(item.name in test_runners.RUNNER_NAMES for item in runners.values())


def test_go_json_test_results_are_structured():
    runner = test_runners.TestRunner("go", ("go", "test"), "go.mod", True, "go-json")
    output = "\n".join([
        '{"Action":"pass","Package":"example.dev/api","Test":"TestHealthy"}',
        '{"Action":"fail","Package":"example.dev/api","Test":"TestCheckout"}',
    ])
    evidence = test_runners.parse_result(runner, output, 1)
    assert [item.summary for item in evidence] == ["PASS: TestHealthy", "FAIL: TestCheckout"]
    assert evidence[1].ref == "example.dev/api::TestCheckout"


def test_polyglot_runner_uses_disposable_copy_and_no_shell(tmp_path, monkeypatch):
    (tmp_path / "go.mod").write_text("module example.test/project\n", encoding="utf-8")
    monkeypatch.delenv("ENGINEERINGOS_TEST_WORKER", raising=False)
    monkeypatch.setattr(test_runners.shutil, "which", lambda name: f"/tools/{name}" if name == "go" else None)
    calls = {}

    def fake_run(command, **kwargs):
        calls.update(command=command, **kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout='{"Action":"pass","Package":"example.test/project","Test":"TestSmoke"}\n',
            stderr="",
        )

    monkeypatch.setattr(test_tools.subprocess, "run", fake_run)
    evidence = test_tools.run_tests(str(tmp_path), runner="go", timeout=15)
    assert calls["command"] == ["go", "test", "-json", "-count=1", "./..."]
    assert calls["shell"] is False
    assert Path(calls["cwd"]) != tmp_path
    assert calls["env"]["CI"] == "1"
    assert evidence[0].summary == "PASS: TestSmoke"


def test_invalid_runner_is_rejected_before_external_worker(tmp_path, monkeypatch):
    import pytest

    monkeypatch.setenv("ENGINEERINGOS_TEST_WORKER", "operator-worker")
    monkeypatch.setattr(worker_client, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("worker was called")))
    with pytest.raises(Exception, match="allow-listed"):
        test_tools.run_tests(str(tmp_path), runner="go; remove-everything")
    with pytest.raises(Exception, match="whole number"):
        test_tools.run_tests(str(tmp_path), timeout="forever")


def test_polyglot_indexer_tracks_javascript_and_python(tmp_path):
    (tmp_path / "app.js").write_text("class Checkout {}\nfunction charge() {}\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("def settle():\n    return True\n", encoding="utf-8")
    indexed = index_repo(str(tmp_path))
    assert "parser backends:" in indexed[0].summary
    assert parser_backend("python") == "python-ast"
    names = {item.summary for item in find_symbol(str(tmp_path), "")}
    assert "class Checkout" in names
    assert "function charge" in names
    assert "function settle" in names
    assert "fresh" in freshness(str(tmp_path)).summary
    (tmp_path / "app.js").write_text("class Changed {}\n", encoding="utf-8")
    assert "stale" in freshness(str(tmp_path)).summary


def test_polyglot_indexer_covers_extended_language_families(tmp_path):
    samples = {
        "native.c": "struct Ledger { int id; };\nint charge(int amount) { return amount; }\n",
        "service.cpp": "namespace billing { class Checkout {};\nbool settle() { return true; } }\n",
        "Worker.cs": "public class Worker { public bool Execute() { return true; } }\n",
        "Client.swift": "struct Client {}\nfunc authorize() -> Bool { return true }\n",
        "Engine.scala": "object Engine { def compile(value: Int) = value }\n",
        "worker.lua": "local function dispatch(job) return job end\n",
        "release.sh": "publish() { echo ready; }\n",
        "model.dart": "class Invoice {}\nbool calculate() { return true; }\n",
        "router.ex": "defmodule Router do\n  def route(request), do: request\nend\n",
    }
    for name, source in samples.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    evidence = index_repo(str(tmp_path))
    assert "Indexed 9 changed source file(s)" in evidence[0].summary
    expected = {"Ledger", "charge", "Checkout", "settle", "Worker", "Execute", "Client", "authorize", "Engine", "compile", "dispatch", "publish", "Invoice", "calculate", "Router", "route"}
    found = {item.summary.split(" ", 1)[1] for item in find_symbol(str(tmp_path), "", max_results=200)}
    assert expected <= found

    (tmp_path / "Package.swift").write_text("// package manifest\n", encoding="utf-8")
    profile = language_profile(str(tmp_path))
    summaries = [item.summary for item in profile]
    assert any(item.startswith("csharp: 1 source file(s)") for item in summaries)
    assert any(item.startswith("swift: 2 source file(s)") for item in summaries)
    assert any("Package.swift (Swift)" in item for item in summaries)
    assert all("index backend" in item for item in summaries[:-1])


def test_parser_backend_reports_fallback_when_native_language_cannot_load(monkeypatch):
    import engineeringos.indexer as indexer_module
    original = indexer_module.importlib.import_module
    indexer_module._tree_sitter_language.cache_clear()
    monkeypatch.setattr(indexer_module.importlib, "import_module", lambda name: (_ for _ in ()).throw(ImportError()) if name == "tree_sitter_c" else original(name))
    assert indexer_module.parser_backend("c") == "regex-fallback"
    indexer_module._tree_sitter_language.cache_clear()


def test_available_native_grammar_produces_structural_symbols():
    import pytest
    import engineeringos.indexer as indexer_module
    if indexer_module.parser_backend("csharp") != "tree-sitter":
        pytest.skip("optional C# native grammar is not installed")
    native = indexer_module._tree_sitter_symbols(b"public class Worker { public bool Execute() { return true; } }", "csharp")
    assert native is not None
    assert ("Worker", "class", 1, 1) in native
    assert ("Execute", "method", 1, 1) in native


def test_language_pack_never_fetches_a_grammar_that_is_not_already_cached(monkeypatch):
    import engineeringos.indexer as indexer_module
    indexer_module._tree_sitter_language.cache_clear()
    monkeypatch.setattr(indexer_module, "_language_pack_cached", lambda name: False)
    assert indexer_module._tree_sitter_language("kotlin") is None
    assert indexer_module.parser_backend("kotlin") == "regex-fallback"
    indexer_module._tree_sitter_language.cache_clear()


@pytest.mark.parametrize(
    "language,source,expected",
    [
        ("kotlin", b"class Worker {\n    fun execute(): Boolean { return true }\n}\ninterface Handler {\n    fun handle()\n}\nobject Singleton {\n    fun run() {}\n}\n",
         {("Worker", "class", 1, 3), ("execute", "function", 2, 2), ("Handler", "interface", 4, 6), ("handle", "function", 5, 5), ("Singleton", "object", 7, 9), ("run", "function", 8, 8)}),
        ("lua", b"function greet(name)\n  print(name)\nend\n\nlocal function helper()\nend\n",
         {("greet", "function", 1, 3), ("helper", "function", 5, 6)}),
        ("shell", b"function greet() {\n  echo hi\n}\nbuild_all() {\n  echo building\n}\n",
         {("greet", "function", 1, 3), ("build_all", "function", 4, 6)}),
        ("dart", b"class Worker {\n  bool execute() { return true; }\n}\nmixin Loggable {}\nenum Status { ok, fail }\n",
         {("Worker", "class", 1, 3), ("execute", "function", 2, 2), ("Loggable", "mixin", 4, 4), ("Status", "enum", 5, 5)}),
    ],
)
def test_language_pack_grammars_produce_expected_structural_symbols(language, source, expected):
    import engineeringos.indexer as indexer_module
    if indexer_module.parser_backend(language) != "tree-sitter (language-pack)":
        pytest.skip(f"optional {language} language-pack grammar is not cached locally")
    found = indexer_module._tree_sitter_symbols(source, language)
    assert found is not None
    assert expected <= set(found)


def test_polyglot_dependency_edges_cover_javascript_go_and_csharp(tmp_path):
    (tmp_path / "checkout.js").write_text("function charge() {}\nfunction checkout() { return charge(); }\n", encoding="utf-8")
    (tmp_path / "service.go").write_text("package service\nfunc validate() bool { return true }\nfunc Handle() bool { return validate() }\n", encoding="utf-8")
    (tmp_path / "Worker.cs").write_text("public class Worker {\n public bool Charge() { return true; }\n public bool Execute() { return Charge(); }\n}\n", encoding="utf-8")
    index_repo(str(tmp_path))
    assert any("checkout calls charge" in item.summary for item in dependency_graph(str(tmp_path), "checkout"))
    assert any("Handle calls validate" in item.summary for item in dependency_graph(str(tmp_path), "Handle"))
    assert any("Execute calls Charge" in item.summary for item in dependency_graph(str(tmp_path), "Execute"))


def test_indexer_builds_python_dependency_edges(tmp_path):
    (tmp_path / "flow.py").write_text("def charge():\n    return validate()\n\ndef checkout():\n    return charge()\n", encoding="utf-8")
    indexed = index_repo(str(tmp_path))
    assert "reference edges" in indexed[0].summary
    outgoing = dependency_graph(str(tmp_path), "checkout", "out")
    assert any("checkout calls charge" in item.summary for item in outgoing)
    incoming = dependency_graph(str(tmp_path), "charge", "in")
    assert any("checkout calls charge" in item.summary for item in incoming)


def test_source_free_code_map_round_trip_and_tenant_isolation(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "flow.py").write_text(
        "SECRET_VALUE = 'do-not-export'\n\ndef charge():\n    return True\n\ndef checkout():\n    return charge()\n",
        encoding="utf-8",
    )
    index_repo(str(repo))
    payload = code_maps.export_code_map(str(repo))
    serialized = __import__("json").dumps(payload)
    assert payload["format"] == "engineeringos.code-map/v1"
    assert "do-not-export" not in serialized
    assert "return charge()" not in serialized
    assert set(payload) == {"format", "source_fingerprint", "files", "symbols", "edges"}

    hosted = tmp_path / "hosted-indexes"
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(hosted))
    with tenant_context("tenant-a"):
        evidence = code_maps.ingest_code_map("payments", payload)
        assert "source-free map" in evidence[0].summary
        assert any("function checkout" in item.summary for item in code_maps.map_find_symbol("payments", "checkout"))
        assert any("checkout calls charge" in item.summary for item in code_maps.map_dependency_graph("payments", "checkout"))
        assert "matches supplied fingerprint" in code_maps.map_status("payments", payload["source_fingerprint"])[0].summary
        assert "does not match supplied fingerprint" in code_maps.map_status("payments", "0" * 64)[0].summary
    with tenant_context("tenant-b"):
        import pytest
        with pytest.raises(Exception, match="no map has been imported"):
            code_maps.map_find_symbol("payments", "checkout")


def test_code_map_rejects_content_fields_and_fingerprint_tampering(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def checkout():\n    return True\n", encoding="utf-8")
    index_repo(str(repo))
    payload = code_maps.export_code_map(str(repo))
    import copy
    import pytest
    smuggled = copy.deepcopy(payload)
    smuggled["files"][0]["content"] = "raw source"
    with pytest.raises(Exception, match="unknown or missing fields"):
        code_maps.validate_code_map(smuggled)
    tampered = copy.deepcopy(payload)
    tampered["files"][0]["digest"] = "0" * 64
    with pytest.raises(Exception, match="source_fingerprint"):
        code_maps.validate_code_map(tampered)


def test_local_code_map_identity_matches_cli_default(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def checkout():\n    return True\n", encoding="utf-8")
    index_repo(str(repo))
    payload = code_maps.export_code_map(str(repo))
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(tmp_path / "hosted"))
    with tenant_context("local"):
        code_maps.ingest_code_map("checkout", payload)
    assert any("checkout" in item.summary for item in code_maps.map_find_symbol("checkout", "checkout"))


def test_code_map_export_rejects_stale_local_index(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def checkout():\n    return True\n", encoding="utf-8")
    index_repo(str(tmp_path))
    source.write_text("def checkout():\n    return False\n", encoding="utf-8")
    import pytest
    with pytest.raises(Exception, match="local index is stale"):
        code_maps.export_code_map(str(tmp_path))


def test_indexer_removes_deleted_files_and_enforces_file_limit(tmp_path, monkeypatch):
    source = tmp_path / "old.py"
    source.write_text("def removed_symbol():\n    return True\n", encoding="utf-8")
    index_repo(str(tmp_path))
    assert find_symbol(str(tmp_path), "removed_symbol")
    source.unlink()
    result = index_repo(str(tmp_path))
    assert "removed 1 deleted file(s)" in result[0].summary
    assert find_symbol(str(tmp_path), "removed_symbol") == []

    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("x = 2\n", encoding="utf-8")
    monkeypatch.setenv("ENGINEERINGOS_MAX_INDEX_FILES", "1")
    import pytest
    with pytest.raises(Exception, match="configured limit"):
        index_repo(str(tmp_path))


def test_indexer_can_store_map_outside_read_only_source_tree(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def checkout():\n    return True\n", encoding="utf-8")
    index_root = tmp_path / "indexes"
    monkeypatch.setenv("ENGINEERINGOS_INDEX_ROOT", str(index_root))
    evidence = index_repo(str(repo))
    assert not (repo / ".engineeringos").exists()
    assert Path(evidence[0].ref).is_file()
    assert index_root in Path(evidence[0].ref).parents
    assert find_symbol(str(repo), "checkout")


def test_search_code_covers_multiple_source_languages_and_skips_binary(tmp_path):
    (tmp_path / "app.js").write_text("const checkout = true;\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("checkout = False\n", encoding="utf-8")
    (tmp_path / "worker.lua").write_text("local checkout = true\n", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"checkout\x00binary")
    hits = search_code(str(tmp_path), "checkout", max_results=10)
    refs = {item.ref for item in hits}
    assert any(ref.startswith("app.js#L") for ref in refs)
    assert any(ref.startswith("app.py#L") for ref in refs)
    assert any(ref.startswith("worker.lua#L") for ref in refs)
    assert not any("image.png" in ref for ref in refs)


def test_dependency_health_reports_inventory_without_vulnerability_claims(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = ['httpx']\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("pytest\n", encoding="utf-8")
    (tmp_path / "Package.swift").write_text("// swift-tools-version: 6.0\n", encoding="utf-8")
    (tmp_path / "Billing.csproj").write_text("<Project />\n", encoding="utf-8")
    evidence = dependency_health(str(tmp_path))
    summaries = [item.summary for item in evidence]
    assert any("python manifest present: pyproject.toml" in item for item in summaries)
    assert any("swift manifest present: Package.swift" in item for item in summaries)
    assert any("csharp manifest present: Billing.csproj" in item for item in summaries)
    assert any("inventory evidence only" in item for item in summaries)


def test_software_inventory_emits_cross_language_package_urls(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.28.1\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"packages":{"node_modules/@scope/widget":{"name":"@scope/widget","version":"2.4.0"}}}', encoding="utf-8")
    (tmp_path / "go.mod").write_text("module example.test/app\nrequire github.com/acme/lib v1.2.3\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.0"\n', encoding="utf-8")
    (tmp_path / "Billing.csproj").write_text('<Project><ItemGroup><PackageReference Include="Serilog" Version="4.1.0" /></ItemGroup></Project>', encoding="utf-8")
    (tmp_path / "composer.lock").write_text('{"packages":[{"name":"acme/billing","version":"1.3.0"}]}', encoding="utf-8")

    evidence = software_inventory(str(tmp_path))
    refs = {item.ref.split(" | ", 1)[0] for item in evidence}
    assert "pkg:pypi/httpx@0.28.1" in refs
    assert "pkg:npm/%40scope/widget@2.4.0" in refs
    assert "pkg:golang/github.com/acme/lib@v1.2.3" in refs
    assert "pkg:cargo/serde@1.0.0" in refs
    assert "pkg:nuget/Serilog@4.1.0" in refs
    assert "pkg:composer/acme/billing@1.3.0" in refs


def test_software_inventory_is_bounded_and_rejects_oversized_manifest(tmp_path):
    import pytest

    manifest = tmp_path / "requirements.txt"
    manifest.write_text("x" * 5_000_001, encoding="utf-8")
    with pytest.raises(Exception, match="5 MB"):
        software_inventory(str(tmp_path))


def test_cyclonedx_sbom_is_deterministic_and_deduplicates_components(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.28.1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["httpx==0.28.1", "pytest==8.4.0"]\n', encoding="utf-8")
    first, evidence = cyclonedx_sbom(str(tmp_path))
    second, _ = cyclonedx_sbom(str(tmp_path))
    assert first == second
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.6"
    assert len(first["components"]) == 2
    httpx = next(item for item in first["components"] if item["name"] == "httpx")
    assert httpx["bom-ref"] == "pkg:pypi/httpx@0.28.1"
    assert "pyproject.toml,requirements.txt" in httpx["properties"][0]["value"]
    assert "no vulnerability enrichment" in evidence.summary


def test_repository_evidence_tools_enforce_shared_scan_limit(tmp_path, monkeypatch):
    (tmp_path / "one.py").write_text("checkout = True\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("checkout = False\n", encoding="utf-8")
    monkeypatch.setenv("ENGINEERINGOS_MAX_SCAN_FILES", "1")
    import pytest
    for operation in (
        lambda: repo_overview(str(tmp_path)),
        lambda: search_code(str(tmp_path), "checkout"),
        lambda: dependency_health(str(tmp_path)),
    ):
        with pytest.raises(Exception, match="configured limit"):
            operation()


def test_diagnostics_runs_only_detected_safe_checks_in_disposable_copy(tmp_path):
    source = tmp_path / "module.py"
    source.write_text("def healthy():\n    return True\n", encoding="utf-8")
    evidence = diagnostics(str(tmp_path), timeout=10)
    assert any(item.source == "python-compile" and "PASSED" in item.summary for item in evidence)
    assert not source.with_suffix(".pyc").exists()


def test_dashboard_metrics_aggregate_audit_events(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    audit.write_text("\n".join([
        '{"tool":"investigate","status":"success","tenant":"acme"}',
        '{"tool":"run_tests","status":"error","tenant":"acme"}',
        '{"tool":"security_scan","status":"error","tenant":"northstar"}',
        '{"tool":"investigate","status":"index_stale","tenant":"acme"}',
    ]), encoding="utf-8")
    monkeypatch.setattr(dashboard_server, "AUDIT", audit)
    summary = dashboard_server.metrics()
    assert summary["total_calls"] == 4
    assert summary["successes"] == 1
    assert summary["errors"] == 2
    assert summary["security_events"] == 1
    assert summary["stale_indexes"] == 1


def test_dashboard_skips_oversized_audit_lines(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    audit.write_text('{"tool":"ok","status":"success"}\n' + ("x" * (dashboard_server.MAX_AUDIT_LINE_BYTES + 1)) + "\n", encoding="utf-8")
    monkeypatch.setattr(dashboard_server, "AUDIT", audit)
    rows = dashboard_server.events()
    assert len(rows) == 1
    assert rows[0]["tool"] == "ok"


def test_mcp_native_resource_and_prompt_discovery():
    async def run():
        async with Client(app) as client:
            resources = await client.list_resources()
            prompts = await client.list_prompts()
            assert any(str(item.uri) == "engineeringos://capabilities" for item in resources.resources)
            assert any(item.name == "investigation_plan" for item in prompts.prompts)
    asyncio.run(run())


def test_capabilities_resource_reports_actual_integrations(monkeypatch):
    import json
    monkeypatch.delenv("ENGINEERINGOS_SEM_BIN", raising=False)
    monkeypatch.delenv("ENGINEERINGOS_TEST_WORKER", raising=False)
    payload = json.loads(capabilities())
    assert payload["integrations"]["semantic_impact"] is False
    assert payload["integrations"]["sandbox_worker"] is False
    assert payload["features"]
    assert payload["claim_policy"].startswith("Deterministic tools")


def test_readiness_reports_missing_production_integrations(tmp_path, monkeypatch):
    monkeypatch.delenv("ENGINEERINGOS_TEST_WORKER", raising=False)
    monkeypatch.delenv("ENGINEERINGOS_MCP_SCANNER", raising=False)
    result = production_readiness(str(tmp_path))
    assert any("sandbox worker is not configured" in item for item in result["incomplete"])
    assert any("security scanner is not configured" in item for item in result["incomplete"])


def test_subprocess_backed_tools_reject_empty_or_option_like_inputs(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("ERROR checkout\n", encoding="utf-8")
    import pytest
    with pytest.raises(Exception, match="query is empty"):
        search_logs(str(log), "")
    with pytest.raises(Exception, match="revision identifier is invalid"):
        git_diff(str(tmp_path), "--output=/tmp/leak")
