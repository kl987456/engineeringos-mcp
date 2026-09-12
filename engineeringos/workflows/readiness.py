from __future__ import annotations
import os
import shutil
from ..evidence import EvidenceChain, EvidenceItem, ToolHardFailure
from ..tools import git_tools, test_tools
from ..security import allowed_path

def production_readiness(repo_path: str) -> dict:
    repo = allowed_path(repo_path, must_be_dir=True)
    chain = EvidenceChain(question=f"Is {repo} ready for production?")
    if not repo.is_dir(): raise ToolHardFailure(f"Can't assess readiness — '{repo}' is not a repository directory.")
    chain.evidence.append(EvidenceItem("code_search", "deployment", "Production readiness assessment started", str(repo)))
    try: chain.evidence.extend(test_tools.run_tests(str(repo)))
    except ToolHardFailure as exc: chain.incomplete.append(f"run_tests: {exc}")
    try: chain.evidence.extend(git_tools.recent_changes(str(repo), since="30d"))
    except ToolHardFailure as exc: chain.incomplete.append(f"recent_changes: {exc}")
    required = ["Dockerfile", "pyproject.toml", "SECURITY.md"]
    for name in required:
        if (repo / name).exists(): chain.evidence.append(EvidenceItem("code_search", "deployment", f"Found required deployment artifact: {name}", str(repo / name)))
        else: chain.incomplete.append(f"missing deployment artifact: {name}")
    if os.environ.get("ENGINEERINGOS_TEST_WORKER"):
        chain.evidence.append(EvidenceItem("code_search", "sandbox", "External sandbox worker is configured", "ENGINEERINGOS_TEST_WORKER"))
    else:
        chain.incomplete.append("sandbox worker is not configured; do not expose test execution to untrusted repositories")
    scanner = os.environ.get("ENGINEERINGOS_MCP_SCANNER") or shutil.which("mcp-scanner") or shutil.which("mcp-scan") or shutil.which("agent-scan")
    if scanner:
        chain.evidence.append(EvidenceItem("code_search", "security", "MCP security scanner is configured", str(scanner)))
    else:
        chain.incomplete.append("MCP security scanner is not configured; run mcp-scanner/agent-scan/mcp-scan before release")
    semgrep = os.environ.get("ENGINEERINGOS_SEMGREP_BIN") or shutil.which("semgrep")
    gitleaks = os.environ.get("ENGINEERINGOS_GITLEAKS_BIN") or shutil.which("gitleaks")
    if semgrep or gitleaks:
        chain.evidence.append(EvidenceItem("code_search", "security", f"Code security scanning is available (semgrep={bool(semgrep)}, gitleaks={bool(gitleaks)})", "code_security_scan"))
    else:
        chain.incomplete.append("neither Semgrep nor Gitleaks is configured; consider running code_security_scan before release")
    osv_scanner = os.environ.get("ENGINEERINGOS_OSV_SCANNER_BIN") or shutil.which("osv-scanner")
    if osv_scanner:
        chain.evidence.append(EvidenceItem("code_search", "security", "Dependency vulnerability scanning is configured", str(osv_scanner)))
    else:
        chain.incomplete.append("osv-scanner is not configured; consider running vulnerability_scan before release")
    if chain.incomplete:
        chain.note = "Readiness evidence is incomplete; inspect the incomplete field before release. This tool makes no release decision."
    return chain.to_dict()
