"""Optional adapter for the MCP security scanner selected by the operator."""
from __future__ import annotations
import json, os, shutil, subprocess
from pathlib import Path
from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..audit import redact_sensitive

MAX_OUTPUT_BYTES = 1_000_000
MAX_FINDINGS = 500

def scan_server(server_path: str) -> list[EvidenceItem]:
    path = allowed_path(server_path, must_be_dir=True)
    binary = os.environ.get("ENGINEERINGOS_MCP_SCANNER") or shutil.which("mcp-scan") or shutil.which("agent-scan")
    if not binary:
        raise ToolHardFailure("Can't scan MCP security — no operator-configured mcp-scan/agent-scan executable is installed. Install and configure a scanner before release.")
    try:
        result = subprocess.run([binary, str(path), "--json"], cwd=path, capture_output=True, text=True, timeout=120, shell=False)
    except subprocess.TimeoutExpired:
        raise ToolHardFailure("Can't scan MCP security — the scanner exceeded 120 seconds. Narrow the target or inspect scanner logs.")
    except OSError as exc:
        raise ToolHardFailure(f"Can't scan MCP security — scanner could not start: {exc}. Check the deployment image.")
    if result.returncode not in (0, 1):
        raise ToolHardFailure("Can't scan MCP security — scanner returned an execution failure. Inspect scanner logs before release.")
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise ToolHardFailure("Can't scan MCP security — scanner returned too much output. Narrow the target or scanner scope.")
    try: payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {"raw": result.stdout[-1000:]}
    findings = payload.get("findings", payload.get("issues", [])) if isinstance(payload, dict) else []
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise ToolHardFailure("Can't scan MCP security — scanner returned an invalid or unbounded findings list.")
    if not findings: findings = [{"status": "clean" if result.returncode == 0 else "findings", "result": payload}]
    return [EvidenceItem("code_search", "mcp-security-scanner", redact_sensitive(json.dumps(item, sort_keys=True), 500), str(path)) for item in findings]
