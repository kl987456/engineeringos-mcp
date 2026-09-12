"""Optional adapter for the MCP security scanner selected by the operator.

Different scanners in this space use materially different invocation shapes
and output schemas, not just different binary names — e.g. Cisco's
`mcp-scanner` needs an explicit `behavioral` subcommand and `--format raw`,
while the older mcp-scan/agent-scan lineage takes a bare path and `--json`.
Rather than assume every scanner speaks one shape, we recognize known
binaries by name and build the right command for each; an operator using a
scanner we don't recognize can still point ENGINEERINGOS_MCP_SCANNER at it
and get the generic `<binary> <path> --json` invocation as a best effort."""
from __future__ import annotations
import json, os, shutil, subprocess
from pathlib import Path
from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..audit import redact_sensitive

MAX_OUTPUT_BYTES = 1_000_000
MAX_FINDINGS = 500


def _command_for(binary: str, path: Path) -> list[str]:
    name = Path(binary).stem.lower()
    if name == "mcp-scanner":
        return [binary, "behavioral", str(path), "--format", "raw"]
    return [binary, str(path), "--json"]


def _findings_from(payload: object, returncode: int) -> list[dict]:
    if isinstance(payload, dict):
        for key in ("findings", "issues"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        analyzer_results = payload.get("analyzer_results")
        if isinstance(analyzer_results, dict):
            return [{"analyzer": name, **result} if isinstance(result, dict) else {"analyzer": name, "result": result} for name, result in analyzer_results.items()]
    return [{"status": "clean" if returncode == 0 else "findings", "result": payload}]


def scan_server(server_path: str) -> list[EvidenceItem]:
    path = allowed_path(server_path, must_be_dir=True)
    binary = os.environ.get("ENGINEERINGOS_MCP_SCANNER") or shutil.which("mcp-scanner") or shutil.which("mcp-scan") or shutil.which("agent-scan")
    if not binary:
        raise ToolHardFailure("Can't scan MCP security — no operator-configured mcp-scanner/mcp-scan/agent-scan executable is installed. Install and configure a scanner before release.")
    try:
        result = subprocess.run(_command_for(binary, path), cwd=path, capture_output=True, text=True, timeout=120, shell=False)
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
    findings = _findings_from(payload, result.returncode)
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise ToolHardFailure("Can't scan MCP security — scanner returned an invalid or unbounded findings list.")
    return [EvidenceItem("code_search", "mcp-security-scanner", redact_sensitive(json.dumps(item, sort_keys=True), 500), str(path)) for item in findings]
