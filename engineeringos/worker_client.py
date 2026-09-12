"""Client for an externally managed sandbox worker.

The worker command is operator-configured, never supplied by an MCP caller.
It receives a JSON request on stdin and must return an evidence-chain list on
stdout. The worker itself is responsible for microVM/container isolation.
"""
from __future__ import annotations
import json, os, shlex, subprocess
from pathlib import Path
from .evidence import EvidenceItem, ToolHardFailure
from .test_runners import RUNNER_NAMES

MAX_TIMEOUT_SECONDS = 15 * 60
MAX_OUTPUT_BYTES = 1_000_000
MAX_EVIDENCE_ITEMS = 1_000

def configured() -> bool:
    return bool(os.environ.get("ENGINEERINGOS_TEST_WORKER"))

def run(repo: Path, scope: str | None, timeout: int, runner: str | None = None) -> list[EvidenceItem]:
    configured_command = os.environ.get("ENGINEERINGOS_TEST_WORKER")
    if not configured_command:
        raise ToolHardFailure("Sandbox worker is not configured.")
    command = shlex.split(configured_command, posix=False)
    if not command:
        raise ToolHardFailure("Sandbox worker configuration is empty.")
    if runner is not None and (not isinstance(runner, str) or runner not in RUNNER_NAMES):
        raise ToolHardFailure("Sandbox worker runner is not allow-listed.")
    try:
        timeout = max(1, min(int(timeout), MAX_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        raise ToolHardFailure("Sandbox worker timeout must be a whole number of seconds.")
    request = {"repo_path": str(repo), "scope": scope, "runner": runner, "timeout_seconds": timeout, "network": False, "read_only_checkout": True}
    clean_env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE") if key in os.environ}
    try:
        result = subprocess.run(command, input=json.dumps(request), capture_output=True, text=True, timeout=timeout + 10, shell=False, env=clean_env)
    except subprocess.TimeoutExpired:
        raise ToolHardFailure("Sandbox worker exceeded its time budget and was stopped. Narrow the test scope and retry.")
    except OSError as exc:
        raise ToolHardFailure(f"Sandbox worker could not start: {exc}. Check the worker deployment.")
    if result.returncode != 0:
        raise ToolHardFailure("Sandbox worker failed to return test evidence. Inspect the worker logs and retry.")
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise ToolHardFailure("Sandbox worker returned too much evidence. Reduce the test scope or worker output.")
    try:
        payload = json.loads(result.stdout)
        raw_evidence = payload["evidence"]
        if not isinstance(raw_evidence, list) or len(raw_evidence) > MAX_EVIDENCE_ITEMS:
            raise ValueError("evidence must be a bounded list")
        items = [EvidenceItem(**item) for item in raw_evidence]
        if any(len(item.summary) > 2_000 or len(item.ref) > 2_000 for item in items):
            raise ValueError("evidence fields exceed the size limit")
        return items
    except (ValueError, KeyError, TypeError) as exc:
        raise ToolHardFailure(f"Sandbox worker returned invalid evidence: {exc}. Upgrade or repair the worker.")
