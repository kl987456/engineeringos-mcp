"""Optional operator-owned structural symbol adapter."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from . import lsp_default

MAX_OUTPUT_BYTES = 1_000_000
MAX_SYMBOLS = 500


def symbols(repo_path: str, file_path: str, language: str | None = None, timeout: int = 30) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    adapter_config = os.environ.get("ENGINEERINGOS_LSP_ADAPTER")
    if not adapter_config:
        return lsp_default.symbols(repo, file_path, language, timeout)
    candidate = (repo / file_path).resolve()
    if candidate != repo and repo not in candidate.parents or not candidate.is_file():
        raise ToolHardFailure("Can't resolve structural symbols — the requested file is outside the repository or unavailable.")
    command = shlex.split(adapter_config, posix=False)
    if not command:
        raise ToolHardFailure("Can't resolve structural symbols — the adapter configuration is empty.")
    request = {"repo_path": str(repo), "file_path": str(candidate.relative_to(repo)), "language": language, "timeout_seconds": max(1, min(int(timeout), 120))}
    clean_env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE") if key in os.environ}
    try:
        result = subprocess.run(command, input=json.dumps(request), capture_output=True, text=True, timeout=request["timeout_seconds"] + 5, shell=False, env=clean_env)
    except subprocess.TimeoutExpired:
        raise ToolHardFailure("Can't resolve structural symbols — the adapter exceeded its time budget. Narrow the file or inspect adapter logs.")
    except OSError as exc:
        raise ToolHardFailure(f"Can't resolve structural symbols — the adapter could not start: {exc}.")
    if result.returncode != 0:
        raise ToolHardFailure("Can't resolve structural symbols — the adapter failed. Inspect its operator logs.")
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        raise ToolHardFailure("Can't resolve structural symbols — the adapter returned too much data.")
    try:
        payload = json.loads(result.stdout)
        raw_symbols = payload["symbols"]
        if not isinstance(raw_symbols, list) or len(raw_symbols) > MAX_SYMBOLS:
            raise ValueError("symbols must be a bounded list")
        evidence = []
        for item in raw_symbols:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("line"), int):
                raise ValueError("each symbol needs a name and integer line")
            name = item["name"][:200]
            kind = str(item.get("kind", "symbol"))[:80]
            line = max(1, item["line"])
            end_line = max(line, int(item.get("end_line", line)))
            evidence.append(EvidenceItem("code_search", "lsp-adapter", f"{kind} {name}", f"{file_path}#L{line}-L{end_line}"))
        return evidence
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ToolHardFailure(f"Can't resolve structural symbols — the adapter returned invalid evidence: {exc}.")
