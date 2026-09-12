from __future__ import annotations
import subprocess
import json
import os
import shutil
from pathlib import Path
from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path

def change_impact(repo_path: str, revision: str = "HEAD", entity: str | None = None) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    sem_bin = os.environ.get("ENGINEERINGOS_SEM_BIN") or shutil.which("sem")
    fallback: list[EvidenceItem] = []
    if entity and sem_bin:
        try:
            semantic = subprocess.run([sem_bin, "impact", entity, "--json"], cwd=repo, text=True, capture_output=True, timeout=30)
            if semantic.returncode == 0:
                payload = json.loads(semantic.stdout)
                return [EvidenceItem("git_diff", f"sem impact {entity}", json.dumps(item, sort_keys=True)[:500], f"sem:{entity}") for item in (payload.get("impacts", payload.get("entities", [])) if isinstance(payload, dict) else payload)]
            fallback.append(EvidenceItem("code_search", "change-impact", "sem was available but did not return a usable semantic result; using Git file-level evidence", f"sem:{entity}"))
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            fallback.append(EvidenceItem("code_search", "change-impact", "sem failed while producing semantic impact; using Git file-level evidence", f"sem:{entity}"))
    elif entity:
        fallback.append(EvidenceItem("code_search", "change-impact", "Semantic impact is unavailable because sem is not installed or configured; using Git file-level evidence", f"sem:{entity}"))
    if not (repo / ".git").exists():
        raise ToolHardFailure(f"Can't analyze change impact — '{repo}' is not a Git repository. Provide a Git checkout and retry.")
    try:
        diff = subprocess.run(["git", "diff", "--name-status", f"{revision}^", revision], cwd=repo, text=True, capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ToolHardFailure(f"Can't analyze change impact — Git could not complete: {exc}. Check the checkout and retry.")
    if diff.returncode:
        raise ToolHardFailure(f"Can't analyze change impact — revision '{revision}' is unavailable. Check the commit and retry.")
    return fallback + [EvidenceItem("git_diff", f"commit {revision}", line, f"commit:{revision}") for line in diff.stdout.splitlines()]
