"""Safe, deterministic project diagnostics executed from a disposable copy."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..audit import redact_sensitive


def _checks(repo: Path) -> list[tuple[str, list[str]]]:
    checks: list[tuple[str, list[str]]] = []
    if any(repo.glob("*.py")) or (repo / "pyproject.toml").exists():
        checks.append(("python-compile", [sys.executable, "-m", "compileall", "-q", "."]))
    if shutil.which("ruff") and ((repo / "pyproject.toml").exists() or any(repo.glob("*.py"))):
        checks.append(("ruff", ["ruff", "check", ".", "--output-format", "concise"]))
    if shutil.which("eslint") and (repo / "package.json").exists():
        checks.append(("eslint", ["eslint", ".", "--no-error-on-unmatched-pattern"]))
    if shutil.which("tsc") and (repo / "tsconfig.json").exists():
        checks.append(("typescript", ["tsc", "--noEmit", "--pretty", "false"]))
    if shutil.which("go") and (repo / "go.mod").exists():
        checks.append(("go-vet", ["go", "vet", "./..."]))
    if shutil.which("cargo") and (repo / "Cargo.toml").exists():
        checks.append(("cargo-check", ["cargo", "check", "--locked"]))
    return checks


def diagnostics(repo_path: str, timeout: int = 60) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    timeout = max(1, min(int(timeout), 900))
    checks = _checks(repo)
    if not checks:
        raise ToolHardFailure("Can't run diagnostics — no supported local checker was detected. Install a checker or add the project's standard manifest.")

    results: list[EvidenceItem] = []
    with tempfile.TemporaryDirectory(prefix="engineeringos-diagnostics-") as temp_dir:
        sandbox = Path(temp_dir) / "repo"
        shutil.copytree(repo, sandbox, ignore=shutil.ignore_patterns(".git", ".engineeringos", "__pycache__", ".pytest_cache", "node_modules", "target"))
        clean_env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE") if key in os.environ}
        clean_env["PYTHONDONTWRITEBYTECODE"] = "1"
        for name, command in checks:
            try:
                result = subprocess.run(command, cwd=sandbox, env=clean_env, capture_output=True, text=True, timeout=timeout, shell=False)
            except subprocess.TimeoutExpired:
                results.append(EvidenceItem("diagnostic", name, f"TIMEOUT after {timeout}s", name))
                continue
            except OSError as exc:
                results.append(EvidenceItem("diagnostic", name, f"ERROR: checker could not start: {exc}", name))
                continue
            status = "PASSED" if result.returncode == 0 else "FAILED"
            output = (result.stdout or result.stderr or "no diagnostic output").strip().splitlines()
            detail = redact_sensitive(" | ".join(output[-3:]), 700)
            results.append(EvidenceItem("diagnostic", name, f"{status}: {detail}", name))
    return results
