"""Polyglot test discovery and bounded execution."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .. import worker_client
from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..test_runners import MAX_EVIDENCE_ITEMS, MAX_OUTPUT_BYTES, RUNNER_NAMES, TestRunner, detect, parse_result


def _scope(value: str | None) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ToolHardFailure("Can't run tests — test scope must be a non-empty relative path.")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or str(path).startswith("-"):
        raise ToolHardFailure("Can't run tests — test scope must stay inside the repository and cannot be an option.")
    return path


def test_plan(repo_path: str) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    runners = detect(repo)
    if not runners:
        raise ToolHardFailure("Can't plan tests — no supported test project was detected at the repository root.")
    return [
        EvidenceItem("test_result", "test_discovery", f"{item.name}: {'available' if item.available else 'toolchain unavailable'}; detected from {item.manifest}", item.manifest)
        for item in runners
    ]


def _select(repo: Path, runner: str | None) -> tuple[list[TestRunner], list[str]]:
    candidates = detect(repo)
    if runner is not None:
        names = {item.name for item in candidates}
        if not isinstance(runner, str) or runner not in names:
            raise ToolHardFailure("Can't run tests — requested runner was not detected. Call test_plan and choose a detected runner name.")
        candidates = [item for item in candidates if item.name == runner]
    if not candidates:
        raise ToolHardFailure("Can't run tests — no supported test project was detected. Call test_plan or pass a relative project directory as scope.")
    unavailable = [item.name for item in candidates if not item.available]
    return [item for item in candidates if item.available], unavailable


def run_tests(repo_path: str, scope: str | None = None, timeout: int = 60, runner: str | None = None) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    scope_path = _scope(scope)
    if runner is not None and (not isinstance(runner, str) or runner not in RUNNER_NAMES):
        raise ToolHardFailure("Can't run tests — runner must be an allow-listed test runner name returned by test_plan.")
    try:
        timeout = max(1, min(int(timeout), 15 * 60))
    except (TypeError, ValueError):
        raise ToolHardFailure("Can't run tests — timeout must be a whole number of seconds.")
    if worker_client.configured():
        return worker_client.run(repo, scope, timeout, runner)

    detection_root = repo / scope_path if scope_path and (repo / scope_path).is_dir() else repo
    selected, unavailable = _select(detection_root, runner)
    if not selected:
        raise ToolHardFailure(f"Can't run tests — detected toolchain(s) are unavailable: {', '.join(unavailable)}.")

    evidence: list[EvidenceItem] = []
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix="engineeringos-test-") as temp_dir:
        sandbox = Path(temp_dir) / "repo"
        shutil.copytree(repo, sandbox, ignore=shutil.ignore_patterns(".git", ".engineeringos", "__pycache__", ".pytest_cache"))
        clean_env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE") if key in os.environ}
        clean_env.update({"PYTHONDONTWRITEBYTECODE": "1", "CI": "1", "NO_COLOR": "1", "GIT_TERMINAL_PROMPT": "0", "DOTNET_NOLOGO": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1"})
        for item in selected:
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                raise ToolHardFailure("Can't run tests — the combined test plan exceeded its time budget. Choose one runner or narrower scope.")
            cwd = sandbox / scope_path if scope_path and (sandbox / scope_path).is_dir() else sandbox
            command = list(item.command)
            if scope_path and not (sandbox / scope_path).is_dir():
                if item.name not in {"pytest", "mix", "dart"}:
                    raise ToolHardFailure(f"Can't run tests — {item.name} accepts a project-directory scope here, not a file path.")
                command.append(str(scope_path))
            try:
                result = subprocess.run(command, cwd=cwd, env=clean_env, capture_output=True, text=True, timeout=remaining, shell=False)
            except subprocess.TimeoutExpired:
                raise ToolHardFailure(f"Can't run tests — {item.name} did not finish within the remaining time and was stopped.")
            except OSError as exc:
                raise ToolHardFailure(f"Can't run tests — {item.name} could not start: {exc}.")
            output = (result.stdout or "") + "\n" + (result.stderr or "")
            if len(output.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
                raise ToolHardFailure(f"Can't use test results — {item.name} produced more than {MAX_OUTPUT_BYTES} bytes of output.")
            evidence.extend(parse_result(item, output, result.returncode))
    if unavailable:
        evidence.append(EvidenceItem("test_result", "test_discovery", f"SKIPPED unavailable toolchain(s): {', '.join(unavailable)}", "test_plan"))
    return evidence[:MAX_EVIDENCE_ITEMS]
