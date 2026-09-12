"""Optional target-repository security scanning: SAST (Semgrep) and secret
detection (Gitleaks). Each scanner is independently optional and only runs
when the operator has installed it and, for Semgrep, explicitly chosen a
rule configuration — mirroring impact_tools.py's `sem` integration, this
tool never fails the whole call just because one scanner is missing; it
reports an honest fallback evidence item for that scanner instead."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..audit import redact_sensitive

MAX_FINDINGS_PER_SCANNER = 200
MAX_OUTPUT_BYTES = 2_000_000


def _clean_env() -> dict:
    return {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE") if key in os.environ}


def _run_semgrep(sandbox: Path, timeout: int) -> list[EvidenceItem]:
    binary = os.environ.get("ENGINEERINGOS_SEMGREP_BIN") or shutil.which("semgrep")
    if not binary:
        return [EvidenceItem("code_search", "semgrep", "Semgrep is not installed or configured; SAST evidence is unavailable. Install semgrep and set ENGINEERINGOS_SEMGREP_CONFIG.", "semgrep")]
    # No default ruleset: "auto" requires opting into Semgrep's telemetry,
    # and any named registry ruleset (e.g. p/security-audit) fetches rules
    # over the network. Rather than silently choosing one on the operator's
    # behalf, require them to state their own preference explicitly — a
    # local rules file path is the fully offline option.
    config = os.environ.get("ENGINEERINGOS_SEMGREP_CONFIG")
    if not config:
        return [EvidenceItem("code_search", "semgrep", "Semgrep is installed but ENGINEERINGOS_SEMGREP_CONFIG is not set (a local rules file path, or a registry ruleset such as p/security-audit); SAST evidence is unavailable.", "semgrep")]
    try:
        result = subprocess.run(
            [binary, "scan", "--config", config, "--json", "--metrics=off", "--quiet", "--timeout", str(timeout), str(sandbox)],
            cwd=sandbox, env=_clean_env(), capture_output=True, text=True, timeout=timeout + 30, shell=False,
        )
    except subprocess.TimeoutExpired:
        return [EvidenceItem("code_search", "semgrep", f"Semgrep exceeded its {timeout}s budget; SAST evidence is incomplete.", "semgrep")]
    except OSError as exc:
        return [EvidenceItem("code_search", "semgrep", f"Semgrep could not start: {exc}.", "semgrep")]
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        return [EvidenceItem("code_search", "semgrep", "Semgrep returned too much output to summarize safely.", "semgrep")]
    try:
        payload = json.loads(result.stdout)
        findings = payload["results"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return [EvidenceItem("code_search", "semgrep", "Semgrep returned output that could not be parsed as JSON.", "semgrep")]
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS_PER_SCANNER:
        return [EvidenceItem("code_search", "semgrep", "Semgrep returned an invalid or unbounded findings list.", "semgrep")]
    if not findings:
        return [EvidenceItem("code_search", "semgrep", f"Semgrep (config={config}) found no matches.", "semgrep")]
    items = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        path = finding.get("path", "?")
        line = finding.get("start", {}).get("line", "?") if isinstance(finding.get("start"), dict) else "?"
        check_id = str(finding.get("check_id", "?"))[:200]
        extra = finding.get("extra", {}) if isinstance(finding.get("extra"), dict) else {}
        message = redact_sensitive(str(extra.get("message", "")), 300)
        severity = str(extra.get("severity", "?"))
        items.append(EvidenceItem("code_search", "semgrep", f"{severity} {check_id}: {message}", f"{path}#L{line}"))
    return items


def _run_gitleaks(sandbox: Path, timeout: int) -> list[EvidenceItem]:
    binary = os.environ.get("ENGINEERINGOS_GITLEAKS_BIN") or shutil.which("gitleaks")
    if not binary:
        return [EvidenceItem("code_search", "gitleaks", "Gitleaks is not installed or configured; secret-scan evidence is unavailable. Install gitleaks or set ENGINEERINGOS_GITLEAKS_BIN.", "gitleaks")]
    try:
        result = subprocess.run(
            [binary, "dir", str(sandbox), "--report-format", "json", "--report-path", "-", "--redact", "--no-banner", "--exit-code", "0", "--timeout", str(timeout)],
            cwd=sandbox, env=_clean_env(), capture_output=True, text=True, timeout=timeout + 30, shell=False,
        )
    except subprocess.TimeoutExpired:
        return [EvidenceItem("code_search", "gitleaks", f"Gitleaks exceeded its {timeout}s budget; secret-scan evidence is incomplete.", "gitleaks")]
    except OSError as exc:
        return [EvidenceItem("code_search", "gitleaks", f"Gitleaks could not start: {exc}.", "gitleaks")]
    if result.returncode != 0:
        return [EvidenceItem("code_search", "gitleaks", "Gitleaks returned an execution failure; inspect operator logs.", "gitleaks")]
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
        return [EvidenceItem("code_search", "gitleaks", "Gitleaks returned too much output to summarize safely.", "gitleaks")]
    try:
        findings = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return [EvidenceItem("code_search", "gitleaks", "Gitleaks returned output that could not be parsed as JSON.", "gitleaks")]
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS_PER_SCANNER:
        return [EvidenceItem("code_search", "gitleaks", "Gitleaks returned an invalid or unbounded findings list.", "gitleaks")]
    if not findings:
        return [EvidenceItem("code_search", "gitleaks", "Gitleaks found no leaked secrets.", "gitleaks")]
    items = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule = str(finding.get("RuleID", "?"))[:200]
        file_path = finding.get("File", "?")
        line = finding.get("StartLine", "?")
        description = redact_sensitive(str(finding.get("Description", "")), 300)
        items.append(EvidenceItem("code_search", "gitleaks", f"{rule}: {description}", f"{file_path}#L{line}"))
    return items


def code_security_scan(repo_path: str, timeout: int = 120) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    bounded_timeout = max(1, min(int(timeout), 600))
    semgrep_bin = os.environ.get("ENGINEERINGOS_SEMGREP_BIN") or shutil.which("semgrep")
    gitleaks_bin = os.environ.get("ENGINEERINGOS_GITLEAKS_BIN") or shutil.which("gitleaks")
    if not semgrep_bin and not gitleaks_bin:
        raise ToolHardFailure("Can't scan for code security issues — neither Semgrep nor Gitleaks is installed or configured. Install at least one before using this tool.")
    with tempfile.TemporaryDirectory(prefix="engineeringos-code-security-") as temp_dir:
        sandbox = Path(temp_dir) / "repo"
        shutil.copytree(repo, sandbox, ignore=shutil.ignore_patterns(".git", ".engineeringos", "__pycache__", ".pytest_cache", "node_modules", "target"))
        return _run_semgrep(sandbox, bounded_timeout) + _run_gitleaks(sandbox, bounded_timeout)
