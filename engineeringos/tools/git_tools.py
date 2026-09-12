"""
Git tools — READ tier. Real subprocess calls to git, no mocking.

V0 note: this is the piece that stays exactly this simple even in V1/V2.
The entity-level diffing (spec §8, the `sem` tool) is what upgrades this
from "line-level git log" to "which functions actually changed" — swap it
in here later without touching the workflow layer that calls this.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import re

from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path


def _normalize_since(since: str) -> str:
    """
    Accepts shorthand like '30d' or '2w' (our spec's convention) and turns
    it into something git's --since actually parses. Anything that doesn't
    match the shorthand pattern is passed through untouched, so callers can
    still use git-native formats like '2024-01-01' or '1 week ago'.

    This exists because of a real bug caught by testing: git silently
    returns zero results for '--since=365d' instead of erroring — it needs
    '365 days'. Silent-wrong is worse than loud-wrong, which is exactly why
    this got caught by running the tool, not by reading the code.
    """
    match = re.fullmatch(r"(\d+)([dwmy])", since.strip())
    if not match:
        return since
    count, unit = match.groups()
    unit_name = {"d": "days", "w": "weeks", "m": "months", "y": "years"}[unit]
    return f"{count} {unit_name}"


def _run_git(repo_path: str, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", repo_path] + args,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        raise ToolHardFailure(
            "Can't check git history — git isn't installed on this server. "
            "Install git, or ask an admin to fix the server environment."
        )
    except subprocess.TimeoutExpired:
        raise ToolHardFailure(
            "Can't check git history — the git command took too long and was stopped. "
            "This usually means a very large repo; try narrowing the file path."
        )

    if result.returncode != 0:
        raise ToolHardFailure(
            f"Can't check git history — git reported: {result.stderr.strip()[:200]}. "
            "Check the repo path is correct and this is actually a git repository."
        )
    return result.stdout


def recent_changes(repo_path: str, file_path: str | None = None, since: str = "30d") -> list[EvidenceItem]:
    """Commits touching a file (or the whole repo) within a time window."""
    repo = allowed_path(repo_path, must_be_dir=True)
    if not repo.exists():
        raise ToolHardFailure(
            f"Can't check git history — the path '{repo_path}' doesn't exist on this server. "
            "Confirm the local indexer has been pointed at the right repo."
        )

    args = ["log", f"--since={_normalize_since(since)}", "--pretty=format:%H|%ad|%s", "--date=iso-strict"]
    if file_path:
        candidate = Path(file_path)
        if not candidate.is_absolute():
            candidate = repo / candidate
        candidate = candidate.resolve()
        if candidate != repo and repo not in candidate.parents:
            raise ToolHardFailure("Can't check git history — the requested file is outside the repository.")
        args += ["--", str(candidate.relative_to(repo))]

    output = _run_git(repo_path, args)
    items: list[EvidenceItem] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        sha, date, subject = line.split("|", 2)
        items.append(
            EvidenceItem(
                type="git_commit",
                source=f"commit {sha[:7]}",
                summary=subject,
                ref=f"commit:{sha}",
            )
        )
    return items


def git_diff(repo_path: str, commit: str) -> EvidenceItem:
    """The actual diff for one commit, so a claim can point at real changed lines."""
    repo_path = str(allowed_path(repo_path, must_be_dir=True))
    if not isinstance(commit, str) or not commit.strip() or commit.startswith("-") or "\x00" in commit or len(commit) > 200:
        raise ToolHardFailure("Can't inspect git diff — the revision identifier is invalid. Provide a commit, tag, or branch name.")
    output = _run_git(repo_path, ["show", "--stat", "--patch", commit])
    # Keep this short — a workflow tool's job is to summarize, not dump a
    # full diff into the calling model's context.
    summary_lines = output.splitlines()[:15]
    return EvidenceItem(
        type="git_diff",
        source=f"commit {commit[:7]}",
        summary="\n".join(summary_lines),
        ref=f"commit:{commit}",
    )
