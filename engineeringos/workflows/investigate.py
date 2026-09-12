"""
investigate() — the workflow tool from spec §5/§20.

What this deliberately does NOT do: guess a root cause. It gathers
evidence from git history, code search, logs, and tests, and hands all of
it back structured. Forming the actual "here's why it's failing" claim is
left to the calling model, which can reason over real evidence instead of
this tool pretending to reason with string-matching heuristics.

What this deliberately DOES do (spec §10):
  - keeps evidence from steps that succeeded even if other steps fail
  - records exactly which steps failed and why, instead of aborting silently
"""

from __future__ import annotations

from ..evidence import EvidenceChain, ToolHardFailure
from ..tools import git_tools, search_tools, test_tools, log_tools
from .. import indexer


def investigate(
    question: str,
    repo_path: str,
    search_query: str | None = None,
    log_path: str | None = None,
    log_query: str | None = None,
    since: str = "30d",
) -> dict:
    """
    Gather evidence relevant to `question` from the repo's recent git
    history, a code search, a log search (if a log source is given), and
    the repo's test suite. Returns an EvidenceChain dict — never raises for
    partial failures, only for total inability to gather any evidence.
    """
    chain = EvidenceChain(question=question)

    try:
        chain.evidence.append(indexer.freshness(repo_path))
    except ToolHardFailure as e:
        chain.incomplete.append(f"index_freshness: {e}")

    # 1. Recent changes — almost always relevant, so this failing is a
    #    strong signal, but we still try everything else.
    try:
        chain.evidence.extend(git_tools.recent_changes(repo_path, since=since))
    except ToolHardFailure as e:
        chain.incomplete.append(f"recent_changes: {e}")

    # 2. Code search — only if the caller gave us something to search for.
    if search_query:
        try:
            chain.evidence.extend(search_tools.search_code(repo_path, search_query))
        except ToolHardFailure as e:
            chain.incomplete.append(f"search_code: {e}")

    # 3. Log search — only if a log source was actually connected.
    if log_path and log_query:
        try:
            chain.evidence.extend(log_tools.search_logs(log_path, log_query))
        except ToolHardFailure as e:
            chain.incomplete.append(f"search_logs: {e}")

    # 4. Test run — reproduction is the strongest evidence available.
    try:
        chain.evidence.extend(test_tools.run_tests(repo_path))
    except ToolHardFailure as e:
        chain.incomplete.append(f"run_tests: {e}")

    # 5. For every commit found, pull its actual diff so the calling model
    #    has real changed-line evidence, not just a commit message.
    commit_shas = [e.ref.split(":", 1)[1] for e in chain.evidence if e.type == "git_commit"]
    for sha in commit_shas[:5]:  # cap it — don't flood context with every commit's diff
        try:
            chain.evidence.append(git_tools.git_diff(repo_path, sha))
        except ToolHardFailure as e:
            chain.incomplete.append(f"git_diff({sha[:7]}): {e}")

    if not chain.evidence:
        # Every single step failed — this genuinely is a hard failure, not
        # a "here's an empty evidence chain" soft result.
        raise ToolHardFailure(
            "Couldn't gather any evidence at all — every investigation step failed: "
            + "; ".join(chain.incomplete)
        )

    if chain.incomplete:
        chain.note = (
            f"Evidence gathered from {len(chain.evidence)} sources. "
            f"{len(chain.incomplete)} step(s) could not run — see 'incomplete'. "
            "Forming a root-cause claim from this evidence is left to the calling model."
        )

    return chain.to_dict()
