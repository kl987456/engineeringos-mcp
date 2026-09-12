"""
Evidence-chain schema (spec §6) and error/uncertainty helpers (spec §10).

Design rule that matters most here: this module never forms a "root cause
claim" on its own. It only carries evidence. Forming a claim requires
reasoning, and reasoning belongs to the calling model (Claude Code, Cursor,
etc.) — not to this deterministic tool layer. See workflows/investigate.py
for where this gets assembled and handed back un-conclusioned.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Literal, Optional


EvidenceType = Literal["log", "git_diff", "git_commit", "test_result", "diagnostic", "code_search"]
Confidence = Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"]


@dataclass
class EvidenceItem:
    type: EvidenceType
    source: str          # e.g. "production_logs", "commit 0299eff", "pytest"
    summary: str         # short, human-readable description of what was found
    ref: str             # pointer back to the raw thing (file#line, commit sha, test id)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvidenceChain:
    """
    The shared result shape every workflow tool returns (spec §6).

    `claim` and `confidence` are intentionally left as None/UNKNOWN when this
    object is built by a pure evidence-gathering tool like `investigate()`.
    They only get filled in by something that actually reasoned over the
    evidence — either the calling model, or (later, optionally) an internal
    LLM-as-judge step for specific diagnostic features. A tool that fills
    these in itself using string-matching heuristics would be quietly
    reinventing bad AI inside the "deterministic" layer — exactly what the
    architecture is designed to avoid.
    """

    question: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    claim: Optional[str] = None
    confidence: Confidence = "UNKNOWN"
    alternative_hypotheses_considered: list[dict] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)  # steps that failed/were skipped
    note: str = (
        "This tool gathers evidence only. Forming a root-cause claim from "
        "this evidence is left to the calling model."
    )

    def to_dict(self) -> dict:
        return {
            "question": self.question,
            "evidence": [e.to_dict() for e in self.evidence],
            "claim": self.claim,
            "confidence": self.confidence,
            "alternative_hypotheses_considered": self.alternative_hypotheses_considered,
            "incomplete": self.incomplete,
            "note": self.note,
        }


class ToolHardFailure(Exception):
    """
    Raise this for genuine hard failures (spec §10.1) — the tool could not
    run at all. The message MUST answer: what didn't work, why (if known),
    and what to do next, in one short sentence each. This gets surfaced to
    the calling agent as an actual MCP tool error (isError: true), not
    swallowed into a fake "successful" result.
    """
    pass
