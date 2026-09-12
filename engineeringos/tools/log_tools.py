"""
search_logs — READ tier.

V0 note: reads a local log file directly. In the hosted design (spec §9),
this is the natural place to plug in a real log backend (Datadog, Loki,
CloudWatch) behind the same function signature — the workflow layer
doesn't need to know or care which one is behind it.
"""

from __future__ import annotations

from pathlib import Path

from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..audit import redact_sensitive


def search_logs(log_path: str, query: str, max_results: int = 20) -> list[EvidenceItem]:
    path = allowed_path(log_path)
    if not isinstance(query, str) or not query.strip():
        raise ToolHardFailure("Can't search logs — the query is empty. Provide a specific message, ID, or error text.")
    max_results = max(1, min(int(max_results), 1_000))

    items: list[EvidenceItem] = []
    with open(path) as f:
        for i, line in enumerate(f, start=1):
            if query.lower() in line.lower():
                items.append(
                    EvidenceItem(
                        type="log",
                        source=str(path.name),
                        summary=redact_sensitive(line.strip(), 300),
                        ref=f"{path.name}#L{i}",
                    )
                )
            if len(items) >= max_results:
                break
    return items
