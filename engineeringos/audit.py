"""Append-only structured audit events for tool execution."""
from __future__ import annotations
import json, os, re, time, uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

_CURRENT_TENANT: ContextVar[str] = ContextVar("engineeringos_tenant", default="unknown")

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\s*[=:]\s*([^\s,;]+)"), r"\1=[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED_JWT]"),
)


def redact_sensitive(value: str, limit: int = 500) -> str:
    text = " ".join(str(value).split())
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:limit]


@contextmanager
def tenant_context(tenant: str):
    token = _CURRENT_TENANT.set(redact_sensitive(tenant, 160))
    try:
        yield
    finally:
        _CURRENT_TENANT.reset(token)


def current_tenant() -> str:
    """Return the authenticated tenant propagated by request middleware."""
    return _CURRENT_TENANT.get()


def record(tool: str, *, status: str, tenant: str | None = None, detail: str | None = None) -> None:
    target = os.environ.get("ENGINEERINGOS_AUDIT_LOG")
    if not target:
        return
    event = {"timestamp": time.time(), "event_id": str(uuid.uuid4()), "tool": redact_sensitive(tool, 100), "status": redact_sensitive(status, 80), "tenant": redact_sensitive(tenant or _CURRENT_TENANT.get(), 160)}
    if detail: event["detail"] = redact_sensitive(detail)
    path = Path(target); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, separators=(",", ":")) + "\n")
