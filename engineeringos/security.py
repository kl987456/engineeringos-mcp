"""Request-boundary checks for filesystem-backed tools and HTTP tenancy."""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque
from dataclasses import replace
from pathlib import Path
from typing import Any

from mcp.shared.exceptions import MCPError

from .evidence import ToolHardFailure
from .permissions import requires_approval
from .audit import tenant_context


def _within(path: Path, root: Path) -> bool:
    """Use resolved paths so prefix tricks and symlink escapes do not pass."""
    return path == root or root in path.parents


def allowed_path(value: str, *, must_be_dir: bool = False) -> Path:
    """Resolve a local path and, when configured, keep it under the repo root."""
    try:
        path = Path(value).expanduser().resolve()
    except (TypeError, ValueError, OSError):
        raise ToolHardFailure("Access denied — the requested path is invalid. Use a path assigned to this tenant.")

    root_value = os.environ.get("ENGINEERINGOS_REPO_ROOT")
    if root_value:
        root = Path(root_value).expanduser().resolve()
        if not _within(path, root):
            raise ToolHardFailure(
                "Access denied — the requested path is outside the configured tenant repository root. "
                "Use a repository assigned to this tenant."
            )
    if not path.exists() or (must_be_dir and not path.is_dir()):
        raise ToolHardFailure(f"Requested path '{path}' is unavailable. Check the tenant repository and retry.")
    return path


class TenantPathPolicy:
    """Map a validated token tenant claim to one isolated filesystem subtree."""

    _TENANT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")

    def __init__(self, root: str | Path, claim: str = "tenant_id"):
        self.root = Path(root).expanduser().resolve()
        self.claim = claim
        if not self.root.is_dir():
            raise RuntimeError("ENGINEERINGOS_TENANT_ROOT must point to an existing directory")

    def tenant_id(self, request: Any) -> str:
        scope = getattr(request, "scope", {}) or {}
        user = scope.get("user")
        access_token = getattr(user, "access_token", None)
        claims = getattr(access_token, "claims", None) or {}
        tenant_id = claims.get(self.claim)
        if not isinstance(tenant_id, str) or not self._TENANT_ID.fullmatch(tenant_id) or tenant_id in {".", ".."}:
            raise MCPError(-32602, "The access token does not identify a valid tenant")
        return tenant_id

    def resolve(self, request: Any, value: str, *, base: Path | None = None) -> Path:
        if "\x00" in value:
            raise MCPError(-32602, "The requested path is invalid")
        tenant_root = (self.root / self.tenant_id(request)).resolve()
        candidate = Path(value).expanduser()
        if not candidate.is_absolute() and base is not None:
            candidate = base / candidate
        elif not candidate.is_absolute():
            candidate = tenant_root / candidate
        candidate = candidate.resolve()
        if not _within(candidate, tenant_root):
            raise MCPError(-32602, "The requested path is outside the tenant boundary")
        return candidate


class TenantIsolationMiddleware:
    """Rewrite path arguments to tenant-scoped absolute paths before validation."""

    _PATH_KEYS = {"repo_path", "log_path"}

    def __init__(self, policy: TenantPathPolicy):
        self.policy = policy

    async def __call__(self, ctx, call_next):
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)

        params = dict(ctx.params)
        arguments = dict(params.get("arguments") or {})
        if not arguments:
            with tenant_context(self.policy.tenant_id(ctx.request)):
                return await call_next(ctx)

        tenant_id = self.policy.tenant_id(ctx.request)
        repo_path = arguments.get("repo_path")
        if isinstance(repo_path, str):
            repo = self.policy.resolve(ctx.request, repo_path)
            arguments["repo_path"] = str(repo)
        else:
            repo = None

        log_path = arguments.get("log_path")
        if isinstance(log_path, str):
            arguments["log_path"] = str(self.policy.resolve(ctx.request, log_path))

        file_path = arguments.get("file_path")
        if isinstance(file_path, str) and repo is not None:
            resolved_file = self.policy.resolve(ctx.request, file_path, base=repo)
            arguments["file_path"] = str(resolved_file.relative_to(repo))

        scope = arguments.get("scope")
        if isinstance(scope, str):
            if scope.startswith("-"):
                raise MCPError(-32602, "Test scope must be a path, not a pytest option")
            scope_parts = scope.split("::", 1)
            scope_path = self.policy.resolve(ctx.request, scope_parts[0], base=repo)
            if repo is not None:
                scope_value = str(scope_path.relative_to(repo))
            else:
                scope_value = str(scope_path)
            arguments["scope"] = scope_value + (("::" + scope_parts[1]) if len(scope_parts) == 2 else "")

        params["arguments"] = arguments
        with tenant_context(tenant_id):
            return await call_next(replace(ctx, params=params))


class SecurityHeadersMiddleware:
    """Add conservative response headers without buffering streaming bodies."""

    def __init__(self, app, *, hsts: bool = False):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in headers}
                additions = [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]
                if self.hsts:
                    additions.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                headers.extend((key, value) for key, value in additions if key not in existing)
                message = dict(message)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


class PermissionEnforcementMiddleware:
    """Enforce approval-required tool tiers from trusted access-token claims."""

    def __init__(self, approval_claim: str = "engineeringos_approvals"):
        self.approval_claim = approval_claim

    async def __call__(self, ctx, call_next):
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)
        tool_name = ctx.params.get("name")
        if not isinstance(tool_name, str) or not requires_approval(tool_name):
            return await call_next(ctx)
        request = getattr(ctx, "request", None)
        scope = getattr(request, "scope", {}) or {}
        user = scope.get("user")
        access_token = getattr(user, "access_token", None)
        claims = getattr(access_token, "claims", None) or {}
        approvals = claims.get(self.approval_claim, [])
        if not isinstance(approvals, list) or not all(isinstance(item, str) for item in approvals) or tool_name not in approvals:
            raise MCPError(-32003, f"Human approval is required for tool '{tool_name}'")
        return await call_next(ctx)


class RequestRateLimitMiddleware:
    """Bound tool-call volume per authenticated subject and tenant.

    This is intentionally a small in-process guardrail. Production deployments
    with multiple replicas should also enforce the same limit at the gateway
    or use a shared limiter; the local guard still protects a single instance
    from accidental or bursty abuse.
    """

    def __init__(self, requests: int = 120, window_seconds: int = 60, max_keys: int = 10_000, tenant_claim: str = "tenant_id"):
        if requests < 1 or window_seconds < 1 or max_keys < 1:
            raise ValueError("rate-limit settings must be positive")
        self.requests = requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.tenant_claim = tenant_claim
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def _identity(self, ctx) -> str:
        request = getattr(ctx, "request", None)
        scope = getattr(request, "scope", {}) or {}
        user = scope.get("user")
        token = getattr(user, "access_token", None)
        claims = getattr(token, "claims", None) or {}
        tenant = str(claims.get(self.tenant_claim, "unknown"))
        subject = str(claims.get("sub", "anonymous"))
        return f"{tenant}:{subject}"

    async def __call__(self, ctx, call_next):
        if ctx.method != "tools/call":
            return await call_next(ctx)
        now = time.monotonic()
        key = self._identity(ctx)
        events = self._events[key]
        cutoff = now - self.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= self.requests:
            raise MCPError(-32029, "Rate limit exceeded; retry after the current window.")
        events.append(now)
        if len(self._events) > self.max_keys:
            oldest = min(self._events, key=lambda name: self._events[name][0] if self._events[name] else now)
            self._events.pop(oldest, None)
        return await call_next(ctx)
