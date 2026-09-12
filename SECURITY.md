# Security boundary

The remote HTTP process authenticates requests with an OIDC JWT, requires a tenant claim, and constrains repository paths to the matching subdirectory under `ENGINEERINGOS_TENANT_ROOT`. The local test worker executes from a disposable copy and never writes to the indexed checkout.

JWT verification accepts only approved RSA/ECDSA algorithms, validates issuer/audience/expiry/scopes, caps bearer tokens at 16 KB, and requires `azp` for multi-audience tokens. `ENGINEERINGOS_ALLOW_INSECURE_OIDC=1` permits HTTP only for loopback issuer and JWKS endpoints.

Permission tiers are enforced server-side. Tools marked approval-required in `permissions.yaml` run only when the validated access token contains their exact name in the trusted `engineeringos_approvals` list claim. Configure a different claim name with `ENGINEERINGOS_APPROVAL_CLAIM`; caller-supplied tool arguments can never grant approval.

Production indexing writes only to `ENGINEERINGOS_INDEX_ROOT`, a dedicated writable volume outside read-only tenant repositories. Repository paths are hashed into storage identities, and raw source is never stored in the SQLite map.
Startup rejects source/index roots that overlap and verifies the index root is writable. SQLite uses WAL mode, normal synchronous durability, a five-second busy timeout, and restrictive database permissions where the host supports them.

Authenticated tool calls are rate-limited per tenant and token subject in-process. Configure `ENGINEERINGOS_RATE_LIMIT_PER_MINUTE` and `ENGINEERINGOS_RATE_LIMIT_KEYS`; when running multiple replicas, apply an equivalent shared limit at the API gateway because in-process counters are intentionally local to one instance.

Audit events are append-only JSONL records with bounded fields. The audit writer redacts bearer credentials, JWT-shaped values, and common API-key/token/password/secret assignments before writing; operators should still protect the audit volume as sensitive operational data.
Authenticated tenant identity is propagated through request-local context into audit events and reset after each tool call, preventing concurrent requests from contaminating one another's tenant attribution.

For production, customer code that can execute arbitrary subprocesses must run in a separate worker boundary (microVM or hardened container) with:

- no network egress;
- read-only source mount and ephemeral writable scratch;
- CPU, memory, process-count, and wall-clock limits;
- a distinct service identity per tenant;
- an append-only audit sink outside the worker.

The repository includes the `SandboxPolicy` contract and a hardened local fallback, but it does not claim that a normal host process is equivalent to a microVM. Deploy `run_tests` behind the worker service before enabling untrusted customer repositories.

The authenticated production entrypoint requires `ENGINEERINGOS_TEST_WORKER` by default and refuses to start without it. Set `ENGINEERINGOS_REQUIRE_SANDBOX_WORKER=0` only for controlled local development; never use that override for customer-controlled repositories.

Responses include no-store caching, MIME sniffing protection, referrer restriction, and a restrictive permissions policy. HSTS is opt-in through `ENGINEERINGOS_ENABLE_HSTS=1` because enabling it before TLS is guaranteed can lock clients into an invalid transport configuration.

Set `ENGINEERINGOS_TEST_WORKER` to an operator-owned executable to use the external worker protocol. The MCP sends repository path, scope, an optional allow-listed runner name, timeout, `network=false`, and `read_only_checkout=true` as JSON on stdin; the worker must independently enforce the runner allow-list and return `{"evidence": [...]}` JSON on stdout. Callers cannot choose or override the worker command.

The client validates runner names before worker dispatch, clamps worker timeouts to 15 minutes, passes only a minimal process environment, caps worker output at 1 MB and evidence at 1,000 items, and rejects oversized evidence fields. These checks complement—but do not replace—the worker's microVM/container isolation, outbound-network denial, process limits, and resource limits. The disposable-copy local fallback is for trusted local development only.

The optional `lsp_symbols` integration follows the same operator-owned process boundary when `ENGINEERINGOS_LSP_ADAPTER` is set. Its command is configured only by that variable; callers provide a repository-relative file, and the client enforces path, timeout, output, and symbol-count limits.

When no adapter is configured, `lsp_symbols` falls back to a bundled default backend (`multilspy`, optional `lsp` extra) for Python only. This is a materially different trust boundary than every other integration in this document — instead of an operator-supplied external process, it is library code running in-process that itself launches a language-server subprocess. It is disabled by default on Windows (confirmed by testing: a trivial case hung for several minutes past its configured timeout there, while the identical case succeeded in under 2 seconds on Linux) and disabled for every language except Python (the other languages multilspy supports need externally available language servers whose download/availability behavior has not been individually verified). `ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS=1` overrides the Windows restriction for an operator who has evaluated the risk themselves. Path containment and the same symbol-count/name-length caps as the adapter path still apply.

The optional MCP security-scanner adapter accepts only operator configuration, caps stdout at 1 MB and findings at 500, validates the findings container, and redacts credential-like values before returning evidence to a client. It recognizes Cisco `mcp-scanner`'s distinct `behavioral <path> --format raw` invocation as well as the legacy `mcp-scan`/`agent-scan` `<path> --json` shape; an unrecognized binary name falls back to the legacy shape as a best effort.

`code_security_scan` (Semgrep SAST + Gitleaks secret detection) and `vulnerability_scan` (OSV-Scanner SCA) follow the same operator-installed, presence-detected posture as every other optional scanner here — none of the three binaries is bundled or downloaded by this project. Semgrep additionally requires an explicit `ENGINEERINGOS_SEMGREP_CONFIG` (a local rules file path, or a registry ruleset name such as `p/security-audit`) rather than defaulting to one on the operator's behalf, because Semgrep's own `auto` config requires opting into its telemetry and any registry ruleset name fetches rules over the network — a choice this project will not make silently. `vulnerability_scan` queries the public osv.dev database by default, which is inherent to what a live vulnerability check is, not an incidental network call; this is stated in the tool description and in every evidence item's source label, and `ENGINEERINGOS_OSV_SCANNER_OFFLINE=1` switches to a pre-downloaded local database for operators who need zero live network calls. All three tools run from a disposable copy of the target repository (Semgrep/Gitleaks) or read manifests directly like `dependency_health` does (OSV-Scanner, which only parses lockfiles).

**Operational note**: install Semgrep, Gitleaks, OSV-Scanner, and any MCP security scanner as standalone tools (a dedicated virtual environment, `pipx`/`uvx`, a Go binary, or a system package manager) — never as a `pip install` alongside `engineeringos-mcp` itself. Semgrep in particular bundles its own MCP server and its own `mcp` SDK dependency; installing it into the same environment as this project silently downgrades the `mcp` package this server needs, breaking it in a way that is not obvious until something using the SDK fails. This was discovered directly during development, not theorized.

The optional `tree-sitter-language-pack` backend (`parsing-pack` extra) only ever consults a grammar that is already downloaded to its local cache; it never fetches one over the network from inside a tool call. An operator who wants broader language coverage than the pinned `parsing` extra provides runs a one-time prefetch (see README) before relying on it — this keeps every code-search/indexing tool's behavior fully offline and deterministic during normal operation, consistent with everything else in this document.
