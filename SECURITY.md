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

The optional `lsp_symbols` integration follows the same operator-owned process boundary. Its command is configured only by `ENGINEERINGOS_LSP_ADAPTER`; callers provide a repository-relative file, and the client enforces path, timeout, output, and symbol-count limits.

The optional MCP security-scanner adapter accepts only operator configuration, caps stdout at 1 MB and findings at 500, validates the findings container, and redacts credential-like values before returning evidence to a client.
