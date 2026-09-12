# EngineeringOS MCP

Evidence-first engineering workflows for MCP clients. The server gathers code, Git, logs, and test evidence; it never invents a root-cause claim.

See [`ROADMAP.md`](ROADMAP.md) for current state, what's deliberately deferred and why, and the suggested next increment. See [`VERDICT.md`](VERDICT.md) for an evidence-based assessment of whether this is actually a good product to solve developer problems, and why.

## Quick install

To just use the CLI (not develop the project itself), install straight from GitHub — no PyPI account needed:

```powershell
irm https://raw.githubusercontent.com/kl987456/engineeringos-mcp/master/install.ps1 | iex
```
```bash
curl -fsSL https://raw.githubusercontent.com/kl987456/engineeringos-mcp/master/install.sh | bash
```

Both scripts just run `pip install` against this repo — read [`install.ps1`](install.ps1) or [`install.sh`](install.sh) before piping them into your shell, same as you would for any installer. This gives you `engineeringos-mcp`, `engineeringos-dashboard`, `engineeringos-eval`, `engineeringos-preflight`, and `engineeringos-map` on PATH. Register it with Claude Code globally (works in every project, not just this repo):

```bash
claude mcp add engineeringos -s user -- engineeringos-mcp
```

## Local run (for developing EngineeringOS itself)

Use a project-local virtual environment rather than installing into your system Python — this keeps EngineeringOS's dependencies isolated and, critically, avoids version conflicts with any operator-installed scanner CLI you later add (see the scanner setup note below).

```powershell
python -m venv .venv
.venv\Scripts\pip install -e .
$env:PYTHONPATH = "."
.venv\Scripts\python -m engineeringos.server
```

After installing the package, use `engineeringos-mcp` for the local stdio server, `engineeringos-dashboard` for the local control room, `engineeringos-eval sample-repo` for the golden evidence regression, and `engineeringos-preflight` to validate production configuration without printing configured secret values.

See `CLIENTS.md` for ready-to-copy local setup for Claude Code, Codex, Cursor, and Gemini CLI, plus a two-agent investigator/verifier workflow.

## Production HTTP run

Set `ENGINEERINGOS_OIDC_ISSUER`, `ENGINEERINGOS_OIDC_AUDIENCE`, `ENGINEERINGOS_TENANT_ROOT`, `ENGINEERINGOS_INDEX_ROOT`, `ENGINEERINGOS_ALLOWED_HOSTS`, and an operator-owned `ENGINEERINGOS_TEST_WORKER`; optionally set `ENGINEERINGOS_OIDC_SCOPES`, `ENGINEERINGOS_OIDC_JWKS_URI`, and `ENGINEERINGOS_ALLOWED_ORIGINS`. Then run `uvicorn engineeringos.production:application --host 0.0.0.0 --port 8000`. Use TLS and an allow-listed reverse proxy at the edge. Tenant repositories must be stored as one directory per validated token tenant claim, or remain in customer-side indexers or isolated workers. The production entrypoint refuses to start without a worker unless `ENGINEERINGOS_REQUIRE_SANDBOX_WORKER=0` is explicitly set for local development.
The app emits conservative security headers; set `ENGINEERINGOS_ENABLE_HSTS=1` only when HTTPS is guaranteed at the edge for the hostname and all subdomains.

## Container deployment

`docker-compose.yml` runs as a non-root user with a read-only filesystem, dropped Linux capabilities, no-new-privileges, read-only tenant repositories, and a separate audit-log volume. Set `ENGINEERINGOS_TENANT_REPOS` before starting it. Set `ENGINEERINGOS_AUDIT_LOG` to enable JSONL audit events. `ENGINEERINGOS_RATE_LIMIT_PER_MINUTE` configures the per-tenant/per-subject tool-call guardrail (default: 120), while `ENGINEERINGOS_RATE_LIMIT_KEYS` bounds in-process limiter memory (default: 10,000). Multi-replica deployments should enforce a matching shared limit at the gateway.

## Verification

Run the sample suite from its repository directory:

```powershell
Push-Location sample-repo
python -m pytest -q
Pop-Location
```

## Local dashboard

Start the local-only control room with `python -m dashboard.server` and open `http://127.0.0.1:8765`. Set `ENGINEERINGOS_AUDIT_LOG` to the MCP JSONL audit file. It visualizes health, calls, success rate, errors, stale indexes, tenant activity, tool volume, security/worker signals, and recent audit events; it refreshes every ten seconds and sends no data externally.

If the optional `sem` CLI is installed, set `ENGINEERINGOS_SEM_BIN` and pass an entity to `analyze_change` for entity-level impact analysis. The server falls back to Git evidence when `sem` is unavailable.

`code_security_scan` runs Semgrep (SAST) and Gitleaks (secret detection) against the target repository from a disposable copy, each independently optional. Gitleaks needs no configuration beyond being on `PATH` or set via `ENGINEERINGOS_GITLEAKS_BIN`. Semgrep additionally requires `ENGINEERINGOS_SEMGREP_CONFIG` — a local rules file path, or a registry ruleset such as `p/security-audit` — since it has no config that is both meaningful and network-free by default; the tool reports an honest fallback for either scanner that isn't configured rather than failing outright, and only hard-fails if neither is. `vulnerability_scan` runs OSV-Scanner against detected dependency manifests for known-vulnerability matches; unlike the other scanners here, this queries the public osv.dev database by default (documented in the tool output's source label), and `ENGINEERINGOS_OSV_SCANNER_OFFLINE=1` switches to a pre-downloaded local database instead. Install all three as standalone tools — never into this project's own environment (see SECURITY.md for why).

The `diagnostics` tool detects only approved project-native checks (Python compile, Ruff, ESLint, TypeScript, Go vet, and Cargo check), runs them from a disposable copy, and never accepts arbitrary commands from an MCP caller. `test_plan` discovers supported test projects without executing repository code. `run_tests` uses a fixed command allow-list for pytest, npm/pnpm/Yarn, Go, Cargo, .NET, Maven, Gradle, Swift, sbt, Dart, Mix, RSpec, PHPUnit, and CTest; callers may select a detected runner but can never supply a command. Network-avoiding/offline flags are used where the underlying runner supports them.

After `index_code`, `dependency_graph` queries bounded direct callers or callees from the local SQLite symbol map. Python references are populated from its AST, while deterministic call edges are also extracted for supported non-Python languages; optional Tree-sitter and LSP adapters improve structural symbol fidelity.

Run the golden evidence regression locally with `python -m engineeringos.evaluations sample-repo`. It checks that the investigation workflow returns code, log, and test evidence while keeping `claim` unset and confidence `UNKNOWN`.

Clients can read `engineeringos://capabilities` to see which optional integrations are actually active in the current process. It reports semantic-impact, security-scanner, sandbox-worker, and parser-backend status so unavailable integrations are not mistaken for supported evidence.

Approval-required permission tiers are enforced from a trusted token claim, defaulting to `engineeringos_approvals`. The claim must contain the exact approved tool names; change its name with `ENGINEERINGOS_APPROVAL_CLAIM` when integrating an authorization service.

`lsp_symbols` is an optional structural adapter seam. Set `ENGINEERINGOS_LSP_ADAPTER` to an operator-owned executable that accepts `{repo_path, file_path, language, timeout_seconds}` JSON on stdin and returns `{"symbols": [{"name", "kind", "line", "end_line"}]}`. The MCP never accepts the adapter command from a caller.

When no adapter is configured, `lsp_symbols` falls back to a default backend for Python only (install the `lsp` extra: `python -m pip install -e ".[lsp]"`), backed by `multilspy`. This default does not run on Windows — a live test hung for several minutes even with a 30-second timeout, while the identical scenario on Linux completed correctly in under 2 seconds — set `ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS=1` to try it there anyway. Other languages multilspy supports (Rust, Java, Kotlin, Go, JS/TS, Ruby, C#, Dart) are not yet enabled by default; each needs external language-server availability verified before it can be trusted as a silent default. `engineeringos://capabilities` reports `structural_symbol_default` per language so this is never mistaken for broader support than it has.

For stronger structural indexing, install the optional parser set with `python -m pip install -e ".[parsing]"`. The indexer records which backend it used in its evidence (`python-ast`, `tree-sitter`, `tree-sitter (language-pack)`, or `regex-fallback`). If a grammar is unavailable, it safely falls back to Python AST or language-aware regex extraction rather than failing the repository scan. Indexing recognizes Python, JavaScript/JSX, TypeScript/TSX, Go, Rust, Java, Kotlin, Ruby, PHP, C, C++, C#, Swift, Scala, Lua, shell, Dart, and Elixir; `parsing` covers the 12 hand-tuned languages with native symbol-kind mappings (all but Kotlin, Lua, shell, and Dart).

Install the additional `python -m pip install -e ".[parsing-pack]"` extra to enable real structural parsing for Kotlin, Lua, shell, and Dart too, backed by `tree-sitter-language-pack`. This backend never fetches a grammar over the network from inside a tool call — it only uses one already cached locally — so it needs a one-time, explicit prefetch before it activates for a given language:

```powershell
.venv\Scripts\python -c "import tree_sitter_language_pack as t; t.prefetch(['kotlin', 'lua', 'bash', 'dart'])"
```

Elixir intentionally stays on the regex fallback: its grammar has no distinct node types for a function definition versus an ordinary call, so a naive mapping would misreport call sites as definitions.

Use `language_profile` before deeper analysis on a mixed repository. It reports source and test counts, indexed bytes, the actual parser backend selected for each detected language, and recognized build/dependency manifests without running project code.

Indexing limits individual source files to 2 MB and defaults to 100,000 source files per repository. Set `ENGINEERINGOS_MAX_INDEX_FILES` to a deliberate higher or lower bound. Deleted files are removed from the SQLite symbol and edge map during the next index pass.
For read-only tenant mounts, `ENGINEERINGOS_INDEX_ROOT` stores each repository map in a path-keyed directory outside the checkout. The production entrypoint requires this setting.

## Source-free hosted code maps

Run `index_code`, then use `export_code_map` or `engineeringos-map export <repo> <map.json>` inside the customer's environment. Export fails when the local index is stale. The v1 map contains only normalized relative paths, language labels, SHA-256 file hashes, symbol locations, and call/reference edges—never raw source text. `ingest_code_map` validates the complete strict schema and fingerprint before transactionally replacing a tenant/project map; `map_find_symbol` and `map_dependency_graph` query that hosted metadata without a checkout. `map_status` compares the hosted fingerprint with a local export so synchronization drift is explicit. Map storage uses `ENGINEERINGOS_MAP_ROOT`, falling back to the required external `ENGINEERINGOS_INDEX_ROOT`, and is partitioned by authenticated tenant plus project ID.

Repository-wide evidence tools stop after 100,000 candidate files by default; set `ENGINEERINGOS_MAX_SCAN_FILES` deliberately when handling a larger repository. Production numeric limits are range-checked by both startup and `engineeringos-preflight`, and `/readyz` returns HTTP 503 if required runtime storage or sandbox-worker readiness is lost.
