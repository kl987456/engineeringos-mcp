# EngineeringOS roadmap and gap list

This file is the durable source of truth for "what's done, what's next, and
what was deliberately deferred and why." It supersedes relying on the
external Master Build Doc (`../work/files_inspected/EngineeringOS-MASTER-BUILD-DOC.md`),
which was accurate when written but is a static snapshot outside this git
repository and will drift. Update this file, not that one, as work lands.

A session picking this up cold — including the recurring scheduled task —
should be able to read this file alone and know exactly what to do next.
Keep entries honest: a claim here that isn't backed by a passing test or a
verified manual check is worse than no claim at all, per this project's own
"evidence before conclusions" principle.

**Before making any change**: run `python -m pytest -q` from a project-local
`.venv` (see README) and confirm the current baseline passes. After any
change: re-run the full suite, `python -m engineeringos.evaluations
sample-repo`, and `python -m compileall -q engineeringos` before committing.
Commit in small, logical steps — this repo's git history starts 2026-09-12
and should stay legible.

**Live deployment**: `https://engineeringos-mcp.onrender.com` (Render free
tier, `engineeringos-mcp` project, trusted-team scope — see the dedicated
section below before touching its configuration).

---

## State as of 2026-09-12

Starting point: a mature server (24 tools, real OIDC auth, tenant isolation,
rate limiting, audit dashboard, source-free hosted code maps, 58 passing
tests) with no git history and several honest, disclosed gaps. This pass
added:

- **`tree-sitter-language-pack` backend** (`engineeringos/indexer.py`) —
  real structural parsing for Kotlin, Lua, shell, and Dart, additive to the
  existing 12-language pinned-package path. Never fetches a grammar over
  the network from inside a tool call (checks `downloaded_languages()`
  first); requires an operator prefetch, documented in README/SECURITY.md.
  Elixir deliberately excluded — see "Deferred" below.
- **`git_diff` tool registration** — it was implemented, tested, and tiered
  in `permissions.yaml`, but never registered as a callable `@app.tool` in
  either `server.py` or `production.py`. Fixed, plus a new regression test
  (`test_tool_registration_stays_in_sync_across_server_production_and_permissions`)
  that asserts permissions.yaml, `server.py`, and `production.py` all agree
  on the tool set — this class of drift should not recur silently.
- **`security_tools.scan_server` fixed for Cisco's `mcp-scanner`** — its
  real CLI (`mcp-scanner behavioral <path> --format raw`) differs from the
  `<binary> <path> --json` shape the code assumed. Legacy mcp-scan/agent-scan
  shape kept as the fallback for unrecognized binaries.
- **`code_security_scan`** (new tool) — Semgrep (SAST) + Gitleaks (secrets)
  against the target repo, honest per-scanner fallback, verified against
  real binaries with a planted secret.
- **`vulnerability_scan`** (new tool) — OSV-Scanner (SCA) against detected
  manifests, verified against a real known-vulnerable dependency (lodash
  4.17.15, 10 real advisories returned from a live osv.dev query).
- Fixed an undeclared `httpx` test dependency (only surfaced by testing in
  a clean venv instead of the pre-existing, polluted global Python install
  — a good reminder to always verify in an isolated environment).
- Local git repository initialized (this was previously untracked entirely),
  then pushed to a new public GitHub repo at the user's request:
  https://github.com/kl987456/engineeringos-mcp. `.github/workflows/ci.yml`
  now runs for real on every push — it never had before.
- **Real CI immediately paid for itself**: the first run failed on the
  `httpx` gap above (this venv's `[test]` extra wasn't in the CI install
  step); the second run then failed two tests only on GitHub's Ubuntu
  runner, never locally on Windows — `shutil.which("sem")` was resolving
  to GNU Parallel's unrelated `sem` (semaphore) command, which ships on
  those runners, making the code believe a real semantic-impact tool was
  installed when it wasn't. Fixed by requiring the already-documented
  `ENGINEERINGOS_SEM_BIN` explicitly everywhere (`impact_tools.py`,
  `server.py`, `preflight.py`) instead of also guessing via PATH. CI is
  green as of the `Fix sem PATH-collision bug...` commit. This is exactly
  why "keep on improving" needs real CI, not just local testing — noted
  here because it's a good example of the project's own "evidence over
  assumption" principle catching a bug about itself. Audited every other
  `shutil.which(` call site for the same collision class while fixing
  this: all other names (`mcp-scanner`, `semgrep`, `gitleaks`,
  `osv-scanner`, every `test_runners.py` toolchain name) are either
  unambiguous or additionally gated on a matching manifest file being
  present in the target repo — `sem` (a 3-letter name colliding with GNU
  Parallel) was the one real instance of this bug, not a wider pattern.
- The `parsing`/`parsing-pack` version pins are confirmed fine on a
  genuinely clean install, not just this one dev's venv: CI installs both
  extras fresh on every run and passes (base `tree-sitter` resolves to
  0.26.0 against the `>=0.25.2,<0.27` pin, all 12 pinned languages parse
  correctly, kotlin/lua/bash/dart resolve via the language-pack prefetch
  step).
- A project-local `.venv` is now the documented, recommended setup.
- `scripts/scheduled-improvement.ps1` + a weekly Windows Scheduled Task
  ("EngineeringOS Weekly Improvement") drive ongoing work between sessions
  — it reads this file, verifies tests pass, implements the top item
  below, and commits locally (never pushes without a human's say-so). Its
  settings were also loosened (`DisallowStartIfOnBatteries`/
  `StopIfGoingOnBatteries` off, `StartWhenAvailable` on) so it doesn't
  silently skip a week if the machine is on battery or was off/logged out
  at the scheduled time; it still requires an interactive logon
  (`LogonType: Interactive`) to actually fire.
- Disk cleanup done: the 36 `dist-final*` snapshots, `dist/`, `build/`,
  `engineeringos_mcp.egg-info/`, `engineeringos/work/`, and the sibling
  `../work/` scratch contents are gone. All of it was already gitignored
  and regeneratable, so this made no git-tracked change — confirmed via
  `git status --short` returning empty and the full suite still passing
  afterward.
- **`multilspy` re-tested on Linux via a manual GitHub Actions workflow
  (`.github/workflows/multilspy-experiment.yml`) — it was Windows-specific
  after all.** The identical trivial-Python-file scenario that hung for
  several minutes on Windows completed correctly in under 2 seconds on
  `ubuntu-latest`, with the exact expected symbols. Given that, actually
  implemented the default `lsp_symbols` backend
  (`engineeringos/tools/lsp_default.py`): Python only for now (the one
  language verified end-to-end and the only one multilspy doesn't need an
  external language-server download for), disabled by default on Windows
  specifically pending a root-cause fix
  (`ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS=1` overrides this), with the
  same path/symbol-count/name-length caps as the operator-adapter path.
  `capabilities()`/`preflight.py` report per-language availability
  honestly rather than a single blanket flag. This project's own
  production Docker deployment (see `Dockerfile`) is Linux-based, so the
  Windows restriction mainly affects local dev on Windows, not hosted use.

**Concrete operational lesson from this pass**: installing Semgrep into
`engineeringos-mcp`'s own venv silently downgraded the `mcp` SDK dependency
(Semgrep bundles its own MCP server and a conflicting `mcp` pin), breaking
`from mcp import Client` imports with no obvious cause. Any future scanner
CLI evaluation must use an isolated venv, `pipx`/`uvx`, or a native package
manager (winget/apt/brew) — never `pip install` alongside this package.

---

## Live deployment (Render, trusted-team scope)

Deployed at the user's request to actually try the production HTTP mode,
scoped explicitly to "just me / my team" (not public/untrusted users) —
this scope is why some choices below are safe here but would NOT be safe
for a customer-facing deployment.

- **Host**: Render free tier (`engineeringos-mcp` project, workspace
  `My Workspace`), auto-deploys from `master` on every push. Free tier
  sleeps after 15 minutes idle; first request after that takes 30-60s.
  No credit card on file — chosen specifically because GCP's billing
  account was closed and Oracle Cloud signup wasn't pursued once Render's
  no-card free tier was confirmed current for 2026.
- **Identity provider**: Auth0 free tier, tenant
  `dev-ebj62kxjy4a7t13e.us.auth0.com`, API identifier (audience)
  `https://engineeringos-api`. Nothing here yet issues real tokens for a
  client to call the deployed server with — this only satisfies the
  server's own startup requirement for a real issuer/audience. Wiring an
  actual MCP client (Claude Code, etc.) through this Auth0 tenant's OAuth
  flow is unfinished; whoever does this next should register a proper
  Application in this tenant for that client.
- **Sandbox worker deliberately disabled**
  (`ENGINEERINGOS_REQUIRE_SANDBOX_WORKER=0`) — an informed, scope-limited
  choice for trusted-team-only use, not an oversight. Do not carry this
  setting into any deployment that might run untrusted repos' tests.
- **Storage is ephemeral**: `ENGINEERINGOS_TENANT_ROOT=/data/tenants` and
  `ENGINEERINGOS_INDEX_ROOT=/data/indexes`, pre-created at Docker build
  time (see Dockerfile) since Render's free tier has no persistent disk
  and the non-root container user can't create top-level directories at
  runtime. Both directories are empty on every redeploy/restart — nothing
  currently populates `/data/tenants` with real tenant repo checkouts, so
  `repo_path`-based tools (`search_code`, `run_tests`, `investigate`, etc.)
  have nothing to operate on against this hosted instance today. The
  source-free code-map tools (`export_code_map` locally →
  `ingest_code_map`/`map_find_symbol`/`map_dependency_graph` against this
  host) are the one workflow that's actually usable end-to-end right now,
  and conveniently also the one this project's whole hosted-architecture
  story was built around.
- **Verified working**: `https://engineeringos-mcp.onrender.com/healthz`
  returns `{"status":"ok",...}`; `/readyz` returns
  `{"status":"ready","checks":{"index_storage":true,"map_storage":true,"sandbox_worker":true}}`
  — confirmed live, not just "deploy succeeded" in the dashboard.
- **Real bug found and fixed getting here**: Render's "Docker Command"
  override field does plain whitespace argv-splitting with no shell —
  `&&`, `sh -c "..."`, quoting, none of it works as a multi-step start
  command. Don't re-attempt a shell one-liner there; if a pre-start step
  is ever needed again, either bake it into the Dockerfile (what was done
  here) or use Render's "Pre-Deploy Command" (paid-plan-only on this
  account, unverified whether it supports real shell syntax).
- **Next steps if continuing this deployment**: decide on persistent
  storage (Render paid disk, or an external object store) before this is
  useful for more than the code-map workflow; finish the Auth0
  client/Application setup so an actual MCP client can authenticate
  against it; re-enable the sandbox worker requirement before ever
  pointing this at anyone else's code.

---

## Investigated and deferred this pass (with reasoning — do not silently re-attempt without reading this)

- **Real sandbox (E2B/Firecracker) for HIGH_RISK tools** — no HIGH_RISK or
  RESTRICTED_WRITE tool exists yet to need it; premature to commit to a
  paid vendor before any tool would use it.
- **RESTRICTED_WRITE/HIGH_RISK tools (`apply_patch`, `deploy`, V4)** — the
  original design doc calls this multi-year-horizon; still true.
- **ragas/deepeval (V3 RAG/LLM diagnostics)** — lower leverage than the
  gaps above; revisit once the LSP-backend question is actually resolved.
- **Elixir tree-sitter mapping** — its grammar has no distinct def/call
  node types (confirmed empirically: a bare function call and a `def` both
  parse as the same generic `call` node), so this needs callee-identifier
  filtering logic, not a naive node-kind map. Not attempted this pass.

---

## Suggested next increment (pick the top unchecked item; re-derive priority if project state has changed)

1. [ ] Decide on persistent storage for the live Render deployment (see
   "Live deployment" section above) — a paid Render disk, or an external
   store — the code-map workflow works today but everything ephemeral
   resets on every restart. This is a cost/vendor decision, not something
   to just implement.
2. [ ] Finish Auth0 client setup for the live deployment so a real MCP
   client can actually authenticate against it (see "Live deployment").
   Currently the server verifies tokens correctly but nothing mints one
   for a caller yet.
3. [ ] Root-cause the Windows multilspy hang, or accept it and move on —
   don't just re-try blindly. If revisited: instrument exactly where it
   blocks on Windows (subprocess pipe handling is the most likely
   suspect for a library whose CI is presumably Linux-first) rather than
   guessing again.
4. [ ] Verify and enable additional multilspy languages one at a time
   (Go and Rust are reasonable next candidates — both have a single,
   well-known, commonly-preinstalled language server binary — gopls and
   rust-analyzer respectively) — each needs its own "does it need a
   silent download, does it actually work" check like Python got, not a
   bulk enable.
5. [ ] Consider `ragas`/`deepeval` for V3 once V1/V2 gaps are exhausted.
6. [ ] Validate the wedge with real target customers (master doc §10) —
   this was never about more building; it's still the actual open question
   behind all of the above.

Completed items are folded into "State as of 2026-09-12" above rather
than kept here as struck-through history — see that section for the
tree-sitter-pin verification, the `shutil.which` collision audit, the
disk cleanup, and the multilspy default backend, all resolved this pass.

Keep this list short and current — prune finished items into "State as of
<date>" above rather than letting checkmarks accumulate here.
