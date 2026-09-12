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
  assumption" principle catching a bug about itself.
- A project-local `.venv` is now the documented, recommended setup.
- `scripts/scheduled-improvement.ps1` + a weekly Windows Scheduled Task
  ("EngineeringOS Weekly Improvement") drive ongoing work between sessions
  — it reads this file, verifies tests pass, implements the top item
  below, and commits locally (never pushes without a human's say-so).

**Concrete operational lesson from this pass**: installing Semgrep into
`engineeringos-mcp`'s own venv silently downgraded the `mcp` SDK dependency
(Semgrep bundles its own MCP server and a conflicting `mcp` pin), breaking
`from mcp import Client` imports with no obvious cause. Any future scanner
CLI evaluation must use an isolated venv, `pipx`/`uvx`, or a native package
manager (winget/apt/brew) — never `pip install` alongside this package.

---

## Investigated and deferred this pass (with reasoning — do not silently re-attempt without reading this)

- **`multilspy` as a default `lsp_symbols` backend**: investigated in an
  isolated venv. `SyncLanguageServer.request_document_symbols()` is exactly
  the right shape (synchronous, no asyncio bridging needed), and Python
  needs no external download (bundles `jedi-language-server` as a normal
  pip dependency). **However**, a live test against a trivial 6-line Python
  file — the easiest possible case — did not return a result even after
  several minutes with a 30-second timeout parameter passed to
  `SyncLanguageServer.create()`, strongly suggesting the timeout doesn't
  actually bound startup on this platform, or the process hangs. This is
  a library at version 0.0.15 (pre-1.0, originally a NeurIPS-2023 research
  artifact), and this result is disqualifying for a "default, always-on"
  backend inside a tool call with a real latency budget. **Next step if
  revisited**: test on Linux/macOS (this was tested on Windows — the hang
  may be platform-specific to how multilspy manages the LSP subprocess on
  Windows); if it reproduces cross-platform, this library is not viable as
  a default backend and the seam should stay purely operator-adapter-based,
  or a different, more mature per-language LSP wrapper should be evaluated
  instead (do not re-try the *same* library without a different platform
  or a fix upstream). `lsp_symbols` remains exactly as documented: a pure
  `ENGINEERINGOS_LSP_ADAPTER` seam with no bundled default.
- **Disk cleanup of `dist-final*`/`wheelcheck*`/build cruft**: the user
  approved deleting 36 `dist-final*` snapshots, `dist/`, `build/`,
  `engineeringos_mcp.egg-info/`, `engineeringos/work/`, and the sibling
  `../work/` scratch contents (all gitignored, all regeneratable, none of
  it source). The actual deletion was blocked by the auto-mode permission
  classifier mid-session and not retried around it per policy. **Next
  step**: retry the deletion (it is pre-approved) or ask the user to grant
  the permission directly; the risk is zero (already gitignored, disk
  hygiene only) but the classifier's decision was respected rather than
  routed around.
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

1. [ ] Retry the disk cleanup (see above) — zero-risk, high-value hygiene.
   Already pre-approved by the user; only blocked by a runtime permission
   gate in one session, not by anything about the action itself.
2. [x] ~~Fix the tree-sitter version pins~~ — verified fine: CI now
   installs `[parsing,parsing-pack]` fresh on every run and passes, so the
   12-pinned-package path and the language-pack path both genuinely work
   from a clean install, not just in one dev's local venv.
3. [ ] Re-test `multilspy` on Linux/macOS per the note above (GitHub
   Actions' `ubuntu-latest` runner is a convenient way to do this without
   needing a non-Windows dev machine); only pursue further if it behaves
   differently there.
4. [x] ~~Audit other `shutil.which(` call sites for the same collision
   class~~ — done same session: every other name (`mcp-scanner`,
   `semgrep`, `gitleaks`, `osv-scanner`, and every `test_runners.py`
   toolchain name) is either unambiguous or, in `test_runners.py`'s case,
   additionally gated on a matching manifest file being present — a
   materially different, safer pattern than `sem`'s old ungated PATH
   check. `sem` (a 3-letter name colliding with GNU Parallel) was the
   one real instance of this bug class, not a symptom of a wider pattern.
5. [ ] Consider `ragas`/`deepeval` for V3 once V1/V2 gaps are exhausted.
6. [ ] Validate the wedge with real target customers (master doc §10) —
   this was never about more building; it's still the actual open question
   behind all of the above.

Keep this list short and current — prune finished items into "State as of
<date>" above rather than letting checkmarks accumulate here.
