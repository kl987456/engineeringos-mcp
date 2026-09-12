# The EngineeringOS Verdict

Evidence-first assessment — not a marketing verdict. Assessed 2026-09-12 against `engineeringos-mcp` v0.4.0, live at https://engineeringos-mcp.onrender.com. Reached the same way the tool itself is supposed to work: gather real evidence first, form a claim only once the evidence earns it.

## Is this a good product to solve a real developer problem?

**Claim:** Yes — for giving an AI agent real evidence instead of a guess. Not yet — as a platform anyone can safely point at untrusted code.

**Confidence:** HIGH on engineering · UNKNOWN on market fit.

## At a glance

| Metric | Result |
|---|---|
| Tools exercised over the real MCP wire protocol | 27/27 |
| Real bugs found this session, all fixed & verified | 5 |
| Automated tests, passing on every commit | 77 |
| Languages with real structural parsing | 18+ |

## What "testing it" actually meant

Not a smoke test. A second, independent process spoke real JSON-RPC to the server over stdio — `initialize`, list tools, call each one — the same conversation any MCP client has with it. The live Render deployment was then hit directly over HTTPS (`/healthz`, `/readyz`).

### Bugs found and fixed this pass

1. **`vulnerability_scan` misread "nothing to report" as a crash.** OSV-Scanner returns `"results": null` — a JSON null, not an empty list — when a repo has zero dependency manifests. `dict.get(key, [])`'s default only applies when the key is *absent*, not present-but-null. Found via the live protocol test, fixed in `db6ca8a`, re-verified against the real binary.
2. **The local dashboard silently broke itself on every load.** A dead reference to a renamed DOM element (`$("tenants")`) threw on every render, silently caught by `refresh()`'s try/catch, and mislabeled the whole page "Dashboard offline" while the top stat tiles still looked fine. Found by actually opening it in a browser, fixed in `d81c011`.
3. **A tool name collided with a Linux system command.** Auto-detecting the optional `sem` semantic-analysis CLI via a PATH lookup silently matched GNU Parallel's unrelated `sem` command on GitHub's own Ubuntu runners — invisible on Windows, invisible locally. Caught only because real CI ran on a genuinely different machine; fixed by requiring `ENGINEERINGOS_SEM_BIN` explicitly everywhere instead of guessing via PATH.
4. **The container had nowhere writable to put a tenant's index.** The non-root container user can't create top-level directories at runtime, and the server deliberately refuses to auto-create a tenant root by design. Found deploying for real (not in a test `docker run`), fixed at the Dockerfile level in `5974d42` so it holds for any hosting target.
5. **"Auto-deploy" wasn't actually deploying.** Four commits sat un-deployed for over an hour because the host's git connection method ("Public Git Repository") doesn't register a push webhook the way its settings imply. Caught by checking the live commit hash against `git log`, not by trusting a dashboard label. Repaired manually for now; a permanent CI-triggered fix is drafted in `ROADMAP.md`, pending a secret only a human should set.

Every other tool call behaved exactly as documented: real git history and diffs, a real planted production-log error surfaced by `search_logs`, a real secret caught by Gitleaks, real CVEs found on a deliberately vulnerable dependency, and a real source-free code map exported with no raw source inside it. Where a scanner wasn't configured, it said so plainly instead of pretending.

## Who it's actually for, today

**Ready now**
- **You, on your own machine.** One install command, works in every project, never fabricates a root cause.
- **A trusted team's shared instance.** Deployed and live today, on a $0 host, with that scope explicitly documented.
- **Polyglot codebases.** Real parsing across 18+ languages, not just a Python demo.

**Not ready yet**
- **Untrusted or public users.** No real sandbox exists; every write-capable tool is deliberately unbuilt.
- **"Set it and forget it" hosting.** The free tier sleeps, storage is ephemeral, and nobody has finished the auth handshake for a real client yet.
- **A validated business.** Zero real target-customer conversations have happened. That was true before this pass and is true after it.

## Verdict

**A well-built evidence engine, not yet a finished product** — and those are different, fixable, honestly-labeled gaps.

The engineering held up under real, adversarial-ish use: every bug found this session was found by actually running the thing — over the wire protocol, in a browser, on someone else's Linux runner, in a real container — and every one got fixed and re-verified, not just patched and hoped for. That's the strongest signal a tool this young can give. What it can't give yet is proof anyone besides its own builder wants it; that answer only comes from the customer conversations `ROADMAP.md` still lists as the actual open question behind everything else.

*Assessed the way the tool itself insists on: evidence retained, claim kept separate.*
