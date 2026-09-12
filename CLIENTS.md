# Connect EngineeringOS to AI coding clients

These examples use the local stdio server. Install the project first (include the parser extra for native polyglot indexing):

```powershell
python -m pip install ".[parsing]"
```

The shared configuration in `examples/mcp-stdio.json` starts `python -m engineeringos.server`. It contains no credentials and performs no deployment.

## Claude Code

From this repository, add the checked-in configuration and verify it:

```powershell
claude mcp add-json engineeringos '{"type":"stdio","command":"python","args":["-m","engineeringos.server"]}'
claude mcp get engineeringos
```

Alternatively, pass `examples/mcp-stdio.json` with Claude Code's `--mcp-config` option for a one-session configuration.

## Codex

Codex provides an MCP management command, so no settings file needs to be edited manually:

```powershell
codex mcp add engineeringos -- python -m engineeringos.server
codex mcp get engineeringos
```

## Cursor

Copy `examples/mcp-stdio.json` to `.cursor/mcp.json` for project-only use, or to the global Cursor MCP configuration location for use across projects. Keep tool approval enabled; EngineeringOS also independently enforces its approval-required permission tiers.

## Gemini CLI

Merge the `mcpServers.engineeringos` object from `examples/mcp-stdio.json` into Gemini's `settings.json`. Keep `trust` absent or set it to `false` so tool confirmations remain enabled.

## Team workflow

Claude, Codex, Cursor, and Gemini can all use the same evidence contract, but the MCP does not silently pass private conversations between models. For a two-agent review, give one agent the investigation task and ask the second agent to independently verify the returned evidence, then compare cited evidence IDs before accepting a conclusion. Both agents should use `investigation_plan`, and neither should fill `claim` when required evidence is incomplete.

Suggested split:

1. Investigator: run `repo_overview`, `recent_changes`, `search_code`, `search_logs`, and `run_tests` or `investigate`.
2. Verifier: check `index_code`, `find_symbol`, `dependency_graph`, `diagnostics`, `security_scan`, and `analyze_change` independently.
3. Reconcile only conclusions supported by evidence returned by the MCP; keep disagreements visible.

For privacy-sensitive repositories, run `index_code` and `export_code_map` locally, ingest the exported map, and have the verifier use `map_find_symbol` and `map_dependency_graph`. Those hosted queries do not require raw source files.
