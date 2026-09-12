# Third-party notices

EngineeringOS depends on the following permissively licensed projects:

- Model Context Protocol Python SDK (`mcp`), MIT License.
- PyYAML, MIT License.
- PyJWT, MIT License.
- pytest, MIT License.
- Tree-sitter and the optional per-language `tree-sitter-<lang>` grammar packages (`parsing` extra), MIT License.
- `tree-sitter-language-pack` (`parsing-pack` extra), MIT License.

The exact resolved versions are recorded by the deployment environment's lock file or image build. Review upstream licenses before commercial distribution.

## Operator-installed tools this MCP shells out to (not bundled or distributed)

These are never vendored, downloaded, or installed by EngineeringOS itself — an operator installs each one independently as a standalone tool, and EngineeringOS only detects and invokes it if present. Review each project's own license and terms directly if you rely on it:

- `sem` (Apache-2.0) — semantic change-impact analysis.
- Semgrep (LGPL 2.1 core / rules under the Semgrep Rules License) — SAST.
- Gitleaks (MIT) — secret detection.
- OSV-Scanner (Apache-2.0) — dependency vulnerability scanning against the public osv.dev database.
- Cisco `mcp-scanner` or Snyk `agent-scan`/legacy `mcp-scan` (see each project's own license) — MCP-specific security scanning of this server itself.
