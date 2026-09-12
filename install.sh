#!/usr/bin/env bash
# EngineeringOS MCP installer for macOS/Linux/Git-Bash.
# Source (inspect before running): https://github.com/kl987456/engineeringos-mcp/blob/master/install.sh
# All this does: check for Python, then `pip install` this repo. Nothing else.
set -euo pipefail

PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PYTHON="$candidate"
    break
  fi
done

if [ -z "$PYTHON" ]; then
  echo "Python 3.12+ is required but was not found on PATH. Install it first." >&2
  exit 1
fi

echo "Installing EngineeringOS MCP from GitHub..."
"$PYTHON" -m pip install "git+https://github.com/kl987456/engineeringos-mcp.git"

echo ""
echo "Installed. Try it:"
echo "  engineeringos-mcp            # run the local MCP server (stdio)"
echo "  engineeringos-dashboard      # local audit dashboard at http://127.0.0.1:8765"
echo "  engineeringos-preflight      # check production config without printing secrets"
echo ""
echo "If those commands aren't found, pip installed them to a directory that isn't"
echo "on PATH yet (pip prints a warning naming the directory when this happens)."
echo ""
echo "Add it to Claude Code globally, so it works in every project:"
echo "  claude mcp add engineeringos -s user -- engineeringos-mcp"
