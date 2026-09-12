# EngineeringOS MCP installer for Windows PowerShell.
# Source (inspect before running): https://github.com/kl987456/engineeringos-mcp/blob/master/install.ps1
# All this does: check for Python, then `pip install` this repo. Nothing else.

$ErrorActionPreference = "Stop"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error "Python 3.12+ is required but was not found on PATH. Install it from https://python.org first."
    exit 1
}

Write-Host "Installing EngineeringOS MCP from GitHub..." -ForegroundColor Cyan
python -m pip install "git+https://github.com/kl987456/engineeringos-mcp.git"

Write-Host ""
Write-Host "Installed. Try it:" -ForegroundColor Green
Write-Host "  engineeringos-mcp            # run the local MCP server (stdio)"
Write-Host "  engineeringos-dashboard      # local audit dashboard at http://127.0.0.1:8765"
Write-Host "  engineeringos-preflight      # check production config without printing secrets"
Write-Host ""
Write-Host "If those commands aren't found, pip installed them to a Scripts folder that" -ForegroundColor Yellow
Write-Host "isn't on PATH yet (pip prints a warning naming the folder when this happens)." -ForegroundColor Yellow
Write-Host ""
Write-Host "Add it to Claude Code globally, so it works in every project:"
Write-Host "  claude mcp add engineeringos -s user -- engineeringos-mcp"
