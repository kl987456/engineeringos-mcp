# Runs one unattended EngineeringOS improvement pass. Invoked weekly by a
# Windows Scheduled Task ("EngineeringOS Weekly Improvement") created via
# schtasks.exe; see ROADMAP.md for what each run is expected to do.
#
# Safe to run manually too: `powershell -File scripts\scheduled-improvement.ps1`

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$logDir = Join-Path $root "scheduled-logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$logFile = Join-Path $logDir "improvement-$timestamp.log"

$prompt = @'
This is an unattended, scheduled maintenance pass on the EngineeringOS MCP
project. Nobody is watching this run interactively, so be conservative and
never do anything destructive or irreversible.

1. Read ROADMAP.md in full for current state and the "Suggested next
   increment" list.
2. Run `.venv\Scripts\python -m pytest -q` first. If the suite does not
   pass, STOP immediately and write a new "Needs human input" section at
   the top of ROADMAP.md describing exactly what failed. Do not attempt to
   fix a failing baseline yourself in this unattended run — that needs a
   human's judgment call. Do not proceed further in that case.
3. If the suite passes, pick the single highest-value unchecked item from
   ROADMAP.md's "Suggested next increment" list and implement it. Prefer
   small, well-scoped, test-covered changes over large ones. If the top
   item requires a decision only a human can make (e.g. it says so
   explicitly, or you discover it does while working), skip it, note why
   in ROADMAP.md's "Needs human input" section, and move to the next item
   instead — do not guess on a genuine judgment call.
4. Re-run `.venv\Scripts\python -m pytest -q`,
   `.venv\Scripts\python -m engineeringos.evaluations sample-repo`, and
   `.venv\Scripts\python -m compileall -q engineeringos`. All three must
   pass before you commit anything.
5. Update ROADMAP.md: move the finished item into a new dated entry under
   "State as of <today's date>", and refresh the "Suggested next
   increment" list to reflect what's left.
6. Commit the change locally with `git` using a clear, conventional commit
   message. Do NOT push to the `origin` remote or any other remote without
   a human's explicit say-so, even though one is configured — leave that
   decision to whoever reviews this run.
   Do NOT force-push, rewrite history, or run any destructive git command.
   Do NOT delete any file outside this project directory. If you are ever
   unsure whether an action is safe, don't take it — note the question in
   ROADMAP.md instead and stop.
7. End with a short plain-text summary of what you did (or why you
   stopped) as your final message.
'@

claude -p $prompt --permission-mode auto 2>&1 | Tee-Object -FilePath $logFile
