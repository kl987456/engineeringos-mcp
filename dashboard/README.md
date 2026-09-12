# Local dashboard

The dashboard is intentionally local-only and reads the MCP's append-only JSONL audit log.

```powershell
$env:ENGINEERINGOS_AUDIT_LOG = (Resolve-Path "..\work\audit.jsonl").Path
python -m dashboard.server
```

Open `http://127.0.0.1:8765`. It shows service state, total calls, success rate, errors, tenant activity, tool volume, security/worker signals, and the recent audit trail. The UI refreshes every ten seconds and does not send audit data anywhere. Diagnostic failures and rate-limit errors appear in the audit trail when emitted by the MCP process.

In authenticated HTTP mode, tenant activity is attributed from the validated tenant claim through request-local context; raw access tokens and token claims are never written to dashboard audit records.
