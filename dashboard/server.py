"""Local-only dashboard server for EngineeringOS audit data."""
from __future__ import annotations
import json, os, threading
from collections import Counter, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
AUDIT = Path(os.environ.get("ENGINEERINGOS_AUDIT_LOG", str(ROOT / "sample-audit.jsonl"))).resolve()
MAX_EVENTS = 5000
MAX_AUDIT_LINE_BYTES = 64 * 1024

def events():
    if not AUDIT.exists(): return []
    result = deque(maxlen=MAX_EVENTS)
    with AUDIT.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if len(line.encode("utf-8", errors="replace")) > MAX_AUDIT_LINE_BYTES:
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict): result.append(event)
            except json.JSONDecodeError:
                continue
    return list(result)

def metrics():
    rows = events(); tools = Counter(row.get("tool", "unknown") for row in rows); statuses = Counter(row.get("status", "unknown") for row in rows); tenants = Counter(row.get("tenant", "unknown") for row in rows)
    security = [row for row in rows if row.get("tool") in {"security_scan", "auth", "authorization"} or row.get("status") == "security_error"]
    worker = [row for row in rows if "worker" in str(row.get("tool", "")) or "worker" in str(row.get("detail", "")).lower()]
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "audit_file": str(AUDIT), "total_calls": len(rows), "successes": statuses.get("success", 0), "errors": statuses.get("error", 0), "warnings": statuses.get("warning", 0), "success_rate": round(statuses.get("success", 0) / len(rows) * 100, 1) if rows else 100.0, "tools": tools, "tenants": tenants, "security_events": len(security), "worker_events": len(worker), "stale_indexes": statuses.get("index_stale", 0), "recent": rows[-40:][::-1]}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'")
        super().end_headers()
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/metrics":
            body = json.dumps(metrics(), default=dict).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        target = ROOT / ("index.html" if path in {"", "/"} else path.lstrip("/"))
        try: target = target.resolve(); target.relative_to(ROOT)
        except ValueError: self.send_error(404); return
        if not target.is_file(): self.send_error(404); return
        content_type = "text/html" if target.suffix == ".html" else "text/css" if target.suffix == ".css" else "text/javascript"
        body = target.read_bytes(); self.send_response(200); self.send_header("Content-Type", f"{content_type}; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

def serve(host="127.0.0.1", port=8765):
    server = ThreadingHTTPServer((host, port), Handler); print(f"EngineeringOS dashboard: http://{host}:{port}"); server.serve_forever()

def main():
    serve()

if __name__ == "__main__": main()
