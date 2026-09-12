"""Operator CLI for source-free code-map interchange."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import tenant_context
from .code_maps import export_code_map, ingest_code_map


def main() -> int:
    parser = argparse.ArgumentParser(description="Export or import an EngineeringOS source-free code map")
    commands = parser.add_subparsers(dest="command", required=True)
    export_parser = commands.add_parser("export")
    export_parser.add_argument("repo_path")
    export_parser.add_argument("output")
    import_parser = commands.add_parser("import")
    import_parser.add_argument("project_id")
    import_parser.add_argument("input")
    import_parser.add_argument("--tenant", default="local")
    args = parser.parse_args()
    if args.command == "export":
        target = Path(args.output).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(export_code_map(args.repo_path), separators=(",", ":")), encoding="utf-8")
        temporary.replace(target)
        print(json.dumps({"status": "exported", "output": str(target)}))
        return 0
    payload = json.loads(Path(args.input).expanduser().resolve().read_text(encoding="utf-8"))
    with tenant_context(args.tenant):
        evidence = ingest_code_map(args.project_id, payload)
    print(json.dumps({"status": "imported", "evidence": [item.to_dict() for item in evidence]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
