"""Deterministic golden scenarios for regression-testing the evidence layer."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .workflows.investigate import investigate


def run_golden(repo_path: str) -> dict:
    repo = Path(repo_path).resolve()
    result = investigate(
        "Why did legacy checkout requests fail?",
        str(repo),
        search_query="payment_method",
        log_path=str(repo / "logs" / "production.log"),
        log_query="cust_legacy_9",
        since="365d",
    )
    evidence = result.get("evidence", [])
    types = {item.get("type") for item in evidence}
    required = {"code_search", "log", "test_result"}
    missing = sorted(required - types)
    checks = {
        "evidence_types_present": not missing,
        "claim_is_unset": result.get("claim") is None and result.get("confidence") == "UNKNOWN",
        "no_fabricated_root_cause": all("root cause" not in str(item).lower() for item in evidence),
    }
    return {"scenario": "legacy-checkout-regression", "passed": all(checks.values()), "checks": checks, "missing": missing, "evidence_count": len(evidence), "incomplete": result.get("incomplete", [])}


def main() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[1] / "sample-repo")
    result = run_golden(repo)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
