#!/usr/bin/env python
"""Convert an evaluation report from reports/1.0 to reports/2.0.

PR-16 (V6-05, ADR-013) migration helper. Reads a reports/1.0 JSON
document and emits a reports/2.0 JSON document by remapping the seven-
state v5.x status vocabulary into the five-state Scorecard-v6-aligned
vocabulary.

See docs/reports-contract-v2.0.md for the full mapping table and the
deprecation timeline.

Usage:

    python scripts/migrate-1.0-to-2.0.py --input old.json --output new.json

Exit codes:
    0  Migration successful.
    1  Input parse error.
    2  Usage / IO error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Importing from src/ requires the package to be installed; the helper is
# intentionally standalone so adopters can run it without installing the kit.
_STATUS_MAP: dict[str, tuple[str, str | None]] = {
    "pass": ("PASS", None),
    "fail": ("FAIL", None),
    "degraded": ("FAIL", None),
    "manual-review-required": ("UNKNOWN", "manual-review-required"),
    "not-applicable": ("NOT_APPLICABLE", None),
    "skipped": ("UNKNOWN", "skipped-by-flag"),
    "error": ("UNKNOWN", "evaluator-error"),
    "attested": ("ATTESTED", None),
}


def _map_status(status: str) -> tuple[str, str | None]:
    key = status.strip().lower()
    if key in _STATUS_MAP:
        return _STATUS_MAP[key]
    return ("UNKNOWN", "unmapped-source-status")


def _convert(doc: dict) -> dict:
    out = dict(doc)
    # Replace top-level schema_version.
    out["schema_version"] = (
        "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"
    )
    out["contract_version"] = "reports/2.0"
    # Remap per-control status.
    controls = doc.get("controls")
    if isinstance(controls, list):
        new_controls = []
        for c in controls:
            if not isinstance(c, dict):
                new_controls.append(c)
                continue
            mapped = dict(c)
            status = c.get("status")
            if isinstance(status, str):
                state, reason = _map_status(status)
                mapped["state"] = state
                if reason is not None:
                    mapped["reason"] = reason
                if status == "degraded":
                    mapped["degraded"] = True
            new_controls.append(mapped)
        out["controls"] = new_controls
    # Remap summary_by_status if present.
    summary = doc.get("summary_by_status")
    if isinstance(summary, dict):
        new_summary: dict[str, int] = {}
        for k, v in summary.items():
            if not isinstance(v, int):
                continue
            state, _ = _map_status(k)
            new_summary[state] = new_summary.get(state, 0) + v
        out["summary_by_status"] = new_summary
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="reports/1.0 JSON document.")
    parser.add_argument("--output", type=Path, required=True, help="Path to write reports/2.0 JSON.")
    args = parser.parse_args(argv)

    try:
        text = args.input.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[migrate-1.0-to-2.0] cannot read --input: {exc}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"[migrate-1.0-to-2.0] --input is not valid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(doc, dict):
        print("[migrate-1.0-to-2.0] --input top-level must be a JSON object.", file=sys.stderr)
        return 1

    out = _convert(doc)
    try:
        args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"[migrate-1.0-to-2.0] cannot write --output: {exc}", file=sys.stderr)
        return 2
    print(f"[migrate-1.0-to-2.0] wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
