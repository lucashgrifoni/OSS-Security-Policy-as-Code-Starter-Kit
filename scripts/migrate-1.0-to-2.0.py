#!/usr/bin/env python
"""Convert an evaluation report from reports/1.0 to reports/2.0.

PR-16 (V6-05, ADR-013) migration helper. Reads a reports/1.0 JSON document and
emits a reports/2.0 JSON document: it remaps the per-control status vocabulary
into the five-state Scorecard-v6-aligned vocabulary and reshapes the 1.0
``results`` array into the 2.0 ``controls`` array.

The mapping mirrors the engine's own ``report_to_dict_v2_0`` /
``REPORTS_V2_STATUS_MAP`` so this standalone helper produces a document
equivalent to the kit's native serialization. The kit's native output remains
the canonical reports/2.0 representation; this script exists so adopters who
only have a stored 1.0 JSON (and not the installed kit) can still convert it.

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
from typing import Any

_REPORTS_2_0_SCHEMA_URL = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"

# Mirror of oss_policy_kit.application.reporting.REPORTS_V2_STATUS_MAP. Kept inline so
# the helper stays standalone (runnable without installing the kit).
_STATUS_MAP: dict[str, tuple[str, str | None]] = {
    "pass": ("PASS", None),
    "fail": ("FAIL", None),
    "degraded": ("FAIL", None),
    "manual-review-required": ("UNKNOWN", "manual-review-required"),
    "not-applicable": ("NOT_APPLICABLE", None),
    "skipped": ("UNKNOWN", "skipped-by-flag"),
    "error": ("UNKNOWN", "evaluator-error"),
    "attested": ("ATTESTED", None),
    "waived": ("UNKNOWN", "waived"),
}


def _map_status(status: str) -> tuple[str, str | None]:
    key = status.strip().lower()
    if key in _STATUS_MAP:
        return _STATUS_MAP[key]
    return ("UNKNOWN", "unmapped-source-status")


def _convert_control(c: dict[str, Any]) -> dict[str, Any]:
    """Reshape a reports/1.0 ``results`` entry into a reports/2.0 ``controls`` entry."""

    control_id = c.get("control_id", "")
    state, reason = _map_status(str(c.get("status", "")))
    evidence = c.get("evidence")
    extra = c.get("extra")
    out: dict[str, Any] = {
        "id": control_id,
        "title": c.get("title", ""),
        "category": c.get("category"),
        "lifecycle": c.get("lifecycle"),
        "profile": c.get("profile"),
        "state": state,
        "assurance": c.get("assurance"),
        "confidence": c.get("confidence"),
        "weight": c.get("weight"),
        "message": c.get("reason", ""),
        "remediation": c.get("remediation", ""),
        "evidence": evidence if isinstance(evidence, dict) else {},
        "owner": c.get("owner"),
        "expires_at": c.get("expires_at"),
        "waiver": c.get("waiver"),
        "extra": extra if isinstance(extra, dict) else {},
        "finding_id": c.get("finding_id") or f"{control_id}@{c.get('profile', '')}",
    }
    if reason is not None:
        out["reason"] = reason
    if str(c.get("status", "")) == "degraded":
        out["degraded"] = True
    if c.get("deprecation_note") is not None:
        out["deprecation_note"] = c["deprecation_note"]
    return out


def _convert_summary(summary: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    if isinstance(summary, dict):
        for key, value in summary.items():
            if not isinstance(value, int):
                continue
            state, _ = _map_status(str(key))
            out[state] = out.get(state, 0) + value
    return dict(sorted(out.items()))


def _convert(doc: dict[str, Any]) -> dict[str, Any]:
    results = doc.get("results")
    controls = [_convert_control(c) for c in results if isinstance(c, dict)] if isinstance(results, list) else []
    out: dict[str, Any] = {
        "schema_version": _REPORTS_2_0_SCHEMA_URL,
        "contract_version": "reports/2.0",
        "generated_at": doc.get("generated_at", ""),
        "kit_version": doc.get("kit_version", ""),
        "target_path": doc.get("target_path", ""),
        "profile": doc.get("profile", {}),
        "summary_by_status": _convert_summary(doc.get("summary_by_status")),
        "controls_total": doc.get("controls_total", len(controls)),
        "controls": controls,
        "results_digest": doc.get("results_digest", ""),
        "operational_warnings": doc.get("operational_warnings", []),
        "scorecard": doc.get("scorecard", {}),
        "external_waiver_path": doc.get("external_waiver_path"),
        "action_insights": doc.get("action_insights", {}),
        "live_collection": doc.get("live_collection"),
        "weighted_score": doc.get("weighted_score"),
        "migration": {
            "from": "reports/1.0",
            "status_mapping": "docs/reports-contract-v2.0.md#mapping-from-reports10-to-reports20",
        },
        "extensions": {},
    }
    provenance = doc.get("evidence_provenance_version")
    if provenance is not None:
        out["evidence_provenance_version"] = provenance
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
    if not isinstance(doc.get("results"), list):
        print(
            "[migrate-1.0-to-2.0] --input has no 'results' array; is it a reports/1.0 document?",
            file=sys.stderr,
        )
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
