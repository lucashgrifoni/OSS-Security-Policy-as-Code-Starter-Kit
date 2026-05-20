"""reports/2.0 contract URL + status mapping (PR-16, V6-05, ADR-013)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import (
    REPORT_JSON_SCHEMA_URL_V1_0,
    REPORT_JSON_SCHEMA_URL_V2_0,
    evaluate_repository,
    map_status_to_reports_v2,
    report_json_schema_url,
)
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict
from oss_policy_kit.domain.errors import LoadError

# --- URL constants + resolver ----------------------------------------------


def test_v2_url_distinct_from_v1() -> None:
    assert REPORT_JSON_SCHEMA_URL_V2_0 != REPORT_JSON_SCHEMA_URL_V1_0
    assert REPORT_JSON_SCHEMA_URL_V2_0.endswith("/reports/2.0")


def test_resolver_accepts_2_0() -> None:
    assert report_json_schema_url("2.0") == REPORT_JSON_SCHEMA_URL_V2_0


def test_resolver_default_remains_1_0() -> None:
    """Default contract stays at 1.0 in this PR to avoid breaking snapshot tests.
    The default-switch to 2.0 is deferred to PR-18 (release prep) or a v6.x point release."""
    assert report_json_schema_url("") == REPORT_JSON_SCHEMA_URL_V1_0


def test_resolver_unknown_mentions_2_0_in_error() -> None:
    with pytest.raises(LoadError, match=r"2\.0"):
        report_json_schema_url("9.9")


# --- Status mapping --------------------------------------------------------


@pytest.mark.parametrize(
    "v1_status,expected_state,expected_reason",
    [
        ("pass", "PASS", None),
        ("fail", "FAIL", None),
        ("degraded", "FAIL", None),
        ("manual-review-required", "UNKNOWN", "manual-review-required"),
        ("not-applicable", "NOT_APPLICABLE", None),
        ("skipped", "UNKNOWN", "skipped-by-flag"),
        ("error", "UNKNOWN", "evaluator-error"),
        ("attested", "ATTESTED", None),
    ],
)
def test_status_mapping_matches_adr_table(v1_status: str, expected_state: str, expected_reason: str | None) -> None:
    state, reason = map_status_to_reports_v2(v1_status)
    assert state == expected_state
    assert reason == expected_reason


def test_status_mapping_handles_unknown_value() -> None:
    state, reason = map_status_to_reports_v2("brand-new-status")
    assert state == "UNKNOWN"
    assert reason == "unmapped-source-status"


def test_status_mapping_case_insensitive() -> None:
    assert map_status_to_reports_v2("PASS") == ("PASS", None)
    assert map_status_to_reports_v2("Manual-Review-Required") == ("UNKNOWN", "manual-review-required")


def test_evaluate_report_contract_2_0_emits_projected_controls() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        report_json_contract="2.0",
    )
    out = report_to_dict(report)
    assert out["schema_version"] == REPORT_JSON_SCHEMA_URL_V2_0
    assert out["contract_version"] == "reports/2.0"
    assert "controls" in out
    assert "results" not in out
    assert set(out["summary_by_status"]) <= {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "ATTESTED"}
    first = out["controls"][0]
    assert "state" in first
    assert first["state"] in {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "ATTESTED"}
    assert "message" in first


# --- migrate-1.0-to-2.0.py script ------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parents[2]
_MIGRATE_SCRIPT = _REPO_ROOT / "scripts" / "migrate-1.0-to-2.0.py"


def _sample_v1_report() -> dict:
    return {
        "schema_version": REPORT_JSON_SCHEMA_URL_V1_0,
        "summary_by_status": {"pass": 5, "fail": 1, "degraded": 1, "manual-review-required": 2},
        "controls": [
            {"id": "GOV-SEC-001", "status": "pass", "reason": "SECURITY.md present."},
            {"id": "GH-PROV-023", "status": "manual-review-required", "reason": "No evidence."},
            {"id": "CI-LEAST-009", "status": "degraded", "reason": "Broad token perms."},
        ],
    }


def test_migrate_script_converts_v1_to_v2(tmp_path: Path) -> None:
    in_file = tmp_path / "old.json"
    out_file = tmp_path / "new.json"
    in_file.write_text(json.dumps(_sample_v1_report()), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_MIGRATE_SCRIPT), "--input", str(in_file), "--output", str(out_file)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert out_file.is_file()
    out = json.loads(out_file.read_text(encoding="utf-8"))
    assert out["schema_version"] == REPORT_JSON_SCHEMA_URL_V2_0
    assert out["contract_version"] == "reports/2.0"
    assert out["summary_by_status"] == {"PASS": 5, "FAIL": 2, "UNKNOWN": 2}
    states = {c["id"]: c["state"] for c in out["controls"]}
    assert states == {"GOV-SEC-001": "PASS", "GH-PROV-023": "UNKNOWN", "CI-LEAST-009": "FAIL"}
    # degraded preserves the per-control flag.
    degraded = next(c for c in out["controls"] if c["id"] == "CI-LEAST-009")
    assert degraded.get("degraded") is True


def test_migrate_script_rejects_malformed_json(tmp_path: Path) -> None:
    in_file = tmp_path / "bad.json"
    out_file = tmp_path / "new.json"
    in_file.write_text("{ not json", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_MIGRATE_SCRIPT), "--input", str(in_file), "--output", str(out_file)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 1
