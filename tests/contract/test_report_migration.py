"""Roundtrip tests for the reports/1.0 -> reports/2.0 migration.

These exercise the migration that actually ships: the engine serializers
``report_to_dict_v1`` (reports/1.0) and ``report_to_dict_v2_0`` (reports/2.0).
The contract is that a 1.0 evaluation can be re-expressed as a schema-valid 2.0
document with no control lost, every status mapped into the five-state
vocabulary, and run metadata preserved.

NOTE: the standalone helper ``scripts/migrate-1.0-to-2.0.py`` is NOT exercised
here on purpose -- it is stale (it reads a top-level ``controls`` key, but
reports/1.0 emits ``results``) and does not produce a 2.0-schema-valid document.
That drift is tracked in the local backlog, separate from this test (see prompt
M5 anti-pattern: a real bug is registered, not patched to make a test pass).
"""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft202012Validator

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict_v1, report_to_dict_v2_0
from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE

_REPORTS_2_0_STATES = {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "ATTESTED"}


def _load_2_0_schema() -> dict[str, Any]:
    schema_path = files("oss_policy_kit.data.schema.reports").joinpath("2.0.json")
    data: dict[str, Any] = json.loads(schema_path.read_text(encoding="utf-8"))
    return data


_SCHEMA_2_0 = _load_2_0_schema()
_VALIDATOR_2_0 = Draft202012Validator(_SCHEMA_2_0)


def _evaluate(profile_id: str, target: Path) -> Any:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    return evaluate_repository(
        repo_root=target,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        report_json_contract="1.0",
    )


def test_native_2_0_validates_against_schema() -> None:
    """AC3: the reports/2.0 serialization is schema-valid for real evaluations."""

    for target in (EXAMPLE_HARDENED, EXAMPLE_VULNERABLE):
        report = _evaluate("github-level-1", target)
        v2 = report_to_dict_v2_0(report)
        _VALIDATOR_2_0.validate(v2)  # raises on any schema violation


def test_migration_preserves_every_control() -> None:
    """No control is dropped or duplicated between 1.0 and 2.0."""

    report = _evaluate("github-level-1", EXAMPLE_HARDENED)
    v1 = report_to_dict_v1(report)
    v2 = report_to_dict_v2_0(report)

    v1_ids = sorted(r["control_id"] for r in v1["results"])
    v2_ids = sorted(c["id"] for c in v2["controls"])

    assert v1_ids == v2_ids
    assert v2["controls_total"] == len(v2["controls"]) == len(v1["results"])


def test_migration_maps_status_into_five_state_vocabulary() -> None:
    """Every 2.0 state (per-control and summary) is in the Scorecard-aligned set."""

    report = _evaluate("github-level-1", EXAMPLE_VULNERABLE)
    v2 = report_to_dict_v2_0(report)

    for control in v2["controls"]:
        assert control["state"] in _REPORTS_2_0_STATES, control
    for state_key in v2["summary_by_status"]:
        assert state_key in _REPORTS_2_0_STATES, state_key

    # The summary counts must add up to the number of controls.
    assert sum(v2["summary_by_status"].values()) == v2["controls_total"]


def test_migration_preserves_run_metadata() -> None:
    """Profile identity and run metadata survive the migration."""

    report = _evaluate("github-level-1", EXAMPLE_HARDENED)
    v1 = report_to_dict_v1(report)
    v2 = report_to_dict_v2_0(report)

    assert v2["profile"]["id"] == v1["profile"]["id"] == "github-level-1"
    assert v2["profile"]["title"] == v1["profile"]["title"]
    assert v2["kit_version"] == v1["kit_version"]
    assert v2["generated_at"] == v1["generated_at"]
    assert v2["contract_version"] == "reports/2.0"


@given(profile_id=st.sampled_from(["github-level-1", "github-level-2", "azure-level-1", "aws-level-1"]))
@settings(max_examples=4, deadline=None)
def test_native_migration_is_always_schema_valid_across_profiles(profile_id: str) -> None:
    """Property: for several profiles, the 2.0 serialization is always schema-valid."""

    report = _evaluate(profile_id, EXAMPLE_HARDENED)
    v2 = report_to_dict_v2_0(report)
    _VALIDATOR_2_0.validate(v2)
    assert v2["controls_total"] == len(v2["controls"])
