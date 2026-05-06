"""End-to-end v5 invariants: deterministic results_digest and hard-gate signal cap.

These tests exercise the full evaluator + reports/1.0 projection on the bundled
hardened repository. They guard against regressions in two v5 properties:

1. **Determinism**: same input → same ``results_digest`` and same per-result
   evidence projection across runs.
2. **No silent inflation on hard gates**: signal-grade controls under hard-gate
   profiles never project to ``trust_level: verified``; their limitations array
   always carries the signal-cap explanation.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import REPORT_JSON_SCHEMA_URL_V1_0, evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict_v1


def _evaluate_v1(profile_id: str) -> dict:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    report = evaluate_repository(
        repo_root=Path(EXAMPLE_HARDENED),
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        external_waiver_path=None,
        verbose_emit=None,
        report_json_contract="1.0",
    )
    return report_to_dict_v1(report)


def test_results_digest_is_stable_across_runs() -> None:
    """Same hardened repo + same profile must produce the same digest twice."""

    a = _evaluate_v1("github-level-1")
    b = _evaluate_v1("github-level-1")
    assert a["schema_version"] == REPORT_JSON_SCHEMA_URL_V1_0
    assert b["schema_version"] == REPORT_JSON_SCHEMA_URL_V1_0
    assert a["results_digest"] == b["results_digest"]
    # results_digest format is sha256:<hex64>
    assert a["results_digest"].startswith("sha256:")
    assert len(a["results_digest"]) == len("sha256:") + 64


def test_results_digest_changes_when_profile_changes() -> None:
    a = _evaluate_v1("github-level-1")
    b = _evaluate_v1("github-level-2")
    assert a["results_digest"] != b["results_digest"]


def test_hard_gate_signal_grade_results_cap_at_inferred() -> None:
    """github-level-3 is a hard-gate profile; signal controls must NOT project to verified."""

    payload = _evaluate_v1("github-level-3")
    signal_results = [r for r in payload["results"] if r["assurance"] == "signal"]
    # The hardened fixture should pass several signal controls. Each must remain capped.
    assert signal_results, "expected at least one signal-grade control in github-level-3"
    for r in signal_results:
        assert r["evidence"]["trust_level"] != "verified", (
            f"{r['control_id']}: signal-grade result must not project to 'verified' on a hard gate"
        )
        # Limitations must contain the signal-cap explanation when source_type is heuristic.
        if r["evidence"]["source_type"] == "heuristic_signal":
            joined = " ".join(r["evidence"]["limitations"]).lower()
            assert "signal" in joined, f"{r['control_id']} missing signal limitation text"


def test_hard_gate_evidence_backed_results_can_reach_higher_trust() -> None:
    """Evidence-backed controls in a hard-gate profile may reach 'declared' or 'verified'.

    This guards the inverse: we must NOT have accidentally capped *all* trust on hard gates.
    """

    payload = _evaluate_v1("github-level-3")
    eb_results = [r for r in payload["results"] if r["assurance"] == "evidence-backed"]
    # Some evidence-backed controls in the hardened fixture should reach at least 'declared'.
    if eb_results:
        trust_levels = {r["evidence"]["trust_level"] for r in eb_results}
        assert trust_levels - {"unobserved"}, (
            f"every evidence-backed result projected to 'unobserved' — projection is too aggressive: {eb_results}"
        )


def test_v1_payload_evidence_provenance_version_is_set() -> None:
    payload = _evaluate_v1("github-level-1")
    assert payload["evidence_provenance_version"] == "evidence/2.0"


def test_v1_payload_extensions_namespace_is_empty_object() -> None:
    """Extensions surface must be present and empty by default for downstream forward compat."""

    payload = _evaluate_v1("github-level-1")
    assert payload["extensions"] == {}


def test_v1_payload_serializes_to_stable_canonical_json() -> None:
    """Sorted-keys JSON dump must be stable across runs."""

    a = _evaluate_v1("github-level-1")
    b = _evaluate_v1("github-level-1")
    # Drop generated_at since it's a timestamp.
    a.pop("generated_at", None)
    b.pop("generated_at", None)
    # Drop kit_version since hot-reloads in dev environments could differ trivially.
    a.pop("kit_version", None)
    b.pop("kit_version", None)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
