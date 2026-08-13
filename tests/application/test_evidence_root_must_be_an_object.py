"""Evidence whose root is not a JSON object earns nothing.

Six controls read a JSON file and reach straight for a key on it. Each one guards that with an
`isinstance(data, dict)` first, and each guard is doing real work: `json.loads` happily returns a
list, a string, a number or `null`, and `[].get` would be an `AttributeError` escaping as an
internal error rather than a verdict.

The shape that matters most is the one that looks harmless. A file containing `[]` is not empty
evidence -- it is evidence the reader cannot interpret -- and the difference decides whether a
repository is told its branch protection is unverified or told nothing at all. Every case below
is asserted as *not a pass*, alongside the well-formed counterpart, so a guard that started
refusing everything would be just as visible as one that stopped refusing anything.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import github, governance, supply_chain
from oss_policy_kit.application.evaluators._shared import EvalContext, _branch_protection_evidence
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

# `null` is included on purpose: it is the shape a truncated or half-written file most often
# takes, and the one an author is least likely to have pictured.
_NOT_AN_OBJECT = ['["a", "list"]', '"a string"', "42", "null", "true"]


def _ctx(root: Path) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _evidence(root: Path, name: str, body: str) -> Path:
    path = root / ".oss-policy-kit" / "evidence" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Branch protection, read by two controls and one shared helper
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", _NOT_AN_OBJECT)
def test_branch_protection_that_is_not_an_object_is_read_as_absent(body: str, tmp_path: Path) -> None:
    """Callers branch on `None`; handing them a list would put `.get` on a list."""

    _evidence(tmp_path, "branch-protection.json", body)
    data, path = _branch_protection_evidence(_ctx(tmp_path))

    assert data is None
    assert path.name == "branch-protection.json"


def test_a_well_formed_branch_protection_file_is_returned(tmp_path: Path) -> None:
    _evidence(tmp_path, "branch-protection.json", json.dumps({"required_approving_review_count": 2}))
    data, _path = _branch_protection_evidence(_ctx(tmp_path))

    assert data == {"required_approving_review_count": 2}


@pytest.mark.parametrize("body", _NOT_AN_OBJECT)
def test_two_party_review_is_not_confirmed_by_evidence_that_cannot_be_read(body: str, tmp_path: Path) -> None:
    _evidence(tmp_path, "branch-protection.json", body)
    assert supply_chain.eval_slsa_src_004(_ctx(tmp_path)).status is not ControlStatus.PASS


def test_two_party_review_passes_on_an_attested_review_requirement(tmp_path: Path) -> None:
    """The counterpart, and the reason the guard cannot simply refuse everything."""

    _evidence(
        tmp_path,
        "branch-protection.json",
        json.dumps(
            {
                "schema_version": "branch-protection/v1",
                "attested_at": "2026-06-15",
                "attested_by": "platform-team",
                "branch": "main",
                "protections": {
                    "require_pull_request_reviews": True,
                    "dismiss_stale_reviews": True,
                    "require_status_checks": True,
                    "enforce_admins": True,
                    "restrict_force_push": True,
                },
            }
        ),
    )
    outcome = supply_chain.eval_slsa_src_004(_ctx(tmp_path))

    assert outcome.status is ControlStatus.PASS
    assert "require_pull_request_reviews" in outcome.reason


# --------------------------------------------------------------------------- #
# Scorecard OSPS conformance
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", _NOT_AN_OBJECT)
def test_osps_conformance_is_not_claimed_from_an_unreadable_verdict(body: str, tmp_path: Path) -> None:
    """A conformance claim is the strongest thing this control emits; it needs a real verdict."""

    _evidence(tmp_path, "scorecard-osps.json", body)
    assert governance.eval_osps_scorecard_v6_001(_ctx(tmp_path)).status is not ControlStatus.PASS


@pytest.mark.parametrize("key", ["conformance", "result", "overall"])
def test_any_of_the_three_verdict_keys_is_honoured(key: str, tmp_path: Path) -> None:
    """Scorecard has moved the field; all three spellings are accepted deliberately."""

    _evidence(tmp_path, "scorecard-osps.json", json.dumps({key: "PASS"}))
    assert governance.eval_osps_scorecard_v6_001(_ctx(tmp_path)).status is ControlStatus.PASS


def test_a_verdict_the_control_does_not_recognise_is_not_a_pass(tmp_path: Path) -> None:
    _evidence(tmp_path, "scorecard-osps.json", json.dumps({"conformance": "unknown"}))
    assert governance.eval_osps_scorecard_v6_001(_ctx(tmp_path)).status is not ControlStatus.PASS


# --------------------------------------------------------------------------- #
# package.json
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", _NOT_AN_OBJECT)
def test_a_package_json_that_is_not_an_object_is_not_declared_free_of_postinstall(body: str, tmp_path: Path) -> None:
    """ "No postinstall script declared" is a claim about a file the reader could read."""

    (tmp_path / "package.json").write_text(body, encoding="utf-8")
    assert supply_chain.eval_worm_postinstall_001(_ctx(tmp_path)).status is not ControlStatus.PASS


def test_a_package_json_without_a_postinstall_hook_passes(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "app", "scripts": {"test": "jest"}}), encoding="utf-8")
    assert supply_chain.eval_worm_postinstall_001(_ctx(tmp_path)).status is ControlStatus.PASS


def test_a_scripts_block_that_is_not_an_object_is_treated_as_no_scripts(tmp_path: Path) -> None:
    """The inner guard: the root parsed, but `scripts` is still whatever the file said."""

    (tmp_path / "package.json").write_text(json.dumps({"name": "app", "scripts": "oops"}), encoding="utf-8")
    assert supply_chain.eval_worm_postinstall_001(_ctx(tmp_path)).status is ControlStatus.PASS


# --------------------------------------------------------------------------- #
# Provenance verification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", _NOT_AN_OBJECT)
def test_a_transparency_log_inclusion_is_not_inferred_from_an_unreadable_file(body: str, tmp_path: Path) -> None:
    evidence = _evidence(tmp_path, "provenance-artifact.json", body)
    assert github._gh_provenance_verification_recorded(evidence) is False


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("no verification block", {"artifact": {}}),
        ("verification is not an object", {"verification": "yes"}),
        ("inclusion not recorded", {"verification": {"transparency_log_inclusion": False}}),
    ],
)
def test_only_a_recorded_inclusion_counts(label: str, payload: dict[str, Any], tmp_path: Path) -> None:
    evidence = _evidence(tmp_path, "provenance-artifact.json", json.dumps(payload))
    assert github._gh_provenance_verification_recorded(evidence) is False, label


def test_a_recorded_inclusion_counts(tmp_path: Path) -> None:
    evidence = _evidence(
        tmp_path, "provenance-artifact.json", json.dumps({"verification": {"transparency_log_inclusion": True}})
    )
    assert github._gh_provenance_verification_recorded(evidence) is True


def test_a_file_that_is_not_there_is_not_a_recorded_inclusion(tmp_path: Path) -> None:
    assert github._gh_provenance_verification_recorded(tmp_path / "missing.json") is False
