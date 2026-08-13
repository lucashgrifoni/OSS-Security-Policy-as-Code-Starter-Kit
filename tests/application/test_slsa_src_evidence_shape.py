"""The SLSA source controls and PLAT-BRPROT-015 read `branch-protection.json` the same way.

They used to disagree about its shape. `SLSA-SRC-003/004/006/007` read top-level
`required_status_checks`, `required_approving_review_count` and `required_signatures`;
`evidence-branch-protection.schema.json` forbids all three (`additionalProperties: false`, and
the flags live under `protections`), and PLAT-BRPROT-015 validated against that schema. So a
`branch-protection.json` written by the kit's own `scaffold-evidence` or `collect-evidence`, and
accepted by the kit's own schema, made PLAT-BRPROT-015 answer `pass` while the four SLSA controls
answered `fail`/`manual-review-required` on the very same bytes. No input could satisfy both.

Backwards compatibility with the flat shape was considered and refused. Every file carrying those
top-level keys is schema-invalid -- there is no conformant document that has them -- so honouring
them would mean granting evidence-backed credit from a file the packaged schema rejects and the
sibling control refuses, which is the same disagreement with the sign flipped. It is refused
*loudly*: the schema violation is named in the reason, so an adopter who hand-wrote the flat shape
is told, not silently ignored. `test_the_legacy_flat_shape_is_refused_by_name` pins that.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import supply_chain
from oss_policy_kit.application.evaluators._shared import _parse_branch_protection_evidence
from oss_policy_kit.domain.models import ControlStatus

_EVIDENCE_RELPATH = ".oss-policy-kit/evidence/branch-protection.json"

# The shape `scaffold-evidence --platform github` writes and the packaged schema requires,
# with the optional `require_signed_commits` filled in the way an honest maintainer would.
_SCHEMA_VALID: dict[str, Any] = {
    "schema_version": "branch-protection/v1",
    "attested_at": "2026-08-13",
    "attested_by": "a-maintainer",
    "branch": "main",
    "protections": {
        "require_pull_request_reviews": True,
        "dismiss_stale_reviews": True,
        "require_status_checks": True,
        "enforce_admins": True,
        "restrict_force_push": True,
        "require_signed_commits": True,
    },
}

_EVALUATORS = {
    "SLSA-SRC-003": supply_chain.eval_slsa_src_003,
    "SLSA-SRC-004": supply_chain.eval_slsa_src_004,
    "SLSA-SRC-006": supply_chain.eval_slsa_src_006,
    "SLSA-SRC-007": supply_chain.eval_slsa_src_007,
}

# The flag each control answers for, and the state it reports when that flag is attested off.
# SLSA-SRC-007 rides on the same flag as 004: zero required approvals is definitively below the
# L2 threshold of two, which is the one thing about the threshold this evidence can settle.
_FLAG_UNDER_TEST = {
    "SLSA-SRC-003": ("require_status_checks", ControlStatus.FAIL),
    "SLSA-SRC-004": ("require_pull_request_reviews", ControlStatus.FAIL),
    "SLSA-SRC-006": ("require_signed_commits", ControlStatus.FAIL),
    "SLSA-SRC-007": ("require_pull_request_reviews", ControlStatus.FAIL),
}


def _ctx(repo: Path) -> SimpleNamespace:
    return SimpleNamespace(repo_root=repo)


def _write_evidence(repo: Path, doc: object) -> Path:
    p = repo / _EVIDENCE_RELPATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _evidence_with(**protections: bool) -> dict[str, Any]:
    doc = json.loads(json.dumps(_SCHEMA_VALID))
    doc["protections"].update(protections)
    return doc


# --------------------------------------------------------------------------- #
# The defect: schema-valid evidence must earn credit
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("control_id", ["SLSA-SRC-003", "SLSA-SRC-004", "SLSA-SRC-006"])
def test_schema_valid_evidence_with_protections_on_passes(control_id: str, tmp_path: Path) -> None:
    """Pre-fix these read top-level keys the schema forbids, so this file could never satisfy them."""

    _write_evidence(tmp_path, _SCHEMA_VALID)

    outcome = _EVALUATORS[control_id](_ctx(tmp_path))

    assert outcome.status is ControlStatus.PASS, outcome.reason


def test_the_same_file_that_passes_plat_brprot_015_passes_the_slsa_controls(tmp_path: Path) -> None:
    """The bug in one sentence: two readers, one file, opposite answers."""

    evidence = _write_evidence(tmp_path, _SCHEMA_VALID)

    assert _parse_branch_protection_evidence(evidence).status is ControlStatus.PASS
    assert supply_chain.eval_slsa_src_003(_ctx(tmp_path)).status is ControlStatus.PASS
    assert supply_chain.eval_slsa_src_004(_ctx(tmp_path)).status is ControlStatus.PASS
    assert supply_chain.eval_slsa_src_006(_ctx(tmp_path)).status is ControlStatus.PASS


@pytest.mark.parametrize("control_id", list(_FLAG_UNDER_TEST))
def test_a_protection_attested_off_fails_its_control(control_id: str, tmp_path: Path) -> None:
    """The other direction: the fix must not have made these controls unable to fail."""

    flag, expected = _FLAG_UNDER_TEST[control_id]
    _write_evidence(tmp_path, _evidence_with(**{flag: False}))

    outcome = _EVALUATORS[control_id](_ctx(tmp_path))

    assert outcome.status is expected, outcome.reason
    assert flag in outcome.reason


@pytest.mark.parametrize("control_id", ["SLSA-SRC-003", "SLSA-SRC-004", "SLSA-SRC-006"])
def test_one_protection_off_does_not_move_the_other_controls(control_id: str, tmp_path: Path) -> None:
    """Each control answers for its own flag; a shared reader must not blur them together."""

    flag, _ = _FLAG_UNDER_TEST[control_id]
    _write_evidence(tmp_path, _evidence_with(**{flag: False}))

    others = [cid for cid in ("SLSA-SRC-003", "SLSA-SRC-004", "SLSA-SRC-006") if cid != control_id]
    assert [_EVALUATORS[cid](_ctx(tmp_path)).status for cid in others] == [ControlStatus.PASS] * len(others)


# --------------------------------------------------------------------------- #
# What the documented shape cannot say
# --------------------------------------------------------------------------- #


def test_the_l2_approver_threshold_is_unknown_not_passed(tmp_path: Path) -> None:
    """`protections` is closed and carries no count, so >= 1 is never read as >= 2."""

    _write_evidence(tmp_path, _SCHEMA_VALID)

    outcome = supply_chain.eval_slsa_src_007(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "no approver count" in outcome.reason


def test_an_unattested_signing_flag_is_unknown_not_failed(tmp_path: Path) -> None:
    """`require_signed_commits` is optional in branch-protection/v1; absent means unrecorded (ADR-045)."""

    doc = json.loads(json.dumps(_SCHEMA_VALID))
    del doc["protections"]["require_signed_commits"]
    _write_evidence(tmp_path, doc)

    outcome = supply_chain.eval_slsa_src_006(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "records no protections.require_signed_commits" in outcome.reason


# --------------------------------------------------------------------------- #
# Evidence the reader refuses -- and refuses out loud
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("control_id", list(_EVALUATORS))
def test_the_legacy_flat_shape_is_refused_by_name(control_id: str, tmp_path: Path) -> None:
    """A stray top-level key is named in the refusal, so the flat shape is not silently dropped."""

    _write_evidence(tmp_path, {**_SCHEMA_VALID, "required_approving_review_count": 2})

    outcome = _EVALUATORS[control_id](_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "required_approving_review_count" in outcome.reason
    assert "evidence-branch-protection.schema.json" in outcome.reason


@pytest.mark.parametrize("control_id", list(_EVALUATORS))
def test_an_unfilled_scaffold_template_earns_no_credit(control_id: str, tmp_path: Path) -> None:
    """The kit's own template must not pass; PLAT-BRPROT-015 already refused it."""

    _write_evidence(tmp_path, {**_SCHEMA_VALID, "attested_by": "REPLACE_ME_GITHUB_HANDLE"})

    outcome = _EVALUATORS[control_id](_ctx(tmp_path))

    assert outcome.status is ControlStatus.NOT_EVALUATED
    assert "placeholder" in outcome.reason.lower()


@pytest.mark.parametrize("control_id", list(_EVALUATORS))
def test_a_non_object_root_is_refused(control_id: str, tmp_path: Path) -> None:
    """`_branch_protection_evidence` reports a list root as absent; the file is present, so refuse."""

    _write_evidence(tmp_path, ["not", "an", "object"])

    outcome = _EVALUATORS[control_id](_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "must be a JSON object" in outcome.reason


@pytest.mark.parametrize("control_id", list(_EVALUATORS))
def test_a_missing_evidence_file_keeps_each_controls_own_wording(control_id: str, tmp_path: Path) -> None:
    """Absent is not the same sentence as unreadable, and stays per-control."""

    outcome = _EVALUATORS[control_id](_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert outcome.evidence_sources == []
    assert "No branch-protection.json evidence" in outcome.reason
