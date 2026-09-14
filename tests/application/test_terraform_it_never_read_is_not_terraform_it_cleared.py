"""Thirteen controls scored 100% over a bucket they never read.

Measured against the built wheel in a clean room. Two Terraform files, one of them carrying
a merge-conflict marker somebody committed by accident:

    infra/network.tf   parses
    infra/buckets.tf   does not parse, and declares acl = "public-read"

    scan-iac  -> files_scanned=['infra/network.tf']  files_failed=['infra/buckets.tf']
    evaluate --profile iac-terraform-baseline-1 --fail-on fail

        Summary: pass=13 | Controls: 13
        weighted_score     {"earned": 25, "possible": 25, "percent": 100.0}
        summary_by_status  {"PASS": 13}
        operational_warnings  []
        exit 0

The only trace was a clause inside each control's free-text `message`, which the table view
truncates and no machine consumer reads. Every field a pipeline gates on said clean.

The sentence in those messages was true -- "no findings across 1 scanned Terraform source" --
and truth is not the bar for a security verdict. `IAC-TF-001` is "object storage configured
for public access", and it answered that question for a repository whose only public bucket
sat in the file the scanner could not open.

WHY THIS FAMILY AND NOT THE OTHER THREE. A guard exactly like this one was written before and
was worse than the bug: it withdrew every Kubernetes control on this very repository, because
`scan-k8s` globs `**/*.yaml` over the whole tree and hits scratch files plus a fixture that is
malformed on purpose. That guard fired on correct content. The difference is the candidate set,
not the principle:

    scan-iac     **/*.tf      every candidate IS Terraform
    scan-bicep   **/*.bicep   every candidate IS Bicep
    scan-cfn     **/*.yaml, **/*.yml, **/*.json, **/*.template
    scan-k8s     **/*.yaml, **/*.yml
    scan-pulumi  **/*.py

For the first two, "a candidate did not parse" and "some of this technology went unchecked"
are the same statement. For the last three they are not, and those keep the note they have.

A rule with a finding is untouched either way: unread sources can only ADD violations, so a
FAIL never becomes less true. Only the clean verdict is withdrawn, and only to
`manual-review-required` -- ADR-045's answer for evidence that could not be read, with
`--fail-on degraded` as the operator's escape hatch.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.application.evaluators_iac import IAC_TF_RULES, build_iac_evaluators
from oss_policy_kit.application.evaluators_iac_bicep import build_iac_bicep_evaluators
from oss_policy_kit.domain.models import ControlStatus

#: The file a scanner could not open, and what is inside it.
UNREAD = "infra/buckets.tf"

#: A merge conflict in a committed `.tf`. Terraform itself would refuse this file too --
#: the kit's answer was that the repository is clean.
CONFLICTED_TF = """resource "aws_s3_bucket" "assets" {
  bucket = "assets-prod"
<<<<<<< HEAD
  acl    = "public-read"
=======
  acl    = "private"
>>>>>>> feature/cdn
}
"""

PINNED_TF = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.31.0"
    }
  }
  backend "s3" {
    bucket         = "tfstate-prod"
    key            = "net/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "tf-locks"
  }
}
"""


def _evidence(
    tmp_path: Path,
    *,
    filename: str,
    schema: str,
    scanned: list[str],
    failed: list[str],
    by_rule: dict[str, int],
) -> None:
    payload: dict[str, Any] = {
        "schema_version": schema,
        "tool": "oss-policy-kit-tf-parser",
        "tool_version": "10.0.21",
        "status": "ok",
        "target": "lab",
        "scanned_at": "2026-09-14T00:00:00+00:00",
        "files_scanned": scanned,
        "files_failed": failed,
        "findings_total": sum(by_rule.values()),
        "findings_by_rule": by_rule,
        "findings_by_severity": {},
        "findings": [],
        "diagnostics": {
            "parse_errors": [{"file": f, "error": "Unexpected token"} for f in failed],
            "raw_message": "",
        },
    }
    out = tmp_path / ".oss-policy-kit" / "evidence"
    out.mkdir(parents=True, exist_ok=True)
    (out / filename).write_text(json.dumps(payload), encoding="utf-8")


def _tf_evidence(tmp_path: Path, *, failed: list[str], by_rule: dict[str, int] | None = None) -> None:
    _evidence(
        tmp_path,
        filename="iac-terraform.json",
        schema="oss-policy-kit/evidence/iac-terraform/v1",
        scanned=["infra/network.tf"],
        failed=failed,
        by_rule=by_rule or dict.fromkeys((r for r, _ in IAC_TF_RULES), 0),
    )


def _run(evaluators: dict[str, Any], control_id: str, tmp_path: Path) -> Any:
    return evaluators[control_id](SimpleNamespace(repo_root=tmp_path))


ALL_TF_RULES = [rule_id for rule_id, _ in IAC_TF_RULES]


@pytest.mark.parametrize("control_id", ALL_TF_RULES)
def test_no_terraform_control_reports_clean_over_a_file_it_could_not_read(control_id: str, tmp_path: Path) -> None:
    """The reproduction, control by control. All twelve said PASS."""

    _tf_evidence(tmp_path, failed=[UNREAD])

    outcome = _run(build_iac_evaluators(), control_id, tmp_path)

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert UNREAD in outcome.reason, "the reader has to be told WHICH file is unchecked"


def test_the_clean_verdict_survives_when_every_file_was_read(tmp_path: Path) -> None:
    """The ordinary target, which is every target. This guard must be invisible there."""

    _tf_evidence(tmp_path, failed=[])

    outcome = _run(build_iac_evaluators(), "IAC-TF-001", tmp_path)

    assert outcome.status == ControlStatus.PASS
    assert outcome.confidence == "high"


def test_a_real_finding_still_fails_even_with_unread_files(tmp_path: Path) -> None:
    """The invariant that orders the whole unread-content program.

    A withdrawal may replace a PASS and never a FAIL. Unread sources can only add violations,
    so they never make an existing failure less true -- and turning a red pipeline
    `manual-review-required` would be the larger mistake, since that state does not trip
    `--fail-on fail`.
    """

    by_rule = dict.fromkeys(ALL_TF_RULES, 0)
    by_rule["IAC-TF-001"] = 2
    _tf_evidence(tmp_path, failed=[UNREAD], by_rule=by_rule)

    outcome = _run(build_iac_evaluators(), "IAC-TF-001", tmp_path)

    assert outcome.status == ControlStatus.FAIL


def test_the_withdrawal_names_the_count_and_does_not_pass_off_a_truncated_list(tmp_path: Path) -> None:
    """Five unread files must not be reported as the three the message has room for."""

    _tf_evidence(tmp_path, failed=[f"infra/m{n}.tf" for n in range(5)])

    reason = _run(build_iac_evaluators(), "IAC-TF-002", tmp_path).reason

    assert "and 2 more" in reason, reason


def test_the_withdrawal_points_at_the_escape_hatch(tmp_path: Path) -> None:
    """ADR-045: this state is not a verdict, and an operator has to be able to gate on it."""

    _tf_evidence(tmp_path, failed=[UNREAD])

    assert "--fail-on degraded" in _run(build_iac_evaluators(), "IAC-TF-003", tmp_path).remediation


# --- the sibling: scan-bicep globs **/*.bicep, so it has the same property ------------------------


def _bicep_evidence(tmp_path: Path, *, failed: list[str]) -> None:
    from oss_policy_kit.infrastructure.iac.bicep.scanner import all_rule_ids

    _evidence(
        tmp_path,
        filename="iac-bicep.json",
        schema="oss-policy-kit/evidence/iac-bicep/v1",
        scanned=["infra/main.bicep"],
        failed=failed,
        by_rule=dict.fromkeys(all_rule_ids(), 0),
    )


def test_no_bicep_control_reports_clean_over_a_file_it_could_not_read(tmp_path: Path) -> None:
    """Found by sweeping the siblings rather than by a second validation round.

    The Bicep scanner parses by regex and never fails on syntax -- it records a parse error
    only when the OS refuses the read (permissions, a broken symlink, a path past the length
    limit). Same shape, same false clean.
    """

    _bicep_evidence(tmp_path, failed=["infra/storage.bicep"])
    evaluators = build_iac_bicep_evaluators()
    control_id = next(iter(evaluators))

    outcome = evaluators[control_id](SimpleNamespace(repo_root=tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "infra/storage.bicep" in outcome.reason


def test_the_bicep_clean_verdict_survives_when_every_file_was_read(tmp_path: Path) -> None:
    _bicep_evidence(tmp_path, failed=[])
    evaluators = build_iac_bicep_evaluators()
    control_id = next(iter(evaluators))

    assert evaluators[control_id](SimpleNamespace(repo_root=tmp_path)).status == ControlStatus.PASS


# --- and the three families whose candidates are not all their technology -------------------------


def test_a_broad_glob_family_keeps_its_pass_and_states_its_scope(tmp_path: Path) -> None:
    """`scan-k8s` reaches every `**/*.yaml` in the tree, most of which are not manifests.

    A guard here fired on this repository's own scratch files and on a fixture that is
    malformed on purpose, turning all 16 Kubernetes controls UNKNOWN. A guard that fires on
    correct content is a guard somebody switches off, so these three keep the note instead.
    """

    from oss_policy_kit.application.evaluators_k8s import build_k8s_evaluators
    from oss_policy_kit.infrastructure.k8s.scanner import all_rule_ids

    _evidence(
        tmp_path,
        filename="k8s-baseline.json",
        schema="oss-policy-kit/evidence/k8s-baseline/v1",
        scanned=["deploy/app.yaml"],
        failed=["notes/scratch.yaml"],
        by_rule=dict.fromkeys(all_rule_ids(), 0),
    )
    evaluators = build_k8s_evaluators()
    control_id = next(iter(evaluators))

    outcome = evaluators[control_id](SimpleNamespace(repo_root=tmp_path))

    assert outcome.status == ControlStatus.PASS
    assert "notes/scratch.yaml" in outcome.reason, "the scope still has to be stated"


# --- end to end, through the real scanner ---------------------------------------------------------


def test_end_to_end_a_committed_merge_conflict_stops_being_a_clean_scan(tmp_path: Path) -> None:
    """From two files on disk to the control verdict, with no hand-written evidence."""

    pytest.importorskip("hcl2")
    from oss_policy_kit.infrastructure.iac.scanner import (
        EVIDENCE_FILENAME,
        render_evidence_payload,
        run_scan,
        write_evidence,
    )

    infra = tmp_path / "infra"
    infra.mkdir()
    (infra / "network.tf").write_text(PINNED_TF, encoding="utf-8")
    (infra / "buckets.tf").write_text(CONFLICTED_TF, encoding="utf-8")

    outcome = run_scan(tmp_path)
    assert outcome.parse_errors, "the fixture has to actually fail to parse"
    write_evidence(render_evidence_payload(outcome, target=tmp_path), repo_root=tmp_path, filename=EVIDENCE_FILENAME)

    states = {
        rule_id: build_iac_evaluators()[rule_id](SimpleNamespace(repo_root=tmp_path)).status for rule_id in ALL_TF_RULES
    }

    assert set(states.values()) == {ControlStatus.MANUAL_REVIEW_REQUIRED}, states
