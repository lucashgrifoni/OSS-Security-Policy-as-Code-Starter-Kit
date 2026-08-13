"""What a governance control may claim from the evidence file it was handed.

Two rules, both about the gap between "there is a document here" and "someone attested
something":

- ``BUILD-SBOM-QUAL-003`` must refuse an untouched ``scaffold-evidence`` template. The scaffold
  ships ``sbom.format: "cyclonedx"`` already filled in, so a declared format says nothing about
  whether an operator ever wrote anything. Reading it as a PASS turned an empty repository from
  0.0% into 18.2% on ``azure-level-3`` with no evidence behind the move.
- ``GOV-EVIDFRESH-054`` must name the evidence file it could not read and nothing else. The CLI
  resolves ``--target`` before evaluating, so interpolating the raw ``OSError`` put the auditor's
  home directory and OS account name into a ``reason`` that reports print verbatim -- in the same
  report whose ``target_path`` was deliberately reduced to a basename (M-002).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import governance as gov
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(repo: Path) -> gov.EvalContext:
    return gov.EvalContext(
        repo_root=repo,
        profile_id="azure-level-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _filled_sbom_evidence() -> dict[str, Any]:
    """The azure SBOM template as an operator who actually attested something leaves it."""

    return {
        "schema_version": "azure-sbom-artifact/v1",
        "attested_at": "2026-08-01",
        "attested_by": "release-engineering@example.com",
        "artifact": {
            "uri": "https://pkgs.dev.azure.com/example/_apis/packaging/feeds/release/artifacts/app-1.4.2.tgz",
            "digest_sha256": "9f2c41e0b7d85a63c1e47f0a2d9b6538ec704a1fb92d3c8570ae6b41d2f89c07",
        },
        "sbom": {
            "format": "cyclonedx",
            "digest_sha256": "3b81d5f6a047c92e1806bf34d75ac2e9083f61bd47e5a20c9d3ef8617a45b0c2",
        },
        "posture": {
            "sbom_covers_release_artifact": True,
            "sbom_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
        "notes": "Digest bound to the 1.4.2 release artifact published from the tagged pipeline run.",
    }


# --------------------------------------------------------------------------- #
# BUILD-SBOM-QUAL-003 — a scaffold nobody filled in earns nothing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("platform", ["azure", "aws"])
def test_sbom_qual_003_refuses_credit_to_an_untouched_scaffold(tmp_path: Path, platform: str) -> None:
    """The shipped template declares a format; only a filled-in file attests one.

    Driven through the real ``scaffold-evidence`` writer rather than a hand-made fixture, so the
    test fails if a future template edit reintroduces a pre-filled ``sbom.format`` beside
    unreplaced tokens.
    """

    scaffold_evidence_files(tmp_path, platform)

    out = gov.eval_build_sbom_qual_003(_ctx(tmp_path))

    assert out.status == ControlStatus.NOT_EVALUATED
    assert f"{platform}-sbom-artifact.json" in out.reason
    assert "placeholder" in out.reason.lower()


def test_sbom_qual_003_passes_once_the_template_is_filled_in(tmp_path: Path) -> None:
    """The gate is on the unreplaced tokens, not on the evidence route: a real attestation still PASSes."""

    scaffold_evidence_files(tmp_path, "azure")
    evidence = tmp_path / ".oss-policy-kit" / "evidence" / "azure-sbom-artifact.json"
    evidence.write_text(json.dumps(_filled_sbom_evidence()), encoding="utf-8")

    out = gov.eval_build_sbom_qual_003(_ctx(tmp_path))

    assert out.status == ControlStatus.PASS
    assert "cyclonedx" in out.reason


# --------------------------------------------------------------------------- #
# GOV-EVIDFRESH-054 — a read failure names the file, never the host path
# --------------------------------------------------------------------------- #


def _repo_with_unreadable_evidence(root: Path) -> Path:
    """A repo whose only evidence entry is a directory named like a JSON file.

    Opening it raises ``OSError``, and ``OSError`` stringifies with the filename it was handed --
    which is the whole defect.
    """

    repo = root / "repo"
    (repo / ".oss-policy-kit" / "evidence" / "branch-protection.json").mkdir(parents=True)
    return repo


def _assert_reason_carries_no_path(reason: str) -> None:
    """No path component survived into *reason* -- in either separator style.

    Asserting the absence of one particular absolute string is what has passed for the wrong
    reason on Windows three times: an 8.3 short path (``LUCASG~1``), a ``json.dumps``-doubled
    backslash and an ``as_posix()`` rewrite all defeat it while still leaking the path. Every one
    of them still contains a separator, and a bare file name never does.
    """

    assert "/" not in reason
    assert "\\" not in reason


def test_evidfresh_054_unreadable_evidence_names_the_file_not_the_path(tmp_path: Path) -> None:
    """The reason identifies the file to repair; the path it was read from is not the operator's business."""

    repo = _repo_with_unreadable_evidence(tmp_path)

    out = gov.eval_gov_evidfresh_054(_ctx(repo.resolve()))

    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "branch-protection.json" in out.reason
    _assert_reason_carries_no_path(out.reason)


def test_evidfresh_054_unreadable_evidence_leaks_no_path_from_a_relative_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative ``--target`` leaks less, but it still leaks: the rule is no path at all, resolved or not."""

    _repo_with_unreadable_evidence(tmp_path)
    monkeypatch.chdir(tmp_path)

    out = gov.eval_gov_evidfresh_054(_ctx(Path("repo")))

    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "branch-protection.json" in out.reason
    _assert_reason_carries_no_path(out.reason)


def test_evidfresh_054_unreadable_evidence_keeps_the_resolved_path_in_evidence_sources(tmp_path: Path) -> None:
    """``evidence_sources`` is not prose: the report writers sanitize it, and ``--include-absolute-path`` needs it."""

    repo = _repo_with_unreadable_evidence(tmp_path)

    out = gov.eval_gov_evidfresh_054(_ctx(repo.resolve()))

    assert out.evidence_sources == [str((repo / ".oss-policy-kit" / "evidence" / "branch-protection.json").resolve())]
