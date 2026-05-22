"""Branch coverage for AWS-SBOMART-058 and AWS-PROVART-059 (artifact-bound evidence)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import aws as aws_eval
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_D1 = "e7c2a4d8f1b6c9d2e5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2b5c8d1e4"
_D2 = "b3a6c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6"


def _ctx(tmp_path: Path) -> aws_eval.EvalContext:
    return aws_eval.EvalContext(
        repo_root=tmp_path,
        profile_id="aws-release-hardening-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _ev(tmp_path: Path, name: str, payload: dict) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def _sbom(*, posture_all: bool = True, api: bool = True, digest: str = _D1, notes: str | None = None) -> dict:
    payload: dict = {
        "schema_version": "aws-sbom-artifact/v1",
        "attested_at": "2026-05-01",
        "attested_by": "aws-api-collection" if api else "platform team",
        "artifact": {"uri": "s3://bucket/artifact.tgz", "digest_sha256": digest},
        "sbom": {"format": "cyclonedx", "digest_sha256": _D2},
        "posture": {
            "sbom_covers_release_artifact": True,
            "sbom_digest_recorded": True,
            "artifact_digest_recorded": posture_all,
        },
    }
    if notes is not None:
        payload["notes"] = notes
    return payload


def _prov(*, posture_all: bool = True, api: bool = True, digest: str = _D1, notes: str | None = None) -> dict:
    payload: dict = {
        "schema_version": "aws-provenance-artifact/v1",
        "attested_at": "2026-05-01",
        "attested_by": "aws-api-collection" if api else "platform team",
        "artifact": {"uri": "s3://bucket/artifact.tgz", "digest_sha256": digest},
        "attestation": {"kind": "cosign", "digest_sha256": _D2},
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": posture_all,
        },
    }
    if notes is not None:
        payload["notes"] = notes
    return payload


# --------------------------------------------------------------------------- #
# AWS-SBOMART-058
# --------------------------------------------------------------------------- #


def test_sbomart_058_missing(tmp_path: Path) -> None:
    assert aws_eval.eval_aws_sbomart_058(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_sbomart_058_placeholder_blocked(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-sbom-artifact.json", _sbom(notes="TODO confirm"))
    assert aws_eval.eval_aws_sbomart_058(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_sbomart_058_placeholder_digest(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-sbom-artifact.json", _sbom(digest="a" * 64))
    assert aws_eval.eval_aws_sbomart_058(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_sbomart_058_incomplete_self_attested(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-sbom-artifact.json", _sbom(posture_all=False))
    assert aws_eval.eval_aws_sbomart_058(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_sbomart_058_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-sbom-artifact.json", _sbom(api=True))
    out = aws_eval.eval_aws_sbomart_058(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS and out.evidence_collection_method == EvidenceCollectionMethod.LIVE


def test_sbomart_058_self_attested_complete(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-sbom-artifact.json", _sbom(api=False))
    assert aws_eval.eval_aws_sbomart_058(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


# --------------------------------------------------------------------------- #
# AWS-PROVART-059
# --------------------------------------------------------------------------- #


def test_provart_059_missing(tmp_path: Path) -> None:
    assert aws_eval.eval_aws_provart_059(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_provart_059_placeholder_blocked(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-provenance-artifact.json", _prov(notes="YOUR_VALUE"))
    assert aws_eval.eval_aws_provart_059(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_provart_059_placeholder_digest(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-provenance-artifact.json", _prov(digest="0" * 64))
    assert aws_eval.eval_aws_provart_059(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_provart_059_incomplete_self_attested(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-provenance-artifact.json", _prov(posture_all=False))
    assert aws_eval.eval_aws_provart_059(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_provart_059_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-provenance-artifact.json", _prov(api=True))
    out = aws_eval.eval_aws_provart_059(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS and out.evidence_collection_method == EvidenceCollectionMethod.LIVE


def test_provart_059_self_attested_complete(tmp_path: Path) -> None:
    _ev(tmp_path, "aws-provenance-artifact.json", _prov(api=False))
    assert aws_eval.eval_aws_provart_059(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED
