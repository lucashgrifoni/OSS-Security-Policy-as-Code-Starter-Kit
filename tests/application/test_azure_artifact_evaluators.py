"""Branch coverage for AZ-ARTSBOM-058 and AZ-ARTPRV-059 (artifact-bound evidence)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import azure as az
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_D1 = "e7c2a4d8f1b6c9d2e5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2b5c8d1e4"
_D2 = "b3a6c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6"


def _ctx(tmp_path: Path) -> az.EvalContext:
    return az.EvalContext(
        repo_root=tmp_path,
        profile_id="azure-release-hardening-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _ev(tmp_path: Path, name: str, payload: dict) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def _sbom_payload(*, posture_all: bool = True, api: bool = True, digest: str = _D1, notes: str | None = None) -> dict:
    payload: dict = {
        "schema_version": "azure-sbom-artifact/v1",
        "attested_at": "2026-05-01",
        "attested_by": "azure-devops-api-collection" if api else "platform team",
        "artifact": {"uri": "https://dev.azure.com/x/artifact", "digest_sha256": digest},
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


def _prov_payload(*, posture_all: bool = True, api: bool = True, digest: str = _D1, notes: str | None = None) -> dict:
    payload: dict = {
        "schema_version": "azure-provenance-artifact/v1",
        "attested_at": "2026-05-01",
        "attested_by": "azure-devops-api-collection" if api else "platform team",
        "artifact": {"uri": "https://dev.azure.com/x/artifact", "digest_sha256": digest},
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
# AZ-ARTSBOM-058
# --------------------------------------------------------------------------- #


def test_artsbom_058_missing(tmp_path: Path) -> None:
    assert az.eval_az_artsbom_058(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_artsbom_058_placeholder_blocked(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-sbom-artifact.json", _sbom_payload(notes="TODO confirm digest"))
    assert az.eval_az_artsbom_058(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_artsbom_058_placeholder_digest(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-sbom-artifact.json", _sbom_payload(digest="a" * 64))
    assert az.eval_az_artsbom_058(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_artsbom_058_incomplete_posture_self_attested(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-sbom-artifact.json", _sbom_payload(posture_all=False, api=True))
    assert az.eval_az_artsbom_058(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_artsbom_058_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-sbom-artifact.json", _sbom_payload(api=True))
    out = az.eval_az_artsbom_058(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method == EvidenceCollectionMethod.LIVE


def test_artsbom_058_self_attested_complete(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-sbom-artifact.json", _sbom_payload(api=False))
    out = az.eval_az_artsbom_058(_ctx(tmp_path))
    assert out.status == ControlStatus.SELF_ATTESTED


# --------------------------------------------------------------------------- #
# AZ-ARTPRV-059
# --------------------------------------------------------------------------- #


def test_artprv_059_missing(tmp_path: Path) -> None:
    assert az.eval_az_artprv_059(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_artprv_059_placeholder_blocked(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-provenance-artifact.json", _prov_payload(notes="REPLACE_ME"))
    assert az.eval_az_artprv_059(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_artprv_059_placeholder_digest(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-provenance-artifact.json", _prov_payload(digest="b" * 64))
    assert az.eval_az_artprv_059(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_artprv_059_incomplete_posture_self_attested(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-provenance-artifact.json", _prov_payload(posture_all=False, api=True))
    assert az.eval_az_artprv_059(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED


def test_artprv_059_api_pass(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-provenance-artifact.json", _prov_payload(api=True))
    out = az.eval_az_artprv_059(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method == EvidenceCollectionMethod.LIVE


def test_artprv_059_self_attested_complete(tmp_path: Path) -> None:
    _ev(tmp_path, "azure-provenance-artifact.json", _prov_payload(api=False))
    assert az.eval_az_artprv_059(_ctx(tmp_path)).status == ControlStatus.SELF_ATTESTED
