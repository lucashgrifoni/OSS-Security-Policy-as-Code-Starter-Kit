"""Evidence scaffold templates must validate against bundled JSON Schemas."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from tests.conftest import ROOT

from oss_policy_kit.application.evidence_scaffold import (
    scaffold_attested_date_yyyy_mm_dd,
    scaffold_evidence_files,
)

_SCHEMA_DIR = ROOT / "reports" / "schema"
_SCHEMA_BY_FILENAME = {
    "branch-protection.json": "evidence-branch-protection.schema.json",
    "github-rulesets.json": "evidence-github-rulesets.schema.json",
    "github-environment-protection.json": "evidence-github-environment-protection.schema.json",
    "github-secret-scanning.json": "evidence-github-secret-scanning.schema.json",
    "azure-branch-policies.json": "evidence-azure-branch-policies.schema.json",
    "azure-pipeline-governance.json": "evidence-azure-pipeline-governance.schema.json",
    "azure-sbom-artifact.json": "evidence-azure-sbom-artifact.schema.json",
    "azure-provenance-artifact.json": "evidence-azure-provenance-artifact.schema.json",
    "aws-codebuild-project.json": "evidence-aws-codebuild-project.schema.json",
    "aws-codepipeline.json": "evidence-aws-codepipeline.schema.json",
    "aws-sbom-artifact.json": "evidence-aws-sbom-artifact.schema.json",
    "aws-provenance-artifact.json": "evidence-aws-provenance-artifact.schema.json",
    "org-mfa-posture.json": "evidence-org-mfa-posture.schema.json",
}


@pytest.mark.parametrize("platform", ["github", "azure", "aws"])
def test_scaffold_evidence_validates_against_schema(tmp_path: Path, platform: str) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    outcome = scaffold_evidence_files(repo, platform, force=False)
    json_paths = [p for p in outcome.created if p.suffix == ".json"]
    assert json_paths
    for path in json_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        schema_rel = _SCHEMA_BY_FILENAME[path.name]
        schema = json.loads((_SCHEMA_DIR / schema_rel).read_text(encoding="utf-8-sig"))
        Draft202012Validator(schema).validate(data)


def test_scaffold_skips_existing_without_force(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    first = scaffold_evidence_files(repo, "github", force=False)
    assert first.created
    assert not first.skipped

    second = scaffold_evidence_files(repo, "github", force=False)
    assert not second.created
    assert second.skipped
    marker = "USER_EDITED_UNIQUE"
    bp = repo / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    text = bp.read_text(encoding="utf-8")
    bp.write_text(text.replace("REPLACE_ME", marker), encoding="utf-8")

    third = scaffold_evidence_files(repo, "github", force=False)
    assert marker in bp.read_text(encoding="utf-8")
    assert bp in third.skipped


def test_scaffold_overwrites_with_force(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    scaffold_evidence_files(repo, "github", force=False)
    bp = repo / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    bp.write_text('{"corrupted": true}', encoding="utf-8")

    out = scaffold_evidence_files(repo, "github", force=True)
    assert bp in out.overwritten
    data = json.loads(bp.read_text(encoding="utf-8"))
    assert "schema_version" in data
    assert data.get("corrupted") is None


def test_scaffold_attested_date_follows_injected_today(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    fixed = date(2030, 1, 15)
    outcome = scaffold_evidence_files(repo, "github", force=False, today=fixed)
    for p in outcome.created:
        if p.suffix != ".json":
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        assert doc.get("attested_at") == "2030-01-15"


def test_scaffold_attested_date_helper_uses_passed_date() -> None:
    assert scaffold_attested_date_yyyy_mm_dd(today=date(2020, 5, 1)) == "2020-05-01"


def test_azure_scaffold_includes_wif_proof_fields(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    scaffold_evidence_files(repo, "azure", force=False)
    payload = json.loads(
        (repo / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json").read_text(encoding="utf-8")
    )
    service_connections = payload.get("service_connections", [])
    assert isinstance(service_connections, list) and service_connections
    wif = next(
        (
            item
            for item in service_connections
            if isinstance(item, dict) and item.get("authentication") == "workload_identity_federation"
        ),
        None,
    )
    assert isinstance(wif, dict)
    assert wif.get("federation_subject")
    assert wif.get("issuer_url")
    assert wif.get("audience")


def test_org_mfa_scaffold_sets_enforcement_scope_all_members(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    scaffold_evidence_files(repo, "github", force=False)
    payload = json.loads((repo / ".oss-policy-kit" / "evidence" / "org-mfa-posture.json").read_text(encoding="utf-8"))
    assert payload.get("enforcement_scope") == "all_members"
