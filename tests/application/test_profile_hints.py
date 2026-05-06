"""Tests for profile recommendation heuristics."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from tests.conftest import ROOT

from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.application.profile_hints import build_profile_recommendation

_AZURE_FIXTURE = ROOT / "tests" / "fixtures" / "repositories" / "azure-hardened-target"
_AWS_FIXTURE = ROOT / "tests" / "fixtures" / "repositories" / "aws-hardened-target"


def test_recommendation_includes_signals_for_hardened_example(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: push\njobs: {x: {runs-on: ubuntu-latest, steps: [{run: echo hi}]}}\n", encoding="utf-8"
    )
    rec = build_profile_recommendation(tmp_path)
    ids = {s["id"] for s in rec.signals_detected}
    assert "github_actions_workflows" in ids
    assert any(s["profile_id"].startswith("github-level") for s in rec.suggestions)


def test_recommendation_suggests_release_hardening_when_github_evidence_present(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "branch-protection.json").write_text(json.dumps({"schema_version": "x"}), encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    pids = [s["profile_id"] for s in rec.suggestions]
    assert any(p.startswith("github-release-hardening") for p in pids)
    assert any(s["id"] == "github_evidence_json_files" for s in rec.signals_detected)


def test_recommendation_conservative_note_when_empty_repo(tmp_path: Path) -> None:
    rec = build_profile_recommendation(tmp_path)
    assert rec.suggestions[0]["profile_id"] == "github-level-1"
    assert rec.notes


def test_recommend_profile_readme_and_app_py_do_not_trigger_github_workflow_signal(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    signal_ids = {s["id"] for s in rec.signals_detected}
    assert "github_actions_workflows" not in signal_ids
    suggested = [s["profile_id"] for s in rec.suggestions]
    assert not any(p.startswith("github-release-hardening") for p in suggested)


def test_azure_with_pipelines_and_scaffolded_evidence_suggests_azure_release_not_github(tmp_path: Path) -> None:
    """Regression: Azure evidence JSON must not imply GitHub release-hardening."""

    if not _AZURE_FIXTURE.is_dir():
        pytest.skip("azure-hardened-target fixture missing")
    dest = tmp_path / "azure-with-ev"
    shutil.copytree(_AZURE_FIXTURE, dest)
    scaffold_evidence_files(dest, "azure", force=True)
    rec = build_profile_recommendation(dest)
    pids = [s["profile_id"] for s in rec.suggestions]
    assert any(p.startswith("azure-release-hardening") for p in pids)
    assert not any(p.startswith("github-release-hardening") for p in pids)
    assert any(s["id"] == "azure_evidence_json_files" for s in rec.signals_detected)


def test_aws_with_buildspec_and_scaffolded_evidence_suggests_aws_release_not_github(tmp_path: Path) -> None:
    if not _AWS_FIXTURE.is_dir():
        pytest.skip("aws-hardened-target fixture missing")
    dest = tmp_path / "aws-with-ev"
    shutil.copytree(_AWS_FIXTURE, dest)
    scaffold_evidence_files(dest, "aws", force=True)
    rec = build_profile_recommendation(dest)
    pids = [s["profile_id"] for s in rec.suggestions]
    assert any(p.startswith("aws-release-hardening") for p in pids)
    assert not any(p.startswith("github-release-hardening") for p in pids)
    assert any(s["id"] == "aws_evidence_json_files" for s in rec.signals_detected)


def test_empty_evidence_dir_azure_repo_does_not_suggest_github_release_hardening(tmp_path: Path) -> None:
    (tmp_path / ".oss-policy-kit" / "evidence").mkdir(parents=True)
    (tmp_path / "azure-pipelines.yml").write_text("trigger: [main]\npool: {vmImage: ubuntu-latest}\n", encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    pids = [s["profile_id"] for s in rec.suggestions]
    assert not any(p.startswith("github-release-hardening") for p in pids)
    assert any(p.startswith("azure-release-hardening") for p in pids)


def test_empty_evidence_dir_aws_repo_does_not_suggest_github_release_hardening(tmp_path: Path) -> None:
    (tmp_path / ".oss-policy-kit" / "evidence").mkdir(parents=True)
    (tmp_path / "buildspec.yml").write_text(
        "version: 0.2\nphases: {build: {commands: ['echo ok']}}\n", encoding="utf-8"
    )
    rec = build_profile_recommendation(tmp_path)
    pids = [s["profile_id"] for s in rec.suggestions]
    assert not any(p.startswith("github-release-hardening") for p in pids)
    assert any(p.startswith("aws-release-hardening") for p in pids)


def test_recommend_profile_detects_nodejs(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "test"}', encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    ids = [s["id"] for s in rec.signals_detected]
    assert "node_js" in ids


def test_recommend_profile_detects_python_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\nversion="0.1.0"\n', encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    ids = [s["id"] for s in rec.signals_detected]
    assert "python_pyproject" in ids


def test_recommend_profile_dockerfile_suggests_level_2(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    assert rec.suggestions[0]["profile_id"] == "github-level-2"


def test_azure_nested_pipelines_dir_generates_azure_signal(tmp_path: Path) -> None:
    """pipelines/azure/ci.yml must produce an Azure signal and not fall back to github-level-1."""
    nested = tmp_path / "pipelines" / "azure"
    nested.mkdir(parents=True)
    (nested / "ci.yml").write_text("trigger: [main]\npool: {vmImage: ubuntu-latest}\n", encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    ids = {s["id"] for s in rec.signals_detected}
    assert "azure_pipelines_yaml" in ids, "Expected azure_pipelines_yaml signal for pipelines/azure/ci.yml"
    pids = [s["profile_id"] for s in rec.suggestions]
    assert any(p.startswith("azure") for p in pids), "Expected an Azure suggestion"
    assert pids[0] != "github-level-1", "Must not fall back to github-level-1 for an Azure repo"


def test_azure_dot_azure_pipelines_dir_generates_azure_signal(tmp_path: Path) -> None:
    """.azure-pipelines/ci.yml must produce an Azure signal and not fall back to github-level-1."""
    nested = tmp_path / ".azure-pipelines"
    nested.mkdir(parents=True)
    (nested / "ci.yml").write_text("trigger: [main]\npool: {vmImage: ubuntu-latest}\n", encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    ids = {s["id"] for s in rec.signals_detected}
    assert "azure_pipelines_yaml" in ids, "Expected azure_pipelines_yaml signal for .azure-pipelines/ci.yml"
    pids = [s["profile_id"] for s in rec.suggestions]
    assert any(p.startswith("azure") for p in pids), "Expected an Azure suggestion"
    assert pids[0] != "github-level-1", "Must not fall back to github-level-1 for an Azure repo"


def test_azure_nested_yaml_extension_generates_azure_signal(tmp_path: Path) -> None:
    """pipelines/azure/ci.yaml (yaml extension) must also produce Azure signal."""
    nested = tmp_path / "pipelines" / "azure"
    nested.mkdir(parents=True)
    (nested / "ci.yaml").write_text("trigger: [main]\npool: {vmImage: ubuntu-latest}\n", encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    ids = {s["id"] for s in rec.signals_detected}
    assert "azure_pipelines_yaml" in ids


def test_github_workflows_plus_github_evidence_still_suggests_github_release_hardening(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: push\njobs: {a: {runs-on: ubuntu-latest, steps: [{run: 'echo x'}]}}\n", encoding="utf-8"
    )
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "github-rulesets.json").write_text(json.dumps({"schema_version": "github-rulesets/v1"}), encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    pids = [s["profile_id"] for s in rec.suggestions]
    assert any(p.startswith("github-release-hardening") for p in pids)
    assert "github_actions_workflows" in {s["id"] for s in rec.signals_detected}
    assert "github_evidence_json_files" in {s["id"] for s in rec.signals_detected}


def test_github_workflows_without_github_evidence_starts_with_level_1(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    workflow_yaml = "on: push\njobs: {x: {runs-on: ubuntu-latest, steps: [{run: echo hi}]}}\n"
    (wf / "ci.yml").write_text(workflow_yaml, encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    assert rec.suggestions[0]["profile_id"] == "github-level-1"


def test_release_hardening_2_rationale_warns_about_unfilled_evidence_templates(tmp_path: Path) -> None:
    """Every ``release-hardening-2`` rationale must explicitly tell the user to verify that the
    evidence JSONs are not still scaffold templates. Removing this hint silently re-introduces
    a UX problem where ``recommend-profile`` would suggest a release-hardening-2 profile over
    unfilled placeholders, which then surfaced as ``manual-review-required`` in evaluate. The
    hint travels with the recommendation, so users see it both in docs and in the CLI output.
    """

    expected_warning = "verify evidence JSONs are filled, not templates"

    # GitHub: workflow + evidence template triggers github-release-hardening-2.
    wf = tmp_path / "gh" / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "on: push\njobs: {a: {runs-on: ubuntu-latest, steps: [{run: 'echo x'}]}}\n",
        encoding="utf-8",
    )
    ev = tmp_path / "gh" / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "branch-protection.json").write_text(json.dumps({"schema_version": "x"}), encoding="utf-8")
    rec = build_profile_recommendation(tmp_path / "gh")
    rh2 = next(s for s in rec.suggestions if s["profile_id"] == "github-release-hardening-2")
    assert expected_warning in rh2["rationale"], rh2["rationale"]

    # Azure: pipeline yaml + evidence template triggers azure-release-hardening-2.
    az = tmp_path / "az"
    az.mkdir()
    (az / "azure-pipelines.yml").write_text("trigger: [main]\npool: {vmImage: ubuntu-latest}\n", encoding="utf-8")
    az_ev = az / ".oss-policy-kit" / "evidence"
    az_ev.mkdir(parents=True)
    (az_ev / "azure-branch-policies.json").write_text(json.dumps({"schema_version": "x"}), encoding="utf-8")
    rec_az = build_profile_recommendation(az)
    rh2_az = next(s for s in rec_az.suggestions if s["profile_id"] == "azure-release-hardening-2")
    assert expected_warning in rh2_az["rationale"], rh2_az["rationale"]

    # AWS: buildspec + evidence template triggers aws-release-hardening-2.
    aws = tmp_path / "aws"
    aws.mkdir()
    (aws / "buildspec.yml").write_text("version: 0.2\nphases: {build: {commands: ['echo ok']}}\n", encoding="utf-8")
    aws_ev = aws / ".oss-policy-kit" / "evidence"
    aws_ev.mkdir(parents=True)
    (aws_ev / "aws-codebuild-project.json").write_text(json.dumps({"schema_version": "x"}), encoding="utf-8")
    rec_aws = build_profile_recommendation(aws)
    rh2_aws = next(s for s in rec_aws.suggestions if s["profile_id"] == "aws-release-hardening-2")
    assert expected_warning in rh2_aws["rationale"], rh2_aws["rationale"]
