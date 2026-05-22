"""Coverage for ``application.profile_hints.build_profile_recommendation`` across repo scenarios."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application import profile_hints as ph


def _w(tmp_path: Path, rel: str, text: str = "{}\n") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_github_repo_with_evidence_and_node(tmp_path: Path) -> None:
    _w(tmp_path, ".github/workflows/ci.yml", "on: push\njobs: {}\n")
    _w(tmp_path, ".oss-policy-kit/evidence/branch-protection.json")
    _w(tmp_path, "package.json", '{"name": "x"}')
    _w(tmp_path, "package-lock.json")
    _w(tmp_path, "Dockerfile", "FROM scratch\n")
    rec = ph.build_profile_recommendation(tmp_path)
    assert rec.suggestions
    sig_ids = {s["id"] for s in rec.signals_detected}
    assert "github_actions_workflows" in sig_ids
    assert any("node" in s for s in sig_ids)


def test_python_no_lockfile_note(tmp_path: Path) -> None:
    _w(tmp_path, ".github/workflows/ci.yml", "on: push\n")
    _w(tmp_path, "pyproject.toml", "[project]\nname='x'\n")
    rec = ph.build_profile_recommendation(tmp_path)
    assert rec.suggestions


def test_azure_repo(tmp_path: Path) -> None:
    _w(tmp_path, "azure-pipelines.yml", "trigger: [main]\nsteps: []\n")
    _w(tmp_path, ".oss-policy-kit/evidence/azure-branch-policies.json")
    rec = ph.build_profile_recommendation(tmp_path)
    assert rec.suggestions
    assert any(s["profile_id"].startswith("azure-") for s in rec.suggestions)


def test_aws_repo(tmp_path: Path) -> None:
    _w(tmp_path, "buildspec.yml", "version: 0.2\n")
    _w(tmp_path, ".oss-policy-kit/evidence/aws-codebuild-project.json")
    rec = ph.build_profile_recommendation(tmp_path)
    assert rec.suggestions
    assert any(s["profile_id"].startswith("aws-") for s in rec.suggestions)


def test_multi_platform(tmp_path: Path) -> None:
    _w(tmp_path, ".github/workflows/ci.yml", "on: push\n")
    _w(tmp_path, "azure-pipelines.yml", "steps: []\n")
    rec = ph.build_profile_recommendation(tmp_path)
    assert rec.suggestions
    # multi-platform should surface notes
    assert rec.notes


def test_no_platform_fallback(tmp_path: Path) -> None:
    _w(tmp_path, "README.md", "# hi\n")
    rec = ph.build_profile_recommendation(tmp_path)
    # No CI platform detected -> conservative fallback recommendation still returned.
    assert isinstance(rec.suggestions, list)


def test_recommend_profiles_wrapper(tmp_path: Path) -> None:
    _w(tmp_path, ".github/workflows/ci.yml", "on: push\n")
    out = ph.recommend_profiles(tmp_path)
    assert isinstance(out, list)
    if out:
        assert isinstance(out[0], tuple) and len(out[0]) == 2


def test_based_on_helpers(tmp_path: Path) -> None:
    wf = [_w(tmp_path, ".github/workflows/release.yml", "on: release\n")]
    gh_ev = [_w(tmp_path, ".oss-policy-kit/evidence/branch-protection.json")]
    assert isinstance(ph._normalize_based_on(["github-level-1"], wf, gh_ev), list)
    az = [_w(tmp_path, "azure-pipelines.yml", "steps: []\n")]
    assert isinstance(ph._normalize_based_on_az(["azure-level-1"], az, []), list)
    assert isinstance(ph._normalize_based_on_aws(["aws-level-1"], True, []), list)
