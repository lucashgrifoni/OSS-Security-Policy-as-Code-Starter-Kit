"""emit-insights subcommand: OpenSSF Security Insights 1.0 YAML emission (PR-8)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oss_policy_kit.cli.emit_insights import (
    _build_insights_document,
    _validate_insights_structure,
)


def _seed_repo(
    tmp_path: Path,
    *,
    security: bool = True,
    contributing: bool = True,
    codeowners: bool = True,
    dependabot: bool = True,
    security_email: str | None = "security@example.com",
) -> Path:
    if security:
        body = "# Security Policy\n\nReport to "
        if security_email:
            body += security_email
        (tmp_path / "SECURITY.md").write_text(body + "\n", encoding="utf-8")
    if contributing:
        (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    if codeowners:
        gh = tmp_path / ".github"
        gh.mkdir(exist_ok=True)
        (gh / "CODEOWNERS").write_text("* @maintainer\n", encoding="utf-8")
    if dependabot:
        gh = tmp_path / ".github"
        gh.mkdir(exist_ok=True)
        (gh / "dependabot.yml").write_text("version: 2\nupdates: []\n", encoding="utf-8")
    return tmp_path


def test_build_document_has_required_top_level(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    doc = _build_insights_document(tmp_path)
    assert "header" in doc
    assert "project-lifecycle" in doc
    assert doc["header"]["schema-version"] == "1.0.0"
    assert "last-updated" in doc["header"]


def test_build_document_includes_security_policy_when_present(tmp_path: Path) -> None:
    _seed_repo(tmp_path, security_email="alice@example.com")
    doc = _build_insights_document(tmp_path)
    vr = doc.get("vulnerability-reporting")
    assert isinstance(vr, dict)
    assert vr.get("accepts-vulnerability-reports") is True
    assert vr.get("email-contact") == "alice@example.com"
    sc = doc.get("security-contacts")
    assert isinstance(sc, list) and any(c.get("value") == "alice@example.com" for c in sc)


def test_build_document_omits_security_section_when_no_security_md(tmp_path: Path) -> None:
    _seed_repo(tmp_path, security=False)
    doc = _build_insights_document(tmp_path)
    assert "vulnerability-reporting" not in doc
    assert "security-contacts" not in doc


def test_build_document_includes_contribution_policy_when_contributing_present(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    doc = _build_insights_document(tmp_path)
    cp = doc.get("contribution-policy")
    assert isinstance(cp, dict)
    assert cp.get("accepts-pull-requests") is True


def test_build_document_includes_dependency_policy_when_dependabot_present(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    doc = _build_insights_document(tmp_path)
    deps = doc.get("dependencies")
    assert isinstance(deps, dict)
    assert "env-dependencies-policy" in deps
    assert "DEP-UPDATE-001" in deps["env-dependencies-policy"]["comment"]


def test_build_document_omits_dependency_section_when_no_automation(tmp_path: Path) -> None:
    _seed_repo(tmp_path, dependabot=False)
    doc = _build_insights_document(tmp_path)
    assert "dependencies" not in doc


def test_validate_structure_accepts_minimal_doc() -> None:
    doc = {
        "header": {"schema-version": "1.0.0", "last-updated": "2026-05-18T00:00:00Z"},
        "project-lifecycle": {"status": "active"},
    }
    assert _validate_insights_structure(doc) == []


def test_validate_structure_rejects_missing_top_level() -> None:
    errs = _validate_insights_structure({"header": {"schema-version": "1.0.0", "last-updated": "x"}})
    assert any("project-lifecycle" in e for e in errs)


def test_validate_structure_rejects_missing_header_required_field() -> None:
    errs = _validate_insights_structure({"header": {}, "project-lifecycle": {"status": "active"}})
    assert any("schema-version" in e for e in errs)


def test_validate_structure_rejects_wrong_schema_version() -> None:
    doc = {
        "header": {"schema-version": "0.9", "last-updated": "x"},
        "project-lifecycle": {"status": "active"},
    }
    errs = _validate_insights_structure(doc)
    assert any("schema-version" in e for e in errs)


def test_yaml_round_trip_parses_back(tmp_path: Path) -> None:
    """Sanity: the emitted YAML round-trips through pyyaml."""
    _seed_repo(tmp_path)
    doc = _build_insights_document(tmp_path)
    text = yaml.safe_dump(doc, sort_keys=False)
    reparsed = yaml.safe_load(text)
    assert reparsed["header"]["schema-version"] == "1.0.0"
    assert reparsed["project-lifecycle"]["status"] == "active"


@pytest.mark.parametrize(
    "dep_file",
    ["dependabot.yml", "dependabot.yaml"],
)
def test_dependency_detection_dependabot_variants(tmp_path: Path, dep_file: str) -> None:
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / dep_file).write_text("version: 2\n", encoding="utf-8")
    doc = _build_insights_document(tmp_path)
    assert "dependencies" in doc


def test_dependency_detection_renovate(tmp_path: Path) -> None:
    (tmp_path / "renovate.json").write_text("{}", encoding="utf-8")
    doc = _build_insights_document(tmp_path)
    assert "dependencies" in doc
