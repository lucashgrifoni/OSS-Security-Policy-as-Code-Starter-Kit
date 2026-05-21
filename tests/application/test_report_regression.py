"""Regression coverage for report shape and conservative workflow behavior."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE, INVALID_WORKFLOW_FIXTURE, ROOT

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict, write_markdown_report
from oss_policy_kit.domain.models import ControlStatus

GOLDEN_SUMMARY = ROOT / "tests" / "fixtures" / "golden" / "github_level_1_hardened.summary.json"
GOLDEN_REPORT_PROJECTION = ROOT / "tests" / "fixtures" / "golden" / "github_level_1_hardened.report-projection.json"
GOLDEN_MARKDOWN_CONTROLS = ROOT / "tests" / "fixtures" / "golden" / "github_level_1_hardened.controls-table.md"


def _markdown_summary_and_controls(text: str) -> list[str]:
    lines = text.splitlines()
    out: list[str] = []
    in_summary = False
    in_controls = False
    for line in lines:
        if line == "## Summary":
            in_summary = True
            continue
        if line == "## Controls":
            in_summary = False
            in_controls = True
        if line == "## Detail":
            break
        if (in_summary or in_controls) and line.startswith("| "):
            out.append(line)
    return out


def test_hardened_github_level_1_summary_matches_golden() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    expected = json.loads(GOLDEN_SUMMARY.read_text(encoding="utf-8"))
    assert report.profile_id == expected["profile_id"]
    assert dict(report.summary_by_status) == expected["summary_by_status"]


def test_hardened_github_level_1_report_projection_matches_golden() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    payload = report_to_dict(report)
    projection = {
        "profile_id": payload["profile_id"],
        "profile_title": payload["profile_title"],
        "summary_by_status": payload["summary_by_status"],
        "result_status_by_control": {row["control_id"]: row["status"] for row in payload["results"]},
        "result_lifecycle_by_control": {row["control_id"]: row["lifecycle"] for row in payload["results"]},
    }
    expected = json.loads(GOLDEN_REPORT_PROJECTION.read_text(encoding="utf-8"))
    assert projection == expected


def test_vulnerable_markdown_contains_summary_sections(tmp_path: Path) -> None:
    """Lightweight Markdown regression without brittle full-file golden files."""

    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_VULNERABLE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    md_path = tmp_path / "r.md"
    write_markdown_report(report, md_path)
    text = md_path.read_text(encoding="utf-8")
    assert "## Summary" in text
    assert "## Controls" in text
    assert "| `fail` |" in text or "`fail`" in text


def test_hardened_markdown_summary_and_controls_match_golden(tmp_path: Path) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    md_path = tmp_path / "report.md"
    write_markdown_report(report, md_path)
    extracted = _markdown_summary_and_controls(md_path.read_text(encoding="utf-8"))
    expected = GOLDEN_MARKDOWN_CONTROLS.read_text(encoding="utf-8").splitlines()
    assert extracted == expected


def test_invalid_workflow_conservative_structural_controls() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=INVALID_WORKFLOW_FIXTURE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    statuses = {r.control_id: r.status for r in report.results}
    assert statuses["CI-PERM-006"] == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert statuses["CI-LEAST-009"] == ControlStatus.MANUAL_REVIEW_REQUIRED
    pin = next(r for r in report.results if r.control_id == "CI-PIN-008")
    assert pin.status == ControlStatus.PASS
    assert pin.confidence == "low"
