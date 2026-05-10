"""Tests for SEC-FUZZ-001 (fuzzing presence)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, ScorecardCheck
from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_fuzzing import (
    build_fuzzing_evaluators,
    eval_sec_fuzz_001,
)
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus


def _ctx(repo_root: Path, scorecard: Any | None = None) -> SimpleNamespace:
    return SimpleNamespace(repo_root=repo_root, scorecard=scorecard)


# ---------------------------------------------------------------------------
# Catalog + registry wiring
# ---------------------------------------------------------------------------


def test_sec_fuzz_001_in_catalog() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert "SEC-FUZZ-001" in catalog
    spec = catalog["SEC-FUZZ-001"]
    assert spec.lifecycle == "experimental"
    assert spec.assurance == "signal"
    assert spec.category == "vulnerability_management"


def test_sec_fuzz_001_registered_in_global_registry() -> None:
    assert "SEC-FUZZ-001" in EVALUATOR_REGISTRY
    assert build_fuzzing_evaluators().keys() == {"SEC-FUZZ-001"}


@pytest.mark.parametrize(
    "profile_id",
    [
        "github-level-3",
        "azure-level-3",
        "aws-level-3",
        "github-release-hardening-3",
        "azure-release-hardening-3",
        "aws-release-hardening-3",
    ],
)
def test_sec_fuzz_001_bundled_in_level_3_profiles(profile_id: str) -> None:
    spec = load_profile_by_id(bundled_kit_root(), profile_id)
    assert "SEC-FUZZ-001" in spec.control_ids


# ---------------------------------------------------------------------------
# Detection paths
# ---------------------------------------------------------------------------


def test_scorecard_fuzzing_score_above_threshold_passes(tmp_path: Path) -> None:
    bundle = ScorecardBundle(checks=[ScorecardCheck(name="Fuzzing", score=8)])
    out = eval_sec_fuzz_001(_ctx(tmp_path, scorecard=bundle))
    assert out.status is ControlStatus.PASS
    assert "Scorecard" in out.reason


def test_scorecard_fuzzing_score_below_threshold_falls_through(tmp_path: Path) -> None:
    bundle = ScorecardBundle(checks=[ScorecardCheck(name="Fuzzing", score=5)])
    out = eval_sec_fuzz_001(_ctx(tmp_path, scorecard=bundle))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_fuzz_directory_passes(tmp_path: Path) -> None:
    fuzz_dir = tmp_path / "fuzz"
    fuzz_dir.mkdir()
    (fuzz_dir / "harness.py").write_text("placeholder", encoding="utf-8")
    out = eval_sec_fuzz_001(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS
    assert "fuzz" in out.reason.lower()


def test_atheris_content_marker_passes(tmp_path: Path) -> None:
    (tmp_path / "test_fuzzer.py").write_text(
        "import atheris\n\ndef TestOneInput(data):\n    pass\n",
        encoding="utf-8",
    )
    out = eval_sec_fuzz_001(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS
    assert "atheris" in out.reason.lower()


def test_no_fuzz_signal_returns_manual_review(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    out = eval_sec_fuzz_001(_ctx(tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "OSS-Fuzz" in out.remediation or "atheris" in out.remediation


def test_skip_dirs_are_not_scanned(tmp_path: Path) -> None:
    """A noisy folder like node_modules must not produce a false PASS."""

    nm = tmp_path / "node_modules" / "x"
    nm.mkdir(parents=True)
    (nm / "atheris.txt").write_text("atheris is just a string here", encoding="utf-8")
    out = eval_sec_fuzz_001(_ctx(tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED
