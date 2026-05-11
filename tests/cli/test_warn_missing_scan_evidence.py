"""Tests for the ``_warn_missing_scan_evidence`` UX banner in ``cli/common.py``.

The banner exists to close the UX gap where ``evaluate`` against a profile that
bundles ``K8S-*`` / ``IAC-TF-*`` / ``SAST-SEMGREP-*`` controls returns opaque
``manual-review-required`` for every one of them, because the operator did not
know that ``scan-k8s`` / ``scan-iac`` / ``scan-sast`` must run first to produce
the evidence file. These tests pin the three branches the banner cares about:
prefix match + missing evidence file + non-JSON stdout.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.cli.common import _warn_missing_scan_evidence


def _normalize(text: str) -> str:
    """Collapse all whitespace so Rich line-wrapping does not break substring assertions."""

    return " ".join(text.split())


def test_banner_fires_for_k8s_profile_when_evidence_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A profile containing ``K8S-*`` controls must surface the scan-k8s hint."""

    _warn_missing_scan_evidence(
        repo_root=tmp_path,
        control_ids={"K8S-PSS-001", "GOV-WAIV-014"},
        machine_stdout=False,
    )
    err = _normalize(capsys.readouterr().err)
    assert "scan-k8s" in err
    assert "manual-review-required" in err


def test_banner_fires_for_iac_terraform_profile_when_evidence_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A profile containing ``IAC-TF-*`` controls must surface the scan-iac hint."""

    _warn_missing_scan_evidence(
        repo_root=tmp_path,
        control_ids={"IAC-TF-001"},
        machine_stdout=False,
    )
    err = _normalize(capsys.readouterr().err)
    assert "scan-iac" in err


def test_banner_fires_for_sast_semgrep_profile_when_evidence_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A profile containing ``SAST-SEMGREP-*`` controls must surface the scan-sast hint."""

    _warn_missing_scan_evidence(
        repo_root=tmp_path,
        control_ids={"SAST-SEMGREP-064"},
        machine_stdout=False,
    )
    err = _normalize(capsys.readouterr().err)
    assert "scan-sast" in err


def test_banner_suppressed_when_machine_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """JSON-mode evaluate must not corrupt the parser stream with banner bytes.

    The banner goes to stderr today, but the function is conservative and skips
    entirely when ``machine_stdout=True`` so that any future wiring through stdout
    or downstream JSON consumers stays clean.
    """

    _warn_missing_scan_evidence(
        repo_root=tmp_path,
        control_ids={"K8S-PSS-001", "IAC-TF-001", "SAST-SEMGREP-064"},
        machine_stdout=True,
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "scan-k8s" not in captured.err
    assert "scan-iac" not in captured.err
    assert "scan-sast" not in captured.err


def test_banner_silent_when_evidence_file_already_exists(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Evidence file present -> no hint for that scan-* command.

    Other branches (missing evidence for a different scan-*) must still fire,
    so we exercise the mixed case: k8s evidence present, iac evidence absent.
    """

    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "k8s-baseline.json").write_text("{}", encoding="utf-8")

    _warn_missing_scan_evidence(
        repo_root=tmp_path,
        control_ids={"K8S-PSS-001", "IAC-TF-001"},
        machine_stdout=False,
    )
    err = _normalize(capsys.readouterr().err)
    assert "scan-k8s" not in err
    assert "scan-iac" in err


def test_banner_silent_for_profile_without_scan_controls(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A governance-only profile must not trigger any scan-* banner."""

    _warn_missing_scan_evidence(
        repo_root=tmp_path,
        control_ids={"GOV-SEC-001", "GOV-WAIV-014", "REL-CHANGE-012"},
        machine_stdout=False,
    )
    captured = capsys.readouterr()
    assert "scan-k8s" not in captured.err
    assert "scan-iac" not in captured.err
    assert "scan-sast" not in captured.err
