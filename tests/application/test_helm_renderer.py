"""Tests for the v5.7.0 Helm template pre-pass (opt-in for ``scan-k8s``)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.k8s.helm_renderer import (
    helm_available,
    render_charts,
)
from oss_policy_kit.infrastructure.k8s.scanner import (
    EVIDENCE_FILENAME,
    render_evidence_payload,
    run_scan,
    write_evidence,
)


def test_helm_available_does_not_raise() -> None:
    """helm_available() must be safe to call even when helm is missing."""

    available, version = helm_available()
    assert isinstance(available, bool)
    if available:
        # version may be None on unusual helm builds, but the available branch
        # should never silently flip to False between the check and a later call.
        assert version is None or isinstance(version, str)


def test_render_charts_without_helm_returns_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When helm is not on PATH, render_charts must return a clean diagnostic."""

    # Force "helm not found" regardless of host state.
    monkeypatch.setattr(shutil, "which", lambda name: None)
    outcome = render_charts(tmp_path)
    assert outcome.available is False
    assert "helm" in outcome.diagnostic.lower()
    assert outcome.rendered_manifest_paths == []


def test_scan_k8s_helm_render_off_by_default(tmp_path: Path) -> None:
    """Without --helm-render, the scanner must not invoke helm_renderer."""

    outcome = run_scan(tmp_path)
    assert outcome.helm_render_attempted is False


def test_scan_k8s_helm_render_records_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With --helm-render but no helm installed, scanner must record the attempt and continue."""

    monkeypatch.setattr(shutil, "which", lambda name: None)
    outcome = run_scan(tmp_path, helm_render=True)
    assert outcome.helm_render_attempted is True
    assert outcome.helm_available is False
    assert outcome.status == "ok"  # scan still completes


def test_helm_render_writes_extended_evidence_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Evidence payload must surface the helm pre-pass fields."""

    monkeypatch.setattr(shutil, "which", lambda name: None)
    outcome = run_scan(tmp_path, helm_render=True)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    assert payload["helm_render_attempted"] is True
    assert payload["helm_available"] is False
    assert payload["helm_charts_discovered"] == []
    assert payload["helm_charts_rendered"] == []
    assert payload["helm_render_errors"] == []
