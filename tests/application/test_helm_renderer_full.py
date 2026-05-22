"""Branch-coverage tests for the Helm pre-pass (helm CLI fully mocked).

These complement ``test_helm_renderer.py`` (which covers the helm-absent
path) by exercising the helm-present branches: discovery, per-chart render
success, and each render-failure mode — without requiring a real ``helm``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure.k8s import helm_renderer as hr


class _FakeProc:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _make_chart(root: Path, rel: str) -> Path:
    chart_dir = root / rel
    chart_dir.mkdir(parents=True, exist_ok=True)
    (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 0.1.0\n", encoding="utf-8")
    return chart_dir


# --------------------------------------------------------------------------- #
# helm_available
# --------------------------------------------------------------------------- #


def test_helm_available_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hr.shutil, "which", lambda _n: None)
    assert hr.helm_available() == (False, None)


def test_helm_available_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hr.shutil, "which", lambda _n: "/usr/bin/helm")
    monkeypatch.setattr(hr.subprocess, "run", lambda *a, **k: _FakeProc(stdout="v3.14.0\n"))
    assert hr.helm_available() == (True, "v3.14.0")


def test_helm_available_blank_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hr.shutil, "which", lambda _n: "/usr/bin/helm")
    monkeypatch.setattr(hr.subprocess, "run", lambda *a, **k: _FakeProc(stdout="  "))
    assert hr.helm_available() == (True, None)


def test_helm_available_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hr.shutil, "which", lambda _n: "/usr/bin/helm")
    monkeypatch.setattr(hr.subprocess, "run", lambda *a, **k: _FakeProc(returncode=1))
    assert hr.helm_available() == (False, None)


def test_helm_available_swallows_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hr.shutil, "which", lambda _n: "/usr/bin/helm")

    def _boom(*_a: Any, **_k: Any) -> None:
        raise OSError("boom")

    monkeypatch.setattr(hr.subprocess, "run", _boom)
    assert hr.helm_available() == (False, None)


# --------------------------------------------------------------------------- #
# _discover_charts / _chart_dir_if_valid
# --------------------------------------------------------------------------- #


def test_discover_charts_finds_and_skips(tmp_path: Path) -> None:
    _make_chart(tmp_path, "app")
    _make_chart(tmp_path, "node_modules/vendored")  # in skip dir
    charts = hr._discover_charts(tmp_path)
    rels = [c.relative_to(tmp_path.resolve()).as_posix() for c in charts]
    assert rels == ["app"]


def test_discover_charts_dedupes(tmp_path: Path) -> None:
    _make_chart(tmp_path, "app")
    # Two overlapping globs both match the same Chart.yaml.
    charts = hr._discover_charts(tmp_path, include_globs=("**/Chart.yaml", "app/Chart.yaml"))
    assert len(charts) == 1


def test_chart_dir_if_valid_rejects_non_chart(tmp_path: Path) -> None:
    other = tmp_path / "values.yaml"
    other.write_text("x", encoding="utf-8")
    assert hr._chart_dir_if_valid(other, tmp_path, set()) is None


def test_chart_dir_if_valid_rejects_outside_root(tmp_path: Path) -> None:
    inside = _make_chart(tmp_path / "repo", "app")
    other_root = tmp_path / "elsewhere"
    other_root.mkdir()
    # Chart.yaml resolves outside other_root -> ValueError path -> None.
    assert hr._chart_dir_if_valid(inside / "Chart.yaml", other_root, set()) is None


# --------------------------------------------------------------------------- #
# _render_one_chart
# --------------------------------------------------------------------------- #


def test_render_one_chart_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    chart = _make_chart(repo, "app")
    tmp_root = tmp_path / "out"
    tmp_root.mkdir()
    outcome = hr.HelmRenderOutcome(available=True)

    def _run(argv: list[str], **_k: Any) -> _FakeProc:
        # Simulate helm writing a manifest under the chosen --output-dir.
        out_dir = Path(argv[argv.index("--output-dir") + 1])
        (out_dir / "app").mkdir(parents=True, exist_ok=True)
        (out_dir / "app" / "deploy.yaml").write_text("kind: Deployment\n", encoding="utf-8")
        # A directory whose name matches the glob must be skipped (not a file).
        (out_dir / "app" / "nested.yaml").mkdir(parents=True, exist_ok=True)
        return _FakeProc(returncode=0)

    monkeypatch.setattr(hr.subprocess, "run", _run)
    hr._render_one_chart(chart.resolve(), repo, tmp_root, "/usr/bin/helm", 60, outcome)
    assert outcome.charts_rendered == ["app"]
    assert len(outcome.rendered_manifest_paths) == 1  # dir-named .yaml excluded


def test_render_one_chart_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    chart = _make_chart(repo, "app")
    tmp_root = tmp_path / "out"
    tmp_root.mkdir()
    outcome = hr.HelmRenderOutcome(available=True)

    def _to(*_a: Any, **_k: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="helm", timeout=60)

    monkeypatch.setattr(hr.subprocess, "run", _to)
    hr._render_one_chart(chart.resolve(), repo, tmp_root, "/usr/bin/helm", 60, outcome)
    assert outcome.render_errors and "timed out" in outcome.render_errors[0]["error"]


def test_render_one_chart_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    chart = _make_chart(repo, "app")
    tmp_root = tmp_path / "out"
    tmp_root.mkdir()
    outcome = hr.HelmRenderOutcome(available=True)

    def _boom(*_a: Any, **_k: Any) -> None:
        raise OSError("exec format error")

    monkeypatch.setattr(hr.subprocess, "run", _boom)
    hr._render_one_chart(chart.resolve(), repo, tmp_root, "/usr/bin/helm", 60, outcome)
    assert outcome.render_errors[0]["error"] == "exec format error"


def test_render_one_chart_nonzero_with_stderr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    chart = _make_chart(repo, "app")
    tmp_root = tmp_path / "out"
    tmp_root.mkdir()
    outcome = hr.HelmRenderOutcome(available=True)
    monkeypatch.setattr(
        hr.subprocess, "run", lambda *a, **k: _FakeProc(stderr="line1\nrender failed: bad template", returncode=1)
    )
    hr._render_one_chart(chart.resolve(), repo, tmp_root, "/usr/bin/helm", 60, outcome)
    assert outcome.render_errors[0]["error"] == "render failed: bad template"


def test_render_one_chart_nonzero_no_stderr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    chart = _make_chart(repo, "app")
    tmp_root = tmp_path / "out"
    tmp_root.mkdir()
    outcome = hr.HelmRenderOutcome(available=True)
    monkeypatch.setattr(hr.subprocess, "run", lambda *a, **k: _FakeProc(stderr="", returncode=1))
    hr._render_one_chart(chart.resolve(), repo, tmp_root, "/usr/bin/helm", 60, outcome)
    assert outcome.render_errors[0]["error"] == "helm exited non-zero"


# --------------------------------------------------------------------------- #
# render_charts (helm present)
# --------------------------------------------------------------------------- #


def test_render_charts_no_charts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hr, "helm_available", lambda: (True, "v3.14.0"))
    outcome = hr.render_charts(tmp_path)
    assert outcome.available is True
    assert outcome.charts_discovered == []
    assert "No Chart.yaml" in outcome.diagnostic


def test_render_charts_renders_each(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _make_chart(tmp_path, "app")
    monkeypatch.setattr(hr, "helm_available", lambda: (True, "v3.14.0"))
    monkeypatch.setattr(hr.shutil, "which", lambda _n: "/usr/bin/helm")

    def _run(argv: list[str], **_k: Any) -> _FakeProc:
        out_dir = Path(argv[argv.index("--output-dir") + 1])
        (out_dir / "app").mkdir(parents=True, exist_ok=True)
        (out_dir / "app" / "svc.yml").write_text("kind: Service\n", encoding="utf-8")
        return _FakeProc(returncode=0)

    monkeypatch.setattr(hr.subprocess, "run", _run)
    outcome = hr.render_charts(tmp_path)
    assert outcome.charts_rendered == ["app"]
    assert outcome.rendered_manifest_paths
    assert outcome.tmp_root is not None
    import shutil as _sh

    _sh.rmtree(outcome.tmp_root, ignore_errors=True)


def test_render_charts_no_manifests_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _make_chart(tmp_path, "app")
    monkeypatch.setattr(hr, "helm_available", lambda: (True, "v3.14.0"))
    monkeypatch.setattr(hr.shutil, "which", lambda _n: "/usr/bin/helm")
    # Returns 0 but writes nothing -> rendered, but no manifest files, no errors.
    monkeypatch.setattr(hr.subprocess, "run", lambda *a, **k: _FakeProc(returncode=0))
    outcome = hr.render_charts(tmp_path)
    assert "without producing manifest files" in outcome.diagnostic
    if outcome.tmp_root is not None:
        import shutil as _sh

        _sh.rmtree(outcome.tmp_root, ignore_errors=True)
