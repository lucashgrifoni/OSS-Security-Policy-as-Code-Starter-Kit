"""Opt-in Helm chart pre-pass for ``scan-k8s`` (v5.7.0).

When ``scan-k8s`` is invoked with ``--helm-render``, this module:

1. Discovers Helm charts by walking for ``Chart.yaml`` files under the
   target (skipping vendored / cache directories).
2. For each chart, invokes the system ``helm`` CLI with
   ``helm template <chart> --output-dir <tmp>`` (no network / no install),
   capturing rendered manifests on disk.
3. Returns the list of rendered manifest paths so the standard K8s scanner
   can index them alongside the regular ``*.yaml`` discovery.

The renderer is **best-effort by design**: if the ``helm`` binary is not
on ``PATH``, the renderer logs a diagnostic and returns no rendered
manifests — the scan continues without crashing. If a single chart fails
to render (missing dependencies, template error), that chart is recorded
in the diagnostics list and the others continue.

No network access is required: ``helm template`` operates on the chart
sources already present in the clone. Subchart ``dependencies`` declared
in ``Chart.yaml`` are skipped (operators can run ``helm dependency build``
locally before scanning if they want subchart coverage).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

_SKIP_DIRS: Final[frozenset[str]] = frozenset(
    {".git", ".terraform", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".oss-policy-kit"}
)

#: Wall-clock budget per individual ``helm template`` invocation.
HELM_RENDER_TIMEOUT_SECONDS: Final[int] = 60


@dataclass(slots=True)
class HelmRenderOutcome:
    """Structured outcome of one ``helm template`` pre-pass run."""

    available: bool
    helm_version: str | None = None
    charts_discovered: list[str] = field(default_factory=list)
    charts_rendered: list[str] = field(default_factory=list)
    rendered_manifest_paths: list[Path] = field(default_factory=list)
    render_errors: list[dict[str, str]] = field(default_factory=list)
    diagnostic: str = ""
    #: Temporary directory created by :func:`render_charts`. Callers must
    #: ``shutil.rmtree(tmp_root, ignore_errors=True)`` once the scan that
    #: consumed ``rendered_manifest_paths`` has completed. ``None`` when no
    #: tmp dir was created (helm absent, no charts discovered).
    tmp_root: Path | None = None


def helm_available() -> tuple[bool, str | None]:
    """Return ``(available, version_string)``. Never raises."""

    binary = shutil.which("helm")
    if binary is None:
        return False, None
    try:
        # Controlled subprocess: no shell, fixed args, resolved binary path.
        proc = subprocess.run(  # noqa: S603
            [binary, "version", "--short"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, None
    if proc.returncode != 0:
        return False, None
    return True, (proc.stdout or "").strip() or None


def _discover_charts(
    repo_root: Path,
    *,
    include_globs: Iterable[str] = ("**/Chart.yaml",),
) -> list[Path]:
    """Return repo-relative directories of every Helm chart discovered under ``repo_root``."""

    seen: set[Path] = set()
    out: list[Path] = []
    for pat in include_globs:
        for p in repo_root.glob(pat):
            chart_dir = _chart_dir_if_valid(p, repo_root, seen)
            if chart_dir is not None:
                out.append(chart_dir)
    return sorted(out)


def _chart_dir_if_valid(p: Path, repo_root: Path, seen: set[Path]) -> Path | None:
    """Return the resolved chart directory for a new ``Chart.yaml`` (not in a skip dir), else None."""

    if not p.is_file() or p.name != "Chart.yaml":
        return None
    try:
        rel = p.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return None
    if any(part in _SKIP_DIRS for part in rel.parts):
        return None
    chart_dir = p.parent.resolve()
    if chart_dir in seen:
        return None
    seen.add(chart_dir)
    return chart_dir


def _render_one_chart(
    chart_dir: Path,
    repo_root: Path,
    tmp_root: Path,
    helm_bin: str,
    timeout_per_chart: int,
    outcome: HelmRenderOutcome,
) -> None:
    """Render one chart via ``helm template`` into ``tmp_root`` and record results on ``outcome``."""

    rel = chart_dir.relative_to(repo_root.resolve()).as_posix()
    # Stable per-chart dir so a name collision between two charts still produces unique outputs.
    out_dir = tmp_root / (rel.replace("/", "__").replace("\\", "__") or "root")
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        # Controlled subprocess: no shell, resolved helm binary, fixed args.
        proc = subprocess.run(  # noqa: S603
            [helm_bin, "template", chart_dir.name or "chart", str(chart_dir), "--output-dir", str(out_dir)],
            capture_output=True,
            text=True,
            timeout=timeout_per_chart,
            check=False,
        )
    except subprocess.TimeoutExpired:
        outcome.render_errors.append({"chart": rel, "error": f"helm template timed out after {timeout_per_chart}s"})
        return
    except OSError as exc:
        outcome.render_errors.append({"chart": rel, "error": str(exc)})
        return
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        outcome.render_errors.append(
            {"chart": rel, "error": stderr.splitlines()[-1] if stderr else "helm exited non-zero"}
        )
        return
    outcome.charts_rendered.append(rel)
    # helm template --output-dir nests templates under <out_dir>/<chart-name>/templates/...
    for pattern in ("*.yaml", "*.yml"):
        for manifest in out_dir.rglob(pattern):
            if manifest.is_file():
                outcome.rendered_manifest_paths.append(manifest)


def render_charts(
    repo_root: Path,
    *,
    timeout_per_chart: int = HELM_RENDER_TIMEOUT_SECONDS,
) -> HelmRenderOutcome:
    """Render every chart under ``repo_root`` via ``helm template``.

    Rendered manifests are written to a fresh temporary directory; the
    paths are returned in ``rendered_manifest_paths`` so the K8s scanner
    can index them as regular YAML documents. The tmp directory itself is
    surfaced through :attr:`HelmRenderOutcome.tmp_root` so callers can
    ``shutil.rmtree(outcome.tmp_root, ignore_errors=True)`` once the scan
    that consumed the manifests has completed.
    """

    available, version = helm_available()
    if not available:
        return HelmRenderOutcome(
            available=False,
            diagnostic=(
                "`helm` CLI not on PATH; install Helm 3.x to enable the --helm-render pre-pass. "
                "scan-k8s will continue without rendering charts."
            ),
        )

    charts = _discover_charts(repo_root)
    outcome = HelmRenderOutcome(
        available=True,
        helm_version=version,
        charts_discovered=[c.relative_to(repo_root.resolve()).as_posix() for c in charts],
    )
    if not charts:
        outcome.diagnostic = "No Chart.yaml files discovered under target."
        return outcome

    tmp_root = Path(tempfile.mkdtemp(prefix="oss-policy-kit-helm-"))
    outcome.tmp_root = tmp_root
    helm_bin = shutil.which("helm") or "helm"
    for chart_dir in charts:
        _render_one_chart(chart_dir, repo_root, tmp_root, helm_bin, timeout_per_chart, outcome)

    if not outcome.rendered_manifest_paths and not outcome.render_errors:
        outcome.diagnostic = "All charts rendered without producing manifest files (unexpected)."
    return outcome
