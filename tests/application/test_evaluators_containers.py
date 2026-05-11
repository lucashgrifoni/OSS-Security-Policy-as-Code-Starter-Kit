"""Tests for the v5.6 CONT-RUNTIME-* and CONT-SIGN-001 evaluators."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_containers import (
    CONT_RULES,
    build_container_evaluators,
    eval_cont_runtime_001,
    eval_cont_runtime_002,
    eval_cont_runtime_003,
    eval_cont_runtime_004,
    eval_cont_runtime_005,
    eval_cont_runtime_006,
    eval_cont_sign_001,
)
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus


def _ctx(repo_root: Path) -> SimpleNamespace:
    return SimpleNamespace(repo_root=repo_root)


# ---------------------------------------------------------------------------
# Catalog + registry + profile wiring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id,_summary,_fn", list(CONT_RULES))
def test_cont_rule_in_catalog(rule_id: str, _summary: str, _fn: Any) -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert rule_id in catalog
    spec = catalog[rule_id]
    assert spec.lifecycle == "experimental"
    assert spec.assurance == "signal"


@pytest.mark.parametrize("rule_id,_summary,_fn", list(CONT_RULES))
def test_cont_rule_registered(rule_id: str, _summary: str, _fn: Any) -> None:
    assert rule_id in EVALUATOR_REGISTRY


def test_container_baseline_1_loads_with_full_pack() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "container-baseline-1")
    assert spec.id == "container-baseline-1"
    pack_ids = {rid for rid, _, _ in CONT_RULES}
    bundled_pack = pack_ids & set(spec.control_ids)
    assert bundled_pack == pack_ids, "container-baseline-1 must include every CONT-RUNTIME-* + CONT-SIGN-001"


def test_build_container_evaluators_returns_full_pack() -> None:
    built = build_container_evaluators()
    assert set(built.keys()) == {rid for rid, _, _ in CONT_RULES}


# ---------------------------------------------------------------------------
# Per-rule unit tests
# ---------------------------------------------------------------------------


def test_runtime_001_multi_stage_pass(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12 AS builder\n"
        "RUN pip install requests\n\n"
        "FROM python:3.12-slim\n"
        "COPY --from=builder /app /app\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_001(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_runtime_001_single_stage_fails(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text('FROM python:3.12\nCMD ["python"]\n', encoding="utf-8")
    out = eval_cont_runtime_001(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL


def test_runtime_001_no_dockerfile_is_not_applicable(tmp_path: Path) -> None:
    out = eval_cont_runtime_001(_ctx(tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_runtime_002_healthcheck_pass(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM nginx:1.27\nHEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_002(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_runtime_002_no_healthcheck_fail(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM nginx:1.27\nCMD nginx -g 'daemon off;'\n", encoding="utf-8")
    out = eval_cont_runtime_002(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL


def test_runtime_003_curl_bash_fails(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/install.sh | bash\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_003(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL


def test_runtime_003_safe_install_passes(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_003(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_runtime_004_dockerignore_present_passes(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    (tmp_path / ".dockerignore").write_text(".git\nnode_modules\n", encoding="utf-8")
    out = eval_cont_runtime_004(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_runtime_004_missing_dockerignore_fails(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    out = eval_cont_runtime_004(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL


def test_runtime_005_apt_with_no_recommends_passes(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_005(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_runtime_005_apt_without_cleanup_fails(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_005(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL


def test_runtime_005_no_apt_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\nRUN apk add --no-cache curl\n", encoding="utf-8")
    out = eval_cont_runtime_005(_ctx(tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_runtime_005_ignores_no_recommends_inside_comment(tmp_path: Path) -> None:
    """Comments mentioning ``--no-install-recommends`` must NOT suppress the FAIL.

    Regression for the v5.7.0 readiness finding where a Dockerfile auto-comment
    listing the missing flag (e.g. ``# apt-get install without --no-install-recommends``)
    made the regex match and force PASS even when the real RUN line lacked the flag.
    """

    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\n"
        "# This image historically lacked --no-install-recommends and cache cleanup.\n"
        "RUN apt-get update && apt-get install -y curl\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_005(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL, out.reason


def test_runtime_005_real_flag_still_passes(tmp_path: Path) -> None:
    """The fix must not break the legitimate PASS path.

    A Dockerfile that uses ``--no-install-recommends`` in the actual RUN line
    (not in a comment) must continue to evaluate as PASS.
    """

    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\n"
        "# Install runtime deps only.\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_005(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS, out.reason


def test_runtime_006_pinned_versions_pass(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get install -y curl=7.81.0-1ubuntu1.20\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_006(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_runtime_006_unpinned_fails(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get install -y curl ca-certificates\n", encoding="utf-8"
    )
    out = eval_cont_runtime_006(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL


def test_sign_001_cosign_in_workflow_passes(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "release.yml").write_text(
        "jobs:\n  build:\n    steps:\n"
        "      - uses: sigstore/cosign-installer@v3\n"
        "      - run: cosign sign --yes ghcr.io/x@sha256:abc\n",
        encoding="utf-8",
    )
    out = eval_cont_sign_001(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_sign_001_attest_build_provenance_passes(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "release.yml").write_text(
        "jobs:\n  attest:\n    steps:\n      - uses: actions/attest-build-provenance@v1\n",
        encoding="utf-8",
    )
    out = eval_cont_sign_001(_ctx(tmp_path))
    assert out.status is ControlStatus.PASS


def test_sign_001_no_signing_returns_manual_review(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  test:\n    steps:\n      - run: pytest\n", encoding="utf-8")
    out = eval_cont_sign_001(_ctx(tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# ---------------------------------------------------------------------------
# Dockerfile variant discovery (regression: Dockerfile.weak, Dockerfile.dev, etc.)
# ---------------------------------------------------------------------------


def test_find_dockerfiles_picks_up_suffixed_variants(tmp_path: Path) -> None:
    """``Dockerfile.<suffix>`` and ``<name>.Dockerfile`` must be inspected.

    Regression for the lab 07 ``container-hardening-target`` finding where
    ``Dockerfile.weak`` was invisible to ``_find_dockerfiles`` and masked
    real CONT-IMAGE-* / CONT-RUNTIME-* failures.
    """

    from oss_policy_kit.application.evaluators_common import find_dockerfiles

    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "Dockerfile.dev").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "Dockerfile.weak").write_text("FROM ubuntu:22.04\n", encoding="utf-8")
    (tmp_path / "Dockerfile-prod").write_text("FROM python:3.12\n", encoding="utf-8")
    sub = tmp_path / "build"
    sub.mkdir()
    (sub / "app.Dockerfile").write_text("FROM golang:1.22\n", encoding="utf-8")
    (sub / "ci.dockerfile").write_text("FROM debian:bookworm\n", encoding="utf-8")
    # Non-Docker siblings that must NOT be picked up.
    (tmp_path / "Dockerfile.md").write_text("# Docs\n", encoding="utf-8")
    (tmp_path / "Dockerfile.example").write_text("FROM nope\n", encoding="utf-8")

    names = sorted(p.name for p in find_dockerfiles(tmp_path))
    assert names == [
        "Dockerfile",
        "Dockerfile-prod",
        "Dockerfile.dev",
        "Dockerfile.weak",
        "app.Dockerfile",
        "ci.dockerfile",
    ]


def test_find_dockerfiles_deduplicates_case_insensitive_filesystems(tmp_path: Path) -> None:
    """The same Dockerfile must not appear twice when ``Path`` casing differs."""

    from oss_policy_kit.application.evaluators_common import find_dockerfiles

    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    results = find_dockerfiles(tmp_path)
    resolved = [str(p.resolve()) for p in results]
    assert len(resolved) == len(set(resolved)), resolved


def test_runtime_006_flags_weak_variant_alongside_main(tmp_path: Path) -> None:
    """``Dockerfile.weak`` next to a hardened ``Dockerfile`` must still trip CONT-RUNTIME-006."""

    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim AS build\n"
        "RUN apt-get update \\\n"
        "  && apt-get install -y --no-install-recommends ca-certificates=20230311 \\\n"
        "  && rm -rf /var/lib/apt/lists/*\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile.weak").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl python3 python3-pip\n",
        encoding="utf-8",
    )
    out = eval_cont_runtime_006(_ctx(tmp_path))
    assert out.status is ControlStatus.FAIL
    assert "Dockerfile.weak" in (out.reason or "")
