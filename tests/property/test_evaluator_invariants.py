"""Property-based invariants that every evaluator in EVALUATOR_REGISTRY must hold.

The existing property tests cover data structures (schema/serialization roundtrips).
This module covers the *evaluators themselves*: given a synthetic repository, every
``eval_*`` callable must behave safely and predictably. A failure here is a real
robustness bug in the evaluator, not in the test (see prompt M5 anti-patterns).

Invariants:
    INV-1  every evaluator returns an ``EvalOutcome`` and never raises on a valid context
    INV-2  ``status`` is always a member of ``ControlStatus``
    INV-3  ``evidence_sources`` is always a list of ``str``
    INV-4  running the same evaluator twice on the same context is deterministic
    INV-5  evaluators do not write under the target repository (read-only)
"""

from __future__ import annotations

import tempfile
from dataclasses import asdict
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY, EvalContext
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome
from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

# Representative files an evaluator might inspect, each with minimal valid content.
# Hypothesis picks an arbitrary subset so evaluators are exercised against many
# present/absent combinations (the source of most evaluator edge cases).
_CANDIDATE_FILES: dict[str, str] = {
    "SECURITY.md": "# Security\nReport issues to security@example.com\n",
    "CONTRIBUTING.md": "# Contributing\nOpen a PR.\n",
    "CODEOWNERS": "* @owner\n",
    ".github/CODEOWNERS": "* @owner\n",
    "LICENSE": "Apache License 2.0\n",
    "CHANGELOG.md": "# Changelog\n## Unreleased\n",
    "README.md": "# Example repository\n",
    ".github/dependabot.yml": (
        "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n    schedule:\n      interval: weekly\n"
    ),
    ".github/workflows/ci.yml": (
        "name: ci\non: push\npermissions:\n  contents: read\njobs:\n  build:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@de0fac2 # v6\n"
    ),
    ".github/workflows/unsafe.yml": (
        "name: unsafe\non: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hello\n"
    ),
    "azure-pipelines.yml": "trigger:\n  - main\npool:\n  vmImage: ubuntu-latest\nsteps:\n  - script: echo hi\n",
    "buildspec.yml": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
    ".gitlab-ci.yml": "stages:\n  - test\ntest:\n  stage: test\n  script:\n    - echo hi\n",
    "Dockerfile": "FROM alpine:3.19\nRUN adduser -D app\nUSER app\n",
    ".oss-policy-kit/evidence/branch-protection.json": '{"schema_version": "x", "required_pull_request_reviews": {}}',
    ".oss-policy-kit/evidence/scorecard.json": '{"score": 7.5, "checks": []}',
    "requirements.txt": "requests==2.31.0\n",
    "package.json": '{"name": "example", "version": "1.0.0"}\n',
    "pyproject.toml": "[project]\nname = 'example'\nversion = '0.1.0'\n",
}

_FILE_KEYS = sorted(_CANDIDATE_FILES)


def _materialize(root: Path, present: list[str]) -> None:
    for rel in present:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_CANDIDATE_FILES[rel], encoding="utf-8")


def _build_context(root: Path, profile_id: str = "github-level-1") -> EvalContext:
    """Build an EvalContext the same way the engine does (analyze_* on the repo)."""

    return EvalContext(
        repo_root=root,
        profile_id=profile_id,
        workflows=analyze_workflows(root),
        azure_pipelines=analyze_azure_pipelines(root),
        aws_ci=analyze_aws_ci(root),
        scorecard=None,
        gitlab_ci=analyze_gitlab_ci(root),
    )


def _snapshot(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}


_repo_subsets = st.lists(st.sampled_from(_FILE_KEYS), unique=True, max_size=len(_FILE_KEYS))


def test_registry_is_populated() -> None:
    """Guard: the invariant tests iterate the whole registry, so it must be non-trivial."""

    assert len(EVALUATOR_REGISTRY) >= 150


@given(present=_repo_subsets)
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_every_evaluator_returns_valid_outcome(present: list[str]) -> None:
    """INV-1, INV-2, INV-3, INV-5 across the entire registry."""

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _materialize(root, present)
        ctx = _build_context(root)
        before = _snapshot(root)

        for control_id, evaluator in EVALUATOR_REGISTRY.items():
            outcome = evaluator(ctx)  # INV-1: must not raise
            assert isinstance(outcome, EvalOutcome), f"{control_id} did not return EvalOutcome"
            assert isinstance(outcome.status, ControlStatus), f"{control_id} returned non-ControlStatus status"
            assert isinstance(outcome.evidence_sources, list), f"{control_id} evidence_sources is not a list"
            assert all(isinstance(s, str) for s in outcome.evidence_sources), (
                f"{control_id} evidence_sources contains a non-str entry"
            )

        # INV-5: evaluators are read-only with respect to the target repository.
        assert _snapshot(root) == before, "an evaluator wrote to the target repository"


@given(present=_repo_subsets)
@settings(max_examples=15, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_every_evaluator_is_deterministic(present: list[str]) -> None:
    """INV-4: same context, same result, twice."""

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _materialize(root, present)
        ctx = _build_context(root)

        for control_id, evaluator in EVALUATOR_REGISTRY.items():
            first = evaluator(ctx)
            second = evaluator(ctx)
            assert asdict(first) == asdict(second), f"{control_id} is non-deterministic on an identical context"
