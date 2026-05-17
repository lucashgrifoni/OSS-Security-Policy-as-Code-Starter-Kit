"""GitLab CI evaluators boundary module (v5.9.0).

Public package boundary for GitLab CI controls. v5.9.0 ships an initial
6-control subset of the ADR-003 design (12 controls planned). The bodies
live in ``evaluators.py`` for cross-evaluator helpers; this module
re-exports them under their canonical names for the registry loader.

Scope (closed set, alphabetized):

- ``GL-PIPE-001`` -- GitLab CI pipeline files present and parseable.
- ``GL-PIPE-002`` -- GitLab CI image references pinned.
- ``GL-PIPE-003`` -- GitLab CI scripts do not pipe network downloads to a shell.
- ``GL-PIPE-004`` -- GitLab CI jobs do not declare broad ``inherit: secrets: true``.
- ``GL-PIPE-005`` -- GitLab CI ``include:`` does not reference unpinned remote URLs.
- ``GL-PIPE-006`` -- GitLab CI jobs use trigger restrictions.

Future v5.9.x / v5.10.0 work (tracked in ADR-003) will extend this list
toward the full 12-control surface: OIDC token usage, self-hosted runner
restrictions, audit log streaming, etc.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

GITLAB_CI_CONTROL_IDS: tuple[str, ...] = (
    "GL-PIPE-001",
    "GL-PIPE-002",
    "GL-PIPE-003",
    "GL-PIPE-004",
    "GL-PIPE-005",
    "GL-PIPE-006",
)


def build_gitlab_ci_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every GitLab CI control."""

    from oss_policy_kit.application import evaluators as _e

    return {
        "GL-PIPE-001": _e.eval_gl_pipe_001,
        "GL-PIPE-002": _e.eval_gl_pipe_002,
        "GL-PIPE-003": _e.eval_gl_pipe_003,
        "GL-PIPE-004": _e.eval_gl_pipe_004,
        "GL-PIPE-005": _e.eval_gl_pipe_005,
        "GL-PIPE-006": _e.eval_gl_pipe_006,
    }
