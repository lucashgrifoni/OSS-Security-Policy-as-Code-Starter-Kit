"""SAST-category evaluators (refactor step F2-05 of ``evaluators.py`` decomposition).

Public package boundary for SAST tooling. Today this is the single
``SAST-SEMGREP-064`` evaluator; the boundary exists so that future
adapter additions (Trivy, Gitleaks, Grype, etc., tracked for v5.9.0
Fase 4) plug into a dedicated surface instead of growing the
supply-chain pack.

Note on overlap with ``evaluators_supply_chain``: ``SAST-SEMGREP-064``
**previously** appeared in that pack's :data:`SUPPLY_CHAIN_CONTROL_IDS`
tuple. It has been moved here so the SAST surface is the single source
of truth for SAST adapters; supply-chain continues to own broader
controls (CodeQL workflow presence, Scorecard aggregate, provenance
verification, SBOM quality).

Scope (closed set, alphabetized):

- ``SAST-SEMGREP-064`` -- Semgrep SAST evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

SAST_CONTROL_IDS: tuple[str, ...] = (
    "SAST-SEMGREP-064",
)


def build_sast_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every SAST control."""

    from oss_policy_kit.application import evaluators as _e

    return {
        "SAST-SEMGREP-064": _e.eval_sast_semgrep_064,
    }
