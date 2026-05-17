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

- ``SAST-GITLEAKS-069`` -- Gitleaks SARIF evidence (secret leak detection).
- ``SAST-OSV-068`` -- OSV-Scanner v2 SARIF evidence (reachability-aware SCA).
- ``SAST-POUTINE-067`` -- poutine SARIF evidence (GHA / GitLab CI pipeline scanner).
- ``SAST-SEMGREP-064`` -- Semgrep SAST evidence (kit-emitted wrapper).
- ``SAST-ZIZMOR-066`` -- zizmor SARIF evidence (GHA static analysis).

The 06x family (zizmor / poutine / OSV / gitleaks) was added in Fase 4
(v5.9.0). They share a generic SARIF reader in ``evaluators.py``; the
boundary keeps the shared helper visible to a single import point.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

SAST_CONTROL_IDS: tuple[str, ...] = (
    "SAST-SEMGREP-064",
    "SAST-ZIZMOR-066",
    "SAST-POUTINE-067",
    "SAST-OSV-068",
    "SAST-GITLEAKS-069",
)


def build_sast_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every SAST control."""

    from oss_policy_kit.application import evaluators as _e

    return {
        "SAST-SEMGREP-064": _e.eval_sast_semgrep_064,
        "SAST-ZIZMOR-066": _e.eval_sast_zizmor_066,
        "SAST-POUTINE-067": _e.eval_sast_poutine_067,
        "SAST-OSV-068": _e.eval_sast_osv_068,
        "SAST-GITLEAKS-069": _e.eval_sast_gitleaks_069,
    }
