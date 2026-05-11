"""Supply-chain-category evaluators (refactor step 3 of ``evaluators.py`` decomposition).

Public package boundary for the supply-chain pack: SAST / SCA / SBOM /
provenance / Scorecard controls. Like
:mod:`oss_policy_kit.application.evaluators_governance`, this module
re-exports the existing callables from ``evaluators.py`` so that
``EVALUATOR_REGISTRY`` remains **byte-equivalent**. Future v5.8 work will
move the bodies into this module incrementally.

Scope (closed set, alphabetized):

- ``BUILD-SBOM-QUAL-003`` — bundled SBOM quality bar.
- ``CONT-SIGN-001`` — container signing presence (re-exported from
  ``evaluators_containers``).
- ``DEP-UPDATE-001`` — automated dependency update tooling.
- ``OSS-SCORECARD-001`` — OpenSSF Scorecard JSON aggregate.
- ``PROV-VERIFY-061`` — provenance verification.
- ``SAST-SEMGREP-064`` — Semgrep SAST evidence.
- ``SEC-CODEQL-010`` — CodeQL / SAST workflow presence.
- ``SEC-DEPREV-011`` — dependency-review / Snyk / Dependabot security
  updates workflow presence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

SUPPLY_CHAIN_CONTROL_IDS: tuple[str, ...] = (
    "BUILD-SBOM-QUAL-003",
    "CONT-SIGN-001",
    "DEP-UPDATE-001",
    "OSS-SCORECARD-001",
    "PROV-VERIFY-061",
    "SAST-SEMGREP-064",
    "SEC-CODEQL-010",
    "SEC-DEPREV-011",
)


def build_supply_chain_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every supply-chain control.

    The ``CONT-SIGN-001`` evaluator is owned by ``evaluators_containers``
    (it's container-built but lives semantically on the supply-chain
    boundary). The container evaluator pack stays the source of truth for
    its registration; this builder intentionally omits it to avoid
    double-registration via :meth:`dict.setdefault`.
    """

    from oss_policy_kit.application import evaluators as _e

    return {
        "BUILD-SBOM-QUAL-003": _e.eval_build_sbom_qual_003,
        "DEP-UPDATE-001": _e.eval_dep_update_001,
        "OSS-SCORECARD-001": _e.eval_oss_scorecard_001,
        "PROV-VERIFY-061": _e.eval_prov_verify_061,
        "SAST-SEMGREP-064": _e.eval_sast_semgrep_064,
        "SEC-CODEQL-010": _e.eval_sec_codeql_010,
        "SEC-DEPREV-011": _e.eval_sec_deprev_011,
    }
