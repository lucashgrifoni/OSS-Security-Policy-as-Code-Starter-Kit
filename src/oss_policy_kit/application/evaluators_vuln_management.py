"""Vulnerability-management-category evaluators (refactor step F2-04 of
``evaluators.py`` decomposition).

Public package boundary for in-repo secret-handling and dependency
pinning hygiene controls. The neighbouring supply-chain pack
(:mod:`oss_policy_kit.application.evaluators_supply_chain`) covers
scanner-presence controls (``SEC-CODEQL-010``, ``SEC-DEPREV-011``,
``DEP-UPDATE-001``, ``OSS-SCORECARD-001``, ``PROV-VERIFY-061``,
``BUILD-SBOM-QUAL-003``); this module is the focused boundary for the
in-repo file-hygiene controls that an adopter typically remediates by
editing the repository directly rather than by adding a scanner.

Scope (closed set, alphabetized):

- ``SEC-GITIGNORE-051`` -- ``.gitignore`` covers common secret-leak
  paths.
- ``SEC-PINLOCK-052`` -- dependency lockfile / pin presence.
- ``SEC-SECRETS-050`` -- secret scanning workflow / keyword presence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

VULN_MANAGEMENT_CONTROL_IDS: tuple[str, ...] = (
    "SEC-GITIGNORE-051",
    "SEC-PINLOCK-052",
    "SEC-SECRETS-050",
)


def build_vuln_management_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every vuln-management control."""

    from oss_policy_kit.application import evaluators as _e

    return {
        "SEC-GITIGNORE-051": _e.eval_sec_gitignore_051,
        "SEC-PINLOCK-052": _e.eval_sec_pinlock_052,
        "SEC-SECRETS-050": _e.eval_sec_secrets_050,
    }
