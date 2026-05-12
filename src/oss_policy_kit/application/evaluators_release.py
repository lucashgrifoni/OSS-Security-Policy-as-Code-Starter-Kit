"""Release-category evaluators (refactor step F2-03 of ``evaluators.py`` decomposition).

Public package boundary for release-time and post-release artifact
controls: deployment workflows, provenance / SBOM artifact emission,
audit log streaming, release archival. ``REL-CHANGE-012`` (changelog
presence) intentionally lives in
:mod:`oss_policy_kit.application.evaluators_governance` because it
captures release **governance** rather than release **artifacts**.

Scope (closed set, alphabetized):

- ``AUDIT-STREAM-060`` -- centralized audit log streaming evidence.
- ``AWS-PROV-043``, ``AWS-PROVART-059``, ``AWS-SBOMART-058`` -- AWS
  provenance / SBOM artifact emission (in-pipeline and artifact-bound).
- ``AZ-ARTPRV-059``, ``AZ-ARTSBOM-058`` -- Azure DevOps provenance /
  SBOM artifact emission.
- ``GH-DEPLOY-022`` -- GitHub deployment workflow / environment binding.
- ``GH-PROV-023`` -- GitHub artifact attestation / provenance.
- ``GH-REL-021`` -- GitHub Releases / tag-driven release workflow.
- ``RELEASE-ARCHIVE-063`` -- release archive retention evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

RELEASE_CONTROL_IDS: tuple[str, ...] = (
    "AUDIT-STREAM-060",
    "AWS-PROV-043",
    "AWS-PROVART-059",
    "AWS-SBOMART-058",
    "AZ-ARTPRV-059",
    "AZ-ARTSBOM-058",
    "GH-DEPLOY-022",
    "GH-PROV-023",
    "GH-REL-021",
    "RELEASE-ARCHIVE-063",
)


def build_release_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every release control."""

    from oss_policy_kit.application import evaluators as _e

    return {
        "AUDIT-STREAM-060": _e.eval_audit_stream_060,
        "AWS-PROV-043": _e.eval_aws_prov_043,
        "AWS-PROVART-059": _e.eval_aws_provart_059,
        "AWS-SBOMART-058": _e.eval_aws_sbomart_058,
        "AZ-ARTPRV-059": _e.eval_az_artprv_059,
        "AZ-ARTSBOM-058": _e.eval_az_artsbom_058,
        "GH-DEPLOY-022": _e.eval_gh_dep_022,
        "GH-PROV-023": _e.eval_gh_prov_023,
        "GH-REL-021": _e.eval_gh_rel_021,
        "RELEASE-ARCHIVE-063": _e.eval_release_archive_063,
    }
