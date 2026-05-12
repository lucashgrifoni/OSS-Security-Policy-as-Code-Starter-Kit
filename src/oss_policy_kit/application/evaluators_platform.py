"""Platform-category evaluators (refactor step F2-02 of ``evaluators.py`` decomposition).

Public package boundary for repo / organization / platform-side
controls: branch protection, organization MFA, environment protection,
ruleset evidence, Azure service connections, AWS IAM identity, runner
posture. These controls typically depend on evidence files collected
out-of-clone (via ``collect-evidence`` or API surfaces) rather than on
in-repo file presence.

Scope (closed set, alphabetized):

- ``AWS-CBIDENT-057``, ``AWS-PIPEIAM-056`` -- AWS CodeBuild / CodePipeline
  IAM identity assertions.
- ``AZ-IDENT-036``, ``AZ-PLAT-034``, ``AZ-PLAT-035``, ``AZ-SCONN-056``,
  ``AZ-WIFEV-057`` -- Azure DevOps identity, branch policy, service
  connection, and workload-identity federation evidence.
- ``GH-PLAT-024``, ``GH-PLAT-025``, ``GH-PLAT-026`` -- GitHub
  rulesets / environment protection / secret-scanning evidence.
- ``GH-RUNNER-062`` -- self-hosted runner / runner group posture.
- ``ORG-MFA-001`` -- organization-level multi-factor authentication.
- ``PLAT-BRPROT-015`` -- branch protection evidence (canonical).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

PLATFORM_CONTROL_IDS: tuple[str, ...] = (
    "AWS-CBIDENT-057",
    "AWS-PIPEIAM-056",
    "AZ-IDENT-036",
    "AZ-PLAT-034",
    "AZ-PLAT-035",
    "AZ-SCONN-056",
    "AZ-WIFEV-057",
    "GH-PLAT-024",
    "GH-PLAT-025",
    "GH-PLAT-026",
    "GH-RUNNER-062",
    "ORG-MFA-001",
    "PLAT-BRPROT-015",
)


def build_platform_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every platform control."""

    from oss_policy_kit.application import evaluators as _e

    return {
        "AWS-CBIDENT-057": _e.eval_aws_cbident_057,
        "AWS-PIPEIAM-056": _e.eval_aws_pipeiam_056,
        "AZ-IDENT-036": _e.eval_az_ident_036,
        "AZ-PLAT-034": _e.eval_az_plat_034,
        "AZ-PLAT-035": _e.eval_az_plat_035,
        "AZ-SCONN-056": _e.eval_az_sconn_056,
        "AZ-WIFEV-057": _e.eval_az_wifev_057,
        "GH-PLAT-024": _e.eval_gh_plat_024,
        "GH-PLAT-025": _e.eval_gh_plat_025,
        "GH-PLAT-026": _e.eval_gh_plat_026,
        "GH-RUNNER-062": _e.eval_gh_runner_062,
        "ORG-MFA-001": _e.eval_org_mfa_001,
        "PLAT-BRPROT-015": _e.eval_plat_brprot_015,
    }
