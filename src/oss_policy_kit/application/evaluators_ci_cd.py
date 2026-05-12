"""CI/CD-category evaluators (refactor step F2-01 of ``evaluators.py`` decomposition).

Public package boundary for the CI/CD evaluator pack: GitHub Actions
workflow analysis, Azure DevOps pipeline analysis, and AWS CodeBuild /
CodePipeline detection. Like
:mod:`oss_policy_kit.application.evaluators_governance` and
:mod:`oss_policy_kit.application.evaluators_supply_chain`, this module
re-exports the existing callables from ``evaluators.py`` so that
``EVALUATOR_REGISTRY`` remains **byte-equivalent**. Future v5.8.x work
will move the bodies into this module incrementally.

Scope (closed set, alphabetized):

- ``AWS-CB-045``, ``AWS-CI-037``, ``AWS-CP-044``, ``AWS-PIPE-042``,
  ``AWS-SBOM-041``, ``AWS-SCA-040``, ``AWS-SEC-039``, ``AWS-SECRET-038``
  -- buildspec / CodePipeline / CodeBuild detection.
- ``AZ-PIPE-027``, ``AZ-PIPE-028``, ``AZ-PIPE-029``, ``AZ-PIPE-030``,
  ``AZ-SBOM-033``, ``AZ-SCA-032``, ``AZ-SEC-031`` -- Azure Pipelines
  YAML analysis.
- ``CI-DANGER-007``, ``CI-LEAST-009``, ``CI-PERM-006``, ``CI-PIN-008``,
  ``CI-WF-005``, ``CI-WFCALLSHA-055`` -- workflow hygiene.
- ``GH-MERGEQ-053`` -- merge queue posture.
- ``GH-WF-018``, ``GH-WF-019``, ``GH-WF-020`` -- GitHub Actions workflow
  signal controls.

Identity / platform / release / vulnerability-management controls live
in dedicated boundary modules to keep this surface focused on the
"continuous integration pipeline" concept.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

CI_CD_CONTROL_IDS: tuple[str, ...] = (
    "AWS-CB-045",
    "AWS-CI-037",
    "AWS-CP-044",
    "AWS-PIPE-042",
    "AWS-SBOM-041",
    "AWS-SCA-040",
    "AWS-SEC-039",
    "AWS-SECRET-038",
    "AZ-PIPE-027",
    "AZ-PIPE-028",
    "AZ-PIPE-029",
    "AZ-PIPE-030",
    "AZ-SBOM-033",
    "AZ-SCA-032",
    "AZ-SEC-031",
    "CI-DANGER-007",
    "CI-LEAST-009",
    "CI-PERM-006",
    "CI-PIN-008",
    "CI-WF-005",
    "CI-WFCALLSHA-055",
    "GH-MERGEQ-053",
    "GH-WF-018",
    "GH-WF-019",
    "GH-WF-020",
)


def build_ci_cd_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every CI/CD control."""

    from oss_policy_kit.application import evaluators as _e

    return {
        "AWS-CB-045": _e.eval_aws_cb_045,
        "AWS-CI-037": _e.eval_aws_ci_037,
        "AWS-CP-044": _e.eval_aws_cp_044,
        "AWS-PIPE-042": _e.eval_aws_pipe_042,
        "AWS-SBOM-041": _e.eval_aws_sbom_041,
        "AWS-SCA-040": _e.eval_aws_sca_040,
        "AWS-SEC-039": _e.eval_aws_sec_039,
        "AWS-SECRET-038": _e.eval_aws_secret_038,
        "AZ-PIPE-027": _e.eval_az_pipe_027,
        "AZ-PIPE-028": _e.eval_az_pipe_028,
        "AZ-PIPE-029": _e.eval_az_pipe_029,
        "AZ-PIPE-030": _e.eval_az_pipe_030,
        "AZ-SBOM-033": _e.eval_az_sbom_033,
        "AZ-SCA-032": _e.eval_az_sca_032,
        "AZ-SEC-031": _e.eval_az_sec_031,
        "CI-DANGER-007": _e.eval_ci_danger_007,
        "CI-LEAST-009": _e.eval_ci_least_009,
        "CI-PERM-006": _e.eval_ci_perm_006,
        "CI-PIN-008": _e.eval_ci_pin_008,
        "CI-WF-005": _e.eval_ci_wf_005,
        "CI-WFCALLSHA-055": _e.eval_ci_wfcallsha_055,
        "GH-MERGEQ-053": _e.eval_gh_mergeq_053,
        "GH-WF-018": _e.eval_gh_wf_018,
        "GH-WF-019": _e.eval_gh_wf_019,
        "GH-WF-020": _e.eval_gh_wf_020,
    }
