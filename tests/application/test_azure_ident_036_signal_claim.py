"""Every Azure control has to describe the situation it actually checked.

AZ-IDENT-036 answered one fixed sentence for both of its no-evidence tails, and that sentence
claimed "A keyword signal was detected in the pipeline YAML" -- said in the tail reached
*because* no workload-identity keyword was found. The same fault, and the same fix, as
AWS-PIPEIAM-056 one platform over; the two are pinned to the same shape of test so they stop
diverging.

The sweep that followed found the claim in three more places, all of them the tool speaking past
what it read:

* AZ-IDENT-036 treated governance evidence it could not parse as governance evidence that was
  not there, so an unreadable file left the control `not-applicable` -- out of the gate rather
  than in front of a human (ADR-045).
* AZ-PIPE-028 and AZ-PIPE-030 reported a pipeline as lacking `pr:` and `extends:` when the file
  holding both had failed to parse, and AZ-PIPE-029 *passed* it. The parser records the failure
  and moves on, so the empty signal list reads like a finding.
* AZ-PIPE-029 confirmed "explicit persistCredentials: false" on any file containing the two
  words somewhere -- a templated `persistCredentials: ${{ parameters.persist }}` next to an
  unrelated `submodules: false` earned the stronger reason and the higher confidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import azure as az
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis, analyze_azure_pipelines
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_EVIDENCE = "azure-pipeline-governance.json"
#: A tab where the YAML parser demands a space: the file is readable, and unparseable.
_UNPARSEABLE = "pr:\n  branches:\n    include: [main]\nextends:\n  template: t.yml\n\tnot yaml\n"


def _ctx(tmp_path: Path, azp: AzurePipelineAnalysis | None = None) -> az.EvalContext:
    return az.EvalContext(
        repo_root=tmp_path,
        profile_id="azure-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=azp if azp is not None else analyze_azure_pipelines(tmp_path),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _write_unreadable_evidence(tmp_path: Path) -> Path:
    """Write governance evidence that is valid JSON but missing a required field.

    `posture.federated_identity_preferred` is present and true, so the only thing between this
    document and a verdict is the schema violation -- which is what makes the file "present but
    unreadable" rather than absent.
    """

    payload: dict[str, Any] = {
        "schema_version": "azure-pipeline-governance/v1",
        # `attested_at` is required by evidence-azure-pipeline-governance.schema.json.
        "attested_by": "azure-api-collection",
        "project": "demo",
        "posture": {
            "approvals_required": True,
            "environment_checks_enabled": True,
            "service_connection_restricted": True,
            "federated_identity_preferred": True,
        },
    }
    return _write(tmp_path, f".oss-policy-kit/evidence/{_EVIDENCE}", json.dumps(payload))


# --------------------------------------------------------------------------- #
# the signal is only claimed where the signal is
# --------------------------------------------------------------------------- #


def test_a_repository_with_no_federation_keyword_is_not_told_a_signal_was_found(tmp_path: Path) -> None:
    """This tail is reached because the keyword is absent; announcing it is the defect."""

    _write(tmp_path, "azure-pipelines.yml", "steps:\n  - task: AzureCLI@2\n")

    outcome = az.eval_az_ident_036(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "was detected" not in outcome.reason
    assert "no pipeline file mentions workload identity federation" in outcome.reason


def test_the_two_repositories_that_differ_by_the_keyword_get_different_reasons(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """One repository mentions federation and one does not; a shared sentence describes only one."""

    with_keyword = tmp_path_factory.mktemp("with-keyword")
    _write(with_keyword, "azure-pipelines.yml", "steps:\n  - task: AzureCLI@2\n    inputs:\n      idToken: $(t)\n")
    _write(tmp_path, "azure-pipelines.yml", "steps:\n  - task: AzureCLI@2\n")

    found = az.eval_az_ident_036(_ctx(with_keyword))
    absent = az.eval_az_ident_036(_ctx(tmp_path))

    assert found.status is absent.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert found.reason != absent.reason
    assert "A pipeline file mentions workload identity federation" in found.reason
    assert found.evidence_sources == [str((with_keyword / "azure-pipelines.yml").resolve())]


def test_both_tails_still_name_the_file_the_operator_has_to_add(tmp_path: Path) -> None:
    """Removing a false claim must not cost the operator the one path that ends the ambiguity."""

    for pipeline in ("steps:\n  - task: AzureCLI@2\n", "steps:\n  - task: AzureCLI@2\n    inputs:\n      idToken: x\n"):
        _write(tmp_path, "azure-pipelines.yml", pipeline)

        outcome = az.eval_az_ident_036(_ctx(tmp_path))

        assert f".oss-policy-kit/evidence/{_EVIDENCE}" in outcome.reason


# --------------------------------------------------------------------------- #
# evidence that is present and unreadable is reviewed, never dropped (ADR-045)
# --------------------------------------------------------------------------- #


def test_an_unreadable_governance_file_is_reviewed_rather_than_ruled_out(tmp_path: Path) -> None:
    """Without a pipeline to fall through to, an unreadable file used to end as `not-applicable`.

    That is the worst reading of the three available: `not-applicable` says the control does not
    apply here, so the operator never learns their evidence is broken and the gate never asks.
    """

    path = _write_unreadable_evidence(tmp_path)

    outcome = az.eval_az_ident_036(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    # No `is not NOT_APPLICABLE` here: with the line above pinning the value it can never
    # fail, and mypy narrows it to a constant. The reason assertions below are what
    # actually catch a regression, because the pre-fix path produced none of this text.
    assert "does not match schema" in outcome.reason
    assert "'attested_at' is a required property" in outcome.reason
    assert "evidence-azure-pipeline-governance.schema.json" in outcome.remediation
    assert outcome.evidence_sources == [str(path.resolve())]


def test_a_file_that_is_there_is_never_reported_as_missing(tmp_path: Path) -> None:
    """The pipeline tails say no file was found; reaching them with the file on disk is a lie."""

    _write_unreadable_evidence(tmp_path)
    _write(tmp_path, "azure-pipelines.yml", "steps:\n  - task: AzureCLI@2\n")

    outcome = az.eval_az_ident_036(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "No evidence file found" not in outcome.reason


def test_the_three_controls_reading_that_file_all_refuse_to_judge_it(tmp_path: Path) -> None:
    """AZ-SCONN-056 and AZ-WIFEV-057 read the same document; one dissenting verdict is the defect."""

    _write_unreadable_evidence(tmp_path)
    ctx = _ctx(tmp_path)

    ident = az.eval_az_ident_036(ctx)
    sconn = az.eval_az_sconn_056(ctx)
    wifev = az.eval_az_wifev_057(ctx)

    assert ident.status is sconn.status is wifev.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert ident.reason == sconn.reason == wifev.reason
    assert ident.remediation == sconn.remediation == wifev.remediation


# --------------------------------------------------------------------------- #
# a pipeline nobody could parse is not a pipeline that lacks the posture
# --------------------------------------------------------------------------- #

#: The fourth column is the verdict each control returned BEFORE this fix — two answered
#: `fail` and one `pass` on a file that never parsed. Carrying it here keeps the
#: regression assertion honest: `is not ControlStatus.PASS` next to
#: `is ControlStatus.MANUAL_REVIEW_REQUIRED` is a tautology mypy can narrow away, so it
#: would pass no matter what the control did.
_PARSE_ERROR_CONTROLS = (
    (az.eval_az_pipe_028, "PR validation trigger posture", "No PR validation trigger signal", ControlStatus.FAIL),
    (
        az.eval_az_pipe_029,
        "checkout credential posture",
        "No checkout step with persistCredentials",
        ControlStatus.PASS,
    ),
    (az.eval_az_pipe_030, "`extends` template posture", "No `extends` template posture detected", ControlStatus.FAIL),
)


@pytest.mark.parametrize(("evaluate", "unproven", "old_claim", "old_status"), _PARSE_ERROR_CONTROLS)
def test_an_unparsed_pipeline_is_reviewed_not_ruled_on(
    tmp_path: Path, evaluate: Any, unproven: str, old_claim: str, old_status: ControlStatus
) -> None:
    """The file holds `pr:`, `extends:` and a checkout step, and none of them could be read.

    Two of these three answered `fail` on it and one answered `pass` -- three verdicts about a
    repository, from a file that was never parsed.
    """

    _write(tmp_path, "azure-pipelines.yml", _UNPARSEABLE)
    ctx = _ctx(tmp_path)
    assert ctx.azure_pipelines.parse_errors, "the fixture has to actually fail to parse"

    outcome = evaluate(ctx)

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert outcome.status is not old_status, f"the control still returns its pre-fix verdict {old_status}"
    assert old_claim not in outcome.reason
    assert f"{unproven} could not be confirmed" in outcome.reason
    assert "azure-pipelines.yml" in outcome.reason
    assert "/" not in outcome.reason and "\\" not in outcome.reason, "M-002: the name, never the path"


@pytest.mark.parametrize(
    ("evaluate", "signal", "expected"),
    [
        (az.eval_az_pipe_028, "pr_validation_paths", ControlStatus.PASS),
        (az.eval_az_pipe_029, "persist_credentials_true_paths", ControlStatus.FAIL),
        (az.eval_az_pipe_030, "extends_template_paths", ControlStatus.PASS),
    ],
)
def test_a_signal_read_from_a_healthy_file_survives_a_broken_sibling(
    tmp_path: Path, evaluate: Any, signal: str, expected: ControlStatus
) -> None:
    """Deferring on a parse error must not swallow what the parser did manage to read.

    A finding stands on the file it came from. Only the absence of a finding is in doubt when
    another file went unread.
    """

    healthy = _write(tmp_path, "azure-pipelines.yml", "steps: []\n")
    broken = _write(tmp_path, "pipelines/azure/broken.yml", _UNPARSEABLE)
    analysis = analyze_azure_pipelines(tmp_path)
    assert [p for p, _ in analysis.parse_errors] == [broken]
    getattr(analysis, signal).append(healthy)

    outcome = evaluate(_ctx(tmp_path, analysis))

    assert outcome.status is expected
    assert "could not be parsed" not in outcome.reason


# --------------------------------------------------------------------------- #
# "explicit persistCredentials: false confirmed" has to have been read somewhere
# --------------------------------------------------------------------------- #


def test_a_templated_persist_credentials_is_not_confirmed_as_false(tmp_path: Path) -> None:
    """The value is a parameter defaulting to true, and the only `false` sets `submodules`.

    Two words in one file are not a setting. The control still passes -- nothing showed
    `persistCredentials: true` -- but on the weaker reason and the lower confidence it earned.
    """

    _write(
        tmp_path,
        "azure-pipelines.yml",
        "parameters:\n  - name: persist\n    default: true\n"
        "steps:\n  - checkout: self\n    persistCredentials: ${{ parameters.persist }}\n    submodules: false\n",
    )

    outcome = az.eval_az_pipe_029(_ctx(tmp_path))

    assert outcome.status is ControlStatus.PASS
    assert "confirmed" not in outcome.reason
    assert outcome.confidence == "low"


@pytest.mark.parametrize(
    "step",
    [
        "  - checkout: self\n    persistCredentials: false\n",
        "  - checkout: self\n    persistCredentials:   FALSE\n",
        "  - persistCredentials: false\n    checkout: self\n",
        "  - checkout: self\n    persistCredentials: false  # deliberate\n",
    ],
)
def test_a_step_that_does_state_it_is_still_confirmed(tmp_path: Path, step: str) -> None:
    """Tightening the match must not stop crediting the repositories that got it right."""

    _write(tmp_path, "azure-pipelines.yml", f"steps:\n{step}")

    outcome = az.eval_az_pipe_029(_ctx(tmp_path))

    assert outcome.status is ControlStatus.PASS
    assert "explicit persistCredentials: false confirmed in 1 pipeline file(s)" in outcome.reason
    assert outcome.confidence == "medium"


# --------------------------------------------------------------------------- #
# the evidence helpers name the fault they found, not a neighbouring one
# --------------------------------------------------------------------------- #


def test_an_entry_that_states_no_authentication_is_not_told_the_value_is_unknown(tmp_path: Path) -> None:
    """`unknown` is a value the schema allows, so it reads as a quotation from the file.

    An operator whose entry simply omits the field goes looking for a word that is not there.
    """

    outcome = az._sconn_auth_outcome([{"name": "deploy"}], tmp_path / _EVIDENCE)

    assert outcome is not None
    assert outcome.status is ControlStatus.NOT_EVALUATED
    assert "'unknown'" not in outcome.reason
    assert "states no authentication type" in outcome.reason


def test_a_non_boolean_federation_flag_is_not_reported_as_a_missing_field(tmp_path: Path) -> None:
    """The branch above returns when the field is absent, so this one knows it is present.

    Its own remediation -- set the field to a boolean -- contradicted the reason beside it.
    """

    outcome = az._az_wif_posture_outcome({"federated_identity_preferred": "yes"}, tmp_path / _EVIDENCE)

    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "missing" not in outcome.reason
    assert "'yes'" in outcome.reason
