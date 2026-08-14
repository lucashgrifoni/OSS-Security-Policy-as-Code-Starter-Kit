"""The exit-3 class, third round: the SARIF reader and one GitLab number.

The wave that routed six evaluators through a shared reader stopped one file short. The SARIF
adapter in ``evaluators/_shared.py`` was never migrated, and it is read by four controls across
eight shipped profiles -- so it had the widest blast radius of anything found this cycle, and
``evaluate-many`` aborted an entire fleet on the first bad file.

Its guard could not protect the test it preceded:

    if (
        not isinstance(doc, dict) or doc.get("$schema", "").endswith("...json") is False
    ) and "runs" not in doc:

When ``doc`` is not a mapping, ``not isinstance(...)`` is True, short-circuits the ``or``, and
thereby FORCES ``"runs" not in doc`` to run against the very non-mapping it just detected.

The inputs are not exotic. These files come from third-party tools and from adopter ``jq``
glue: ``jq -s '.[0]' *.sarif`` over an empty glob writes literally ``null``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import _shared, gitlab
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

#: Every JSON value that is valid but is not an object.
NOT_AN_OBJECT: tuple[tuple[str, str], ...] = (
    ("empty_array", "[]"),
    ("array", "[1, 2]"),
    ("string", '"a string"'),
    ("string_containing_runs", '"see runs below"'),
    ("number", "42"),
    ("float", "1.5"),
    ("null", "null"),
    ("true", "true"),
    ("false", "false"),
)


@pytest.mark.parametrize(("label", "body"), NOT_AN_OBJECT, ids=[r[0] for r in NOT_AN_OBJECT])
def test_a_non_object_sarif_root_is_an_error_string_not_an_exception(label: str, body: str, tmp_path: Path) -> None:
    path = tmp_path / "scan.sarif.json"
    path.write_text(body, encoding="utf-8")

    runs, error = _shared._load_sarif_runs(path)

    assert runs is None
    assert error and "JSON object" in error, error
    # M-002: the message must not name where the file lives.
    assert "/" not in error and "\\" not in error, error


@pytest.mark.parametrize("schema", [210, None, ["x"], {"a": 1}, 1.5, True])
def test_a_non_string_schema_does_not_raise(schema: object, tmp_path: Path) -> None:
    """``.endswith`` was evaluated on whatever ``$schema`` held, before the ``and``."""

    path = tmp_path / "scan.sarif.json"
    path.write_text(json.dumps({"$schema": schema, "runs": []}), encoding="utf-8")

    runs, error = _shared._load_sarif_runs(path)

    assert error is None, error
    assert runs == []


def test_a_declared_sarif_schema_is_still_accepted_without_runs(tmp_path: Path) -> None:
    """The counterpart, so the tests above cannot pass by rejecting everything."""

    path = tmp_path / "scan.sarif.json"
    path.write_text(json.dumps({"$schema": "https://example.test/sarif-schema-2.1.0.json"}), encoding="utf-8")

    runs, error = _shared._load_sarif_runs(path)

    assert error is None, error
    assert runs == []


@pytest.mark.parametrize("tool", ["semgrep", 42, ["driver"], True])
def test_a_truthy_non_object_tool_does_not_raise(tool: object) -> None:
    """``((run.get("tool") or {}).get("driver") or {})`` substitutes only for a FALSY value.

    A SARIF run whose ``tool`` is a bare string -- which a hand-merged or converter-produced
    document can carry -- went straight through to ``.get`` and raised.
    """

    assert _shared._sarif_rule_levels({"tool": tool, "results": []}) == {}


def test_a_well_formed_run_still_yields_its_rule_levels() -> None:
    run = {"tool": {"driver": {"rules": [{"id": "R1", "defaultConfiguration": {"level": "error"}}]}}}

    assert _shared._sarif_rule_levels(run) == {"R1": "error"}


@pytest.mark.parametrize("default_config", ["error", 3, ["error"]])
def test_a_truthy_non_object_default_configuration_does_not_raise(default_config: object) -> None:
    run = {"tool": {"driver": {"rules": [{"id": "R1", "defaultConfiguration": default_config}]}}}

    assert _shared._sarif_rule_levels(run) == {}


# --------------------------------------------------------------------------- #
# GL-PIPE-011
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ['"2"', '"two"', "[2]", '{"n": 2}', "null"])
def test_a_non_numeric_min_approvers_does_not_crash_the_run(value: str, tmp_path: Path) -> None:
    """``data.get("min_approvers", 0) >= 1`` compared whatever was there against an int.

    ``"min_approvers": "2"`` -- what a shell or a spreadsheet export produces -- raised
    TypeError, which is not input-shaped, so the whole run died at exit 3 with no report.
    """

    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "gitlab-mr-rules.json").write_text(f'{{"min_approvers": {value}}}', encoding="utf-8")

    outcome = gitlab.eval_gl_pipe_011(_ctx(tmp_path))

    assert outcome.status.value != "pass", "a value that is not a number cannot document approvals"
    # Asserting only the status let a false sentence through: the first version of this fix
    # exited via the shared fall-through, which tells the operator there is NO evidence file
    # -- about a file that is right there and was just parsed -- and attached no reference to
    # it. Adversarial review caught it because this assertion was missing.
    assert "present" in outcome.reason, outcome.reason
    assert "No " not in outcome.reason, f"the file exists and was read: {outcome.reason}"
    assert outcome.evidence_sources, "the outcome must point at the file it actually read"


def test_a_numeric_min_approvers_still_passes(tmp_path: Path) -> None:
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "gitlab-mr-rules.json").write_text('{"min_approvers": 2}', encoding="utf-8")

    outcome = gitlab.eval_gl_pipe_011(_ctx(tmp_path))

    assert outcome.status.value == "pass"
    assert "min_approvers=2" in outcome.reason


def test_a_boolean_min_approvers_is_not_a_number_of_approvers(tmp_path: Path) -> None:
    """``True >= 1`` is true in Python. It is not two reviewers."""

    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "gitlab-mr-rules.json").write_text('{"min_approvers": true}', encoding="utf-8")

    outcome = gitlab.eval_gl_pipe_011(_ctx(tmp_path))

    assert outcome.status.value != "pass"
    assert "bool" in outcome.reason, outcome.reason


def test_an_absent_evidence_file_still_says_it_is_absent(tmp_path: Path) -> None:
    """The counterpart. Splitting the exits must not make the absent case lie the other way."""

    outcome = gitlab.eval_gl_pipe_011(_ctx(tmp_path))

    assert outcome.status.value != "pass"
    assert "No .oss-policy-kit/evidence/gitlab-mr-rules.json evidence" in outcome.reason
    assert outcome.evidence_sources == []


def _ctx(repo_root: Path) -> EvalContext:
    return EvalContext(
        repo_root=repo_root,
        profile_id="gitlab-level-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )
