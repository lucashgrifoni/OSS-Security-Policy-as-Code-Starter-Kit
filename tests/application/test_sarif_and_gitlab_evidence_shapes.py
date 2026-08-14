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
from typing import Any

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


@pytest.mark.parametrize("value", ['"2"', '"two"', "[2]", '{"n": 2}', "null", "true", "1.5"])
def test_a_non_integer_min_approvers_does_not_crash_the_run(value: str, tmp_path: Path) -> None:
    """``data.get("min_approvers", 0) >= 1`` compared whatever was there against an int.

    ``"min_approvers": "2"`` -- what a shell or a spreadsheet export produces -- raised
    TypeError, which is not input-shaped, so the whole run died at exit 3 with no report.

    ``true`` is here because ``True >= 1`` is true in Python and is not two reviewers, and
    ``1.5`` because the shipped schema says integer. Both used to report PASS.

    The message now comes from schema validation rather than a hand-rolled type check, so
    this asserts what has to hold in either design: no crash, no PASS, and a reason that
    names the field rather than denying the file exists.
    """

    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True)
    payload = {**_VALID_MR_RULES}
    payload.pop("min_approvers")
    body = json.dumps(payload)[:-1] + f', "min_approvers": {value}}}'
    (evidence_dir / "gitlab-mr-rules.json").write_text(body, encoding="utf-8")

    outcome = gitlab.eval_gl_pipe_011(_ctx(tmp_path))

    assert outcome.status.value != "pass", "a value that is not a whole number cannot document approvals"
    # Asserting only the status let a false sentence through once already: an earlier version
    # exited via the shared fall-through, which tells the operator there is NO evidence file
    # -- about a file that is right there and was just parsed -- and attached no reference to
    # it. Adversarial review caught it because this assertion was missing.
    assert "min_approvers" in outcome.reason, outcome.reason
    assert "No .oss-policy-kit" not in outcome.reason, f"the file exists and was read: {outcome.reason}"
    assert outcome.evidence_sources, "the outcome must point at the file it actually read"


def test_an_absent_evidence_file_still_says_it_is_absent(tmp_path: Path) -> None:
    """The counterpart. Splitting the exits must not make the absent case lie the other way."""

    outcome = gitlab.eval_gl_pipe_011(_ctx(tmp_path))

    assert outcome.status.value != "pass"
    assert "No .oss-policy-kit/evidence/gitlab-mr-rules.json evidence" in outcome.reason
    assert outcome.evidence_sources == []


# --------------------------------------------------------------------------- #
# GL-PIPE-011 against its own shipped schema
#
# The contract for this file shipped in the wheel and in reports/schema/ from the day the
# control was written, and nothing ever loaded it. Hand-rolled checks stood in its place and
# let four things through, each verified before the fix: an untouched scaffold reported PASS,
# a file missing a required field reported PASS, a foreign `schema_version` reported PASS, and
# `min_approvers: 1.5` reported PASS although the schema says integer.
# --------------------------------------------------------------------------- #

_VALID_MR_RULES: dict[str, Any] = {
    "schema_version": "gitlab-mr-rules/v1",
    "attested_at": "2026-08-14",
    "attested_by": "lucas",
    "project": "group/project",
    "min_approvers": 2,
    "code_owner_approval_required": True,
    "reset_approvals_on_push": True,
}


def _mr_rules(tmp_path: Path, payload: dict[str, Any]) -> Path:
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "gitlab-mr-rules.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def test_an_untouched_scaffold_does_not_earn_a_pass(tmp_path: Path) -> None:
    """The scaffold ships `min_approvers: 2`, so it passed on the strength of a template.

    This is the family the project keeps hunting: the kit granting credit for a file nobody
    filled in. `REPLACE_ME_GITLAB_USER` was right there in the evidence.
    """

    scaffold = {**_VALID_MR_RULES, "attested_by": "REPLACE_ME_GITLAB_USER", "project": "REPLACE_ME_GROUP/REPLACE_ME"}

    outcome = gitlab.eval_gl_pipe_011(_ctx(_mr_rules(tmp_path, scaffold)))

    assert outcome.status.value != "pass"
    assert "placeholder" in outcome.reason.lower(), outcome.reason


def test_documented_zero_approvers_is_a_finding_not_a_missing_file(tmp_path: Path) -> None:
    """`min_approvers: 0` is readable evidence that the protection is off.

    It used to fall through to "No ... evidence" -- the kit hiding a real finding behind a
    sentence denying the file exists. ADR-045 reserves manual-review for evidence that cannot
    be READ; this reads fine and says merges need no approval.
    """

    outcome = gitlab.eval_gl_pipe_011(_ctx(_mr_rules(tmp_path, {**_VALID_MR_RULES, "min_approvers": 0})))

    assert outcome.status.value == "fail", outcome.status
    assert "min_approvers=0" in outcome.reason
    assert outcome.evidence_sources


@pytest.mark.parametrize(
    ("label", "mutation"),
    [
        ("non_integer", {"min_approvers": 1.5}),
        ("foreign_schema_version", {"schema_version": "something-else/v9"}),
        ("unknown_property", {"min_approverz": 2}),
    ],
)
def test_evidence_that_violates_the_shipped_schema_is_not_a_pass(
    label: str, mutation: dict[str, Any], tmp_path: Path
) -> None:
    outcome = gitlab.eval_gl_pipe_011(_ctx(_mr_rules(tmp_path, {**_VALID_MR_RULES, **mutation})))

    assert outcome.status.value != "pass", f"{label}: {outcome.reason}"
    assert "schema" in outcome.reason.lower(), outcome.reason


def test_a_missing_required_field_is_not_a_pass(tmp_path: Path) -> None:
    payload = {k: v for k, v in _VALID_MR_RULES.items() if k != "project"}

    outcome = gitlab.eval_gl_pipe_011(_ctx(_mr_rules(tmp_path, payload)))

    assert outcome.status.value != "pass"
    assert "project" in outcome.reason


def test_valid_evidence_still_passes(tmp_path: Path) -> None:
    """Without this, every test above is satisfied by a control that never passes."""

    outcome = gitlab.eval_gl_pipe_011(_ctx(_mr_rules(tmp_path, _VALID_MR_RULES)))

    assert outcome.status.value == "pass"
    assert "min_approvers=2" in outcome.reason


def test_what_the_kit_itself_writes_satisfies_the_schema() -> None:
    """A contract the kit's own producers violate is a contract that will be turned off.

    Wiring the schema in is only safe if `scaffold-evidence` and `collect-evidence` already
    emit documents that satisfy it. The scaffold is checked through the evaluator, where its
    placeholders are the expected outcome; the collector payload is checked against the schema
    directly, since producing one needs a live GitLab.
    """

    from jsonschema import Draft202012Validator

    from oss_policy_kit.application.evaluators._shared import _gitlab_mr_rules_schema

    collector_payload = {
        **_VALID_MR_RULES,
        "collection": {
            "evidence_collection_method": "live",
            "collected_at": "2026-08-14T00:00:00Z",
            "source_url": "https://gitlab.example/api/v4/projects/1/approval_rules",
            "mode": "api",
        },
        "notes": "Derived from GitLab project approvals + approval_rules APIs.",
    }

    errors = list(Draft202012Validator(_gitlab_mr_rules_schema()).iter_errors(collector_payload))

    assert not errors, [e.message for e in errors]


def _ctx(repo_root: Path) -> EvalContext:
    return EvalContext(
        repo_root=repo_root,
        profile_id="gitlab-level-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )
