"""Shipped prose must not name a state the code does not produce.

Six statements had drifted into describing an older kit: `cli-reference.md` promised
`manual-review-required` for an unfilled evidence template (the code says `not-evaluated`)
while `results-guide.md` said the opposite, so two shipped pages contradicted each other;
`reports-contract-v2.0.md` called `ATTESTED` opt-in and "default off" years after
`--enable-attested` flipped on, and credited it to one evaluator when two emit it;
`framework-alignment.md` described a `required_approving_review_count` field the packaged
schema forbids outright -- that prose is what produced the wrong reader shape later fixed in
`supply_chain.py`; and the Markdown report told readers `GOV-WAIV-014` "may stay
`not-evaluated`" when it returns `manual-review-required`.

Every guard below derives its expectation by running the code -- scaffolding a template and
evaluating it, reading the Typer default, scanning evaluator sources for the emitters,
validating a document against the packaged schema. A guard that hardcoded the expected
sentence would be the same drift it exists to catch: it would agree with whichever wording
was pasted into it, right or wrong.
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from oss_policy_kit.application import reporting as rp
from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY, EvalContext
from oss_policy_kit.application.evidence_loading import load_evidence_schema
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.cli.evaluate import evaluate_cmd
from oss_policy_kit.domain.models import ControlStatus, ExecutionReport
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_DOCS = Path(__file__).resolve().parents[2] / "docs"
_CLI_REFERENCE = _DOCS / "cli-reference.md"
_CONTRACT = _DOCS / "reports-contract-v2.0.md"
_ALIGNMENT = _DOCS / "framework-alignment.md"
_ADR_022 = _DOCS / "decisions" / "adr-022-slsa-source-l2.md"

_BRANCH_PROTECTION_SCHEMA = "evidence-branch-protection.schema.json"
_APPROVER_COUNT_FIELD = "required_approving_review_count"


def _ctx(repo_root: Path, profile_id: str) -> EvalContext:
    return EvalContext(
        repo_root=repo_root,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _statuses_named(text: str) -> set[str]:
    """Every ``ControlStatus`` value the passage quotes in backticks."""

    quoted = set(re.findall(r"`([a-z-]+)`", text))
    return quoted & {s.value for s in ControlStatus}


def _paragraph_containing(doc: Path, needle: str) -> str:
    """The single blank-line-delimited block of *doc* that carries *needle*."""

    blocks = [b for b in doc.read_text(encoding="utf-8").split("\n\n") if needle in b]
    assert len(blocks) == 1, f"expected exactly one block naming {needle!r} in {doc.name}, got {len(blocks)}"
    return blocks[0]


def _lines_naming(doc: Path, needle: str) -> list[str]:
    lines = [ln for ln in doc.read_text(encoding="utf-8").splitlines() if needle in ln]
    assert lines, f"no line naming {needle!r} in {doc.name}"
    return lines


def _valid_branch_protection_document() -> dict[str, Any]:
    """A branch-protection evidence document that passes the packaged schema."""

    return {
        "schema_version": "branch-protection/v1",
        "attested_at": "2026-08-01",
        "attested_by": "appsec",
        "branch": "main",
        "protections": {
            "require_pull_request_reviews": True,
            "dismiss_stale_reviews": True,
            "require_status_checks": True,
            "enforce_admins": True,
            "restrict_force_push": True,
        },
    }


def _unfilled_template_statuses(tmp_path: Path) -> set[str]:
    """Statuses the whole registry produces for controls blocked on a scaffold placeholder."""

    scaffold_evidence_files(tmp_path, "github")
    ctx = _ctx(tmp_path, "github-level-3")
    blocked: set[str] = set()
    for evaluator in EVALUATOR_REGISTRY.values():
        outcome = evaluator(ctx)
        placeholder_warnings = [w for w in outcome.operational_warnings if "placeholder" in w]
        if placeholder_warnings:
            blocked.add(outcome.status.value)
    assert blocked, "no control reported a placeholder block against a freshly scaffolded template"
    return blocked


def _attested_emitting_control_ids() -> set[str]:
    """Control ids whose evaluator can return ``ControlStatus.ATTESTED``."""

    emitters = {cid for cid, fn in EVALUATOR_REGISTRY.items() if "ControlStatus.ATTESTED" in inspect.getsource(fn)}
    assert emitters, "no bundled evaluator emits ATTESTED -- the docs below describe a state nothing produces"
    return emitters


def _enable_attested_default() -> bool:
    """The shipped default of ``evaluate --enable-attested``, read off the Typer option."""

    option = inspect.signature(evaluate_cmd).parameters["enable_attested"].default
    default = option.default
    assert isinstance(default, bool)
    return default


def test_cli_reference_names_the_status_an_unfilled_template_produces(tmp_path: Path) -> None:
    produced = _unfilled_template_statuses(tmp_path)
    assert len(produced) == 1, f"placeholder handling is no longer one status: {sorted(produced)}"
    caveat = _paragraph_containing(_CLI_REFERENCE, "unfilled template")
    assert _statuses_named(caveat) == produced, "cli-reference.md names a status unfilled templates do not produce"


def test_cli_reference_keeps_the_results_guide_deep_link_resolving() -> None:
    caveat = _paragraph_containing(_CLI_REFERENCE, "unfilled template")
    anchor = re.search(r"\(results-guide\.md#([a-z0-9-]+)\)", caveat)
    assert anchor is not None, "the results-guide deep link was dropped from the template caveat"
    headings = re.findall(r"^#+ (.+)$", (_DOCS / "results-guide.md").read_text(encoding="utf-8"), flags=re.M)
    slugs = {re.sub(r"[^a-z0-9]+", "-", h.lower()).strip("-") for h in headings}
    assert anchor.group(1) in slugs, f"results-guide.md has no heading matching #{anchor.group(1)}"


def test_reports_contract_names_every_evaluator_that_emits_attested() -> None:
    lines = _lines_naming(_CONTRACT, "`ATTESTED`")
    named = " ".join(lines)
    missing = sorted(cid for cid in _attested_emitting_control_ids() if cid not in named)
    assert missing == [], f"reports-contract-v2.0.md credits ATTESTED to too few controls; missing {missing}"


def test_reports_contract_describes_the_shipped_enable_attested_default() -> None:
    # The derived default picks which side of the claim must hold, so flipping the flag in
    # evaluate.py fails this test until the contract page is rewritten to match.
    default = _enable_attested_default()
    required_flag, forbidden_claim = {
        True: ("--no-enable-attested", "default off"),
        False: ("--enable-attested", "default on"),
    }[default]
    described = " ".join(_lines_naming(_CONTRACT, "enable-attested")).lower()
    assert required_flag in described, f"the contract page never tells readers about {required_flag}"
    assert forbidden_claim not in described, f"the contract page still claims {forbidden_claim!r}"


def test_cli_reference_states_the_shipped_default_of_every_flag_it_rates() -> None:
    # `--enable-attested` and `--applicability-engine` both flipped on in v8.0.0 and the table
    # kept calling both "default off". Reading the polarity out of Typer covers every flag the
    # page rates, so the next flip fails here rather than shipping a page nobody re-read.
    parameters = inspect.signature(evaluate_cmd).parameters
    rated = re.findall(r"`--([a-z-]+)` \(default (off|on)", _CLI_REFERENCE.read_text(encoding="utf-8"))
    assert rated, "the CLI reference no longer states a default for any flag"
    wrong: list[str] = []
    for flag, claimed in rated:
        parameter = parameters[flag.replace("-", "_")]
        if parameter.default.default is not (claimed == "on"):
            wrong.append(f"--{flag} is documented as default {claimed}")
    assert wrong == [], f"cli-reference.md misstates a shipped default: {wrong}"


#: A reference-table row: `| `command` | required | optional | description |`
_TABLE_ROW = re.compile(r"^\|\s*`(?P<command>[a-z][a-z0-9-]*)`\s*\|(?P<rest>.*)\|\s*$")

#: `--include` (csv glob, default `**/*.yaml`/`**/*.yml`) -- a VALUE default, written as a run of
#: backticked tokens separated by slashes.
_VALUE_DEFAULT = re.compile(
    r"`--(?P<flag>[a-z][a-z0-9-]*)`\s*\([^)]*?default\s+(?P<values>`[^`)]+`(?:\s*/\s*`[^`)]+`)*)"
)


def _documented_value_defaults() -> list[tuple[str, str, list[str]]]:
    """(command, flag, documented values) for every value default the reference table states."""

    out: list[tuple[str, str, list[str]]] = []
    for line in _CLI_REFERENCE.read_text(encoding="utf-8").splitlines():
        row = _TABLE_ROW.match(line)
        if not row:
            continue
        columns = [c.strip() for c in row.group("rest").split("|")]
        for match in _VALUE_DEFAULT.finditer(" ".join(columns[:2])):
            values = re.findall(r"`([^`]+)`", match.group("values"))
            out.append((row.group("command"), match.group("flag"), values))
    return out


def test_cli_reference_states_the_shipped_value_of_every_default_it_spells_out() -> None:
    """A documented default that is missing an entry costs coverage in silence.

    The sibling guard above reads the polarity of BOOLEAN defaults, and only off `evaluate`. It
    was green while `scan-cfn --include` was documented as `**/*.yml`/`**/*.yaml`/`**/*.json`,
    three quarters of the truth: the shipped default also carries `**/*.template`. An adopter
    pinning the documented default into CI stops scanning CloudFormation `.template` files and
    nothing tells them -- the scan still succeeds, over fewer files.

    Only comma-separated string defaults are compared, because those are the ones where "the
    documented list" and "the shipped list" are the same kind of thing. Anything else is skipped
    rather than guessed at, and the count assertion below keeps that skip from swallowing the
    whole check.
    """

    import typer.main

    from oss_policy_kit.cli.main import app

    commands = typer.main.get_command(app).commands
    compared: list[str] = []
    wrong: list[str] = []
    for command, flag, documented in _documented_value_defaults():
        params = {p.name: p for p in commands[command].params} if command in commands else {}
        parameter = params.get(flag.replace("-", "_"))
        if parameter is None or not isinstance(parameter.default, str) or "," not in parameter.default:
            continue
        shipped = [piece.strip() for piece in parameter.default.split(",")]
        compared.append(f"{command} --{flag}")
        if sorted(shipped) != sorted(documented):
            wrong.append(f"{command} --{flag}: documented {documented}, ships {shipped}")

    assert compared, "no comma-separated default was compared; the pattern stopped matching the table"
    assert wrong == [], f"cli-reference.md misstates a shipped default: {wrong}"


def test_markdown_report_names_the_status_gov_waiv_014_returns(tmp_path: Path) -> None:
    returned = EVALUATOR_REGISTRY["GOV-WAIV-014"](_ctx(tmp_path, "github-level-3")).status
    report = ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-08-01T00:00:00Z",
        kit_version="10.0.13",
        target_path="repo",
        profile_id="github-level-3",
        profile_title="Title",
        summary_by_status={returned.value: 1},
        results=[],
        operational_warnings=[],
        external_waiver_path="waivers/external.yaml",
    )
    rendered = rp._markdown_report_text(report)
    sentence = next(ln for ln in rendered.splitlines() if "GOV-WAIV-014" in ln and "inside the clone" in ln)
    assert _statuses_named(sentence) == {returned.value}, "the report tells readers a state GOV-WAIV-014 never returns"


def test_framework_alignment_promises_no_field_the_schema_rejects() -> None:
    schema = load_evidence_schema(_BRANCH_PROTECTION_SCHEMA)
    validator = Draft202012Validator(schema)
    accepted = _valid_branch_protection_document()
    assert list(validator.iter_errors(accepted)) == [], "the baseline document no longer passes the packaged schema"
    for carrier in (accepted, accepted["protections"]):
        with_count = json.loads(json.dumps(accepted))
        target = with_count if carrier is accepted else with_count["protections"]
        target[_APPROVER_COUNT_FIELD] = 2
        assert list(validator.iter_errors(with_count)), f"the schema now accepts {_APPROVER_COUNT_FIELD}"
    assert _APPROVER_COUNT_FIELD not in _ALIGNMENT.read_text(encoding="utf-8"), (
        f"framework-alignment.md still offers {_APPROVER_COUNT_FIELD}, which the schema forbids"
    )


def test_framework_alignment_names_the_status_slsa_src_007_returns(tmp_path: Path) -> None:
    evidence = tmp_path / ".oss-policy-kit" / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "branch-protection.json").write_text(json.dumps(_valid_branch_protection_document()), encoding="utf-8")
    returned = EVALUATOR_REGISTRY["SLSA-SRC-007"](_ctx(tmp_path, "slsa-source-l2-1")).status
    row = _lines_naming(_ALIGNMENT, "`SLSA-SRC-007`")
    assert len(row) == 1, "SLSA-SRC-007 is described in more than one row; they can disagree"
    assert returned.value in row[0], "framework-alignment.md rates SLSA-SRC-007 above what it answers with evidence"


def test_control_status_comment_names_every_evaluator_that_emits_attested() -> None:
    source = inspect.getsource(ControlStatus)
    comment = source[: source.index('ATTESTED = "attested"')].rpartition("SELF_ATTESTED")[2]
    missing = sorted(cid for cid in _attested_emitting_control_ids() if cid not in comment)
    assert missing == [], f"the ATTESTED comment in models.py still reads as unemitted; missing {missing}"


def test_gh_immutrel_070_docstring_names_the_status_the_absent_file_produces(tmp_path: Path) -> None:
    evaluator = EVALUATOR_REGISTRY["GH-IMMUTREL-070"]
    returned = evaluator(_ctx(tmp_path, "github-release-hardening-2")).status
    docstring = inspect.getdoc(evaluator) or ""
    absent_clause = re.search(r"is absent -> (.+?);", docstring, flags=re.S)
    assert absent_clause is not None, "the docstring no longer says what an absent evidence file produces"
    assert returned.value in " ".join(absent_clause.group(1).split()), (
        "the docstring names a state GH-IMMUTREL-070 does not return for an absent file"
    )
    assert "GH-IMMUTREL-070" in _attested_emitting_control_ids()
    assert "deferred" not in docstring, "the docstring calls ATTESTED deferred while this function emits it"


def test_adr_022_amendment_uses_the_field_names_the_schema_defines() -> None:
    protections = load_evidence_schema(_BRANCH_PROTECTION_SCHEMA)["properties"]["protections"]["properties"]
    text = _ADR_022.read_text(encoding="utf-8")
    head, _, amendment = text.partition("## Amendment")
    assert amendment, "ADR-022 still defines SLSA-SRC-006/007 on a shape the schema forbids, with no amendment"
    assert _APPROVER_COUNT_FIELD in head, "the historical Decision was rewritten; amend it instead"
    for flag in ("require_signed_commits", "require_pull_request_reviews"):
        assert flag in protections, f"{flag} left the schema; the amendment now describes a field that is gone"
        assert f"protections.{flag}" in amendment, f"the amendment never names protections.{flag}"
