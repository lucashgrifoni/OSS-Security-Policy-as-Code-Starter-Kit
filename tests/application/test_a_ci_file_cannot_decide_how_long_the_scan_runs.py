"""A CI file's cost must be bounded by a limit the kit sets, not by the size a fork chose.

This is the other half of `test_a_small_file_cannot_buy_unbounded_work`. That one covers a small
file that expands; this one covers a file that is simply large. The two guards are not
substitutes: the expansion guard lives inside `load_yaml_file` and runs on a *parsed* document,
so it can only refuse a file the process has already paid to read and parse, and the raw text
scan in three of the parsers runs before `load_yaml_file` is reached at all.

`input_limits` has named bytes-on-disk as a threat since v6 -- "an oversized file in an adopter
repository can inflate memory use or slow CI" -- and every operator-facing loader carries a cap
for it: evidence, SARIF, config, profile, Scorecard. The files this product exists to read did
not. Measured on this tree, `evaluate` against a repository holding one workflow:

    0.52 MiB  =   2.12s
    2.08 MiB  =   6.66s
    8.32 MiB  =  24.05s

Linear, about three seconds per MiB, with no ceiling. The largest CI file in this repository is
34 KiB, so the cap sits about thirty times above anything honest.

The assertions are behavioural rather than timed: an oversize file must be REFUSED and recorded
as a parse error, which is what `parse_errors` already means everywhere else and what ADR-045
turns into `manual-review-required` rather than a verdict about the repository.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oss_policy_kit.adapters.scorecard_json import load_scorecard_auto
from oss_policy_kit.application.input_limits import MAX_CI_CONFIG_BYTES, MAX_EVIDENCE_BYTES
from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

#: A mutable action reference. Any parser half that reads the raw text of a workflow records
#: this, so its ABSENCE from a result is proof the file was refused before it was read.
TELLTALE = "      - uses: some-vendor/publish@main\n"


def _padded(head: str, filler: str, total: int) -> str:
    """A syntactically valid document of at least *total* bytes, built by repeating *filler*."""

    body = filler * (1 + (total - len(head)) // len(filler))
    return head + body


def _oversize_workflow() -> str:
    return _padded(
        "name: ci\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + TELLTALE,
        "      - name: pad\n        run: echo pad\n",
        MAX_CI_CONFIG_BYTES + 1,
    )


def test_the_shared_loader_refuses_a_file_larger_than_the_cap(tmp_path: Path) -> None:
    """`load_yaml_file` is the funnel every CI parser reads through, so the size check belongs there.

    A `yaml.YAMLError` is raised on purpose rather than a new exception type, for the same reason
    the expansion guard does it: every call site already catches parse failures, and
    `BAD_INPUT_ERRORS` already lists `yaml.YAMLError`.
    """

    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(_padded("build:\n  script:\n", "    - echo pad\n", MAX_CI_CONFIG_BYTES + 1), encoding="utf-8")

    with pytest.raises(yaml.YAMLError) as excinfo:
        load_yaml_file(path)

    assert "exceeding" in str(excinfo.value)


def test_the_cap_is_the_boundary_and_not_a_byte_either_side(tmp_path: Path) -> None:
    """A file AT the cap is honest input; one byte past it is not.

    Written as one test over both sides on purpose: a guard that refuses everything passes any
    test that only feeds it the hostile case.
    """

    at_cap = tmp_path / "at.yml"
    at_cap.write_bytes(b"a: " + b"x" * (MAX_CI_CONFIG_BYTES - 4) + b"\n")
    over = tmp_path / "over.yml"
    over.write_bytes(b"a: " + b"x" * (MAX_CI_CONFIG_BYTES - 3) + b"\n")

    assert at_cap.stat().st_size == MAX_CI_CONFIG_BYTES
    assert over.stat().st_size == MAX_CI_CONFIG_BYTES + 1

    assert load_yaml_file(at_cap)["a"].startswith("xxx")
    with pytest.raises(yaml.YAMLError):
        load_yaml_file(over)


@pytest.mark.parametrize(
    ("relative", "head", "filler", "analyze"),
    [
        (
            ".github/workflows/ci.yml",
            "name: ci\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n",
            "      - name: pad\n        run: echo pad\n",
            analyze_workflows,
        ),
        (".gitlab-ci.yml", "build:\n  script:\n", "    - echo pad\n", analyze_gitlab_ci),
        ("azure-pipelines.yml", "steps:\n", "  - script: echo pad\n", analyze_azure_pipelines),
        (
            "buildspec.yml",
            "version: 0.2\nphases:\n  build:\n    commands:\n",
            "      - echo pad\n",
            analyze_aws_ci,
        ),
    ],
)
def test_a_ci_parser_records_an_oversize_file_as_unreadable(
    tmp_path: Path,
    relative: str,
    head: str,
    filler: str,
    analyze: object,
) -> None:
    """Every parser reached by `evaluate` must refuse the file, not read it.

    The GitHub workflow parser is present here and absent from the expansion sibling, and the
    difference is the point: it never recurses, so an alias bomb costs it nothing, but it reads
    the raw text whole before it parses -- which is exactly what bytes-on-disk charges for.
    """

    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_padded(head, filler, MAX_CI_CONFIG_BYTES + 1), encoding="utf-8")

    result = analyze(tmp_path)  # type: ignore[operator]

    assert result.parse_errors, f"{relative} was read instead of refused"
    assert any("exceeding" in message for _, message in result.parse_errors)


def test_a_refused_workflow_is_refused_before_its_text_is_scanned(tmp_path: Path) -> None:
    """The guard has to sit ahead of the raw scan, or it arrives after the cost it exists to avoid.

    `mutable_action_refs` is the oracle: it is filled only by a pass over the workflow's raw
    text, so a mutable ref planted in the file appearing in the result would mean the file was
    read in full and the cap only stopped the parse -- which is most of the work, not the guard.
    """

    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(_oversize_workflow(), encoding="utf-8")
    assert TELLTALE in workflow.read_text(encoding="utf-8")

    result = analyze_workflows(tmp_path)

    assert result.parse_errors
    assert result.mutable_action_refs == []


def test_a_codepipeline_export_written_as_json_is_capped_too(tmp_path: Path) -> None:
    """The JSON branch never touches `load_yaml_file`, so the funnel fix does not reach it.

    Left out, it would be the one shape of CI config still able to buy unbounded work -- and the
    only one where the same file is then read twice more, by the stub check and the loader.
    """

    export = tmp_path / "pipelines" / "aws" / "codepipeline.json"
    export.parent.mkdir(parents=True, exist_ok=True)
    padding = "x" * (MAX_CI_CONFIG_BYTES + 1)
    export.write_text('{"pipeline": {"name": "' + padding + '"}}', encoding="utf-8")

    result = analyze_aws_ci(tmp_path)

    assert any("exceeding" in message for _, message in result.parse_errors)
    assert result.codepipeline_valid_export_paths == []


def test_the_largest_ci_file_in_this_repository_is_nowhere_near_the_cap() -> None:
    """The cap has to be generous enough that no real file meets it.

    If a change ever brings one of this project's own workflows close to the ceiling, this fails
    before an adopter's file does.
    """

    workflows = sorted(Path(".github/workflows").glob("*.yml"))
    if not workflows:  # pragma: no cover - only when run outside a source checkout
        pytest.skip("workflows not present in this layout")

    largest = max(path.stat().st_size for path in workflows)

    assert largest < MAX_CI_CONFIG_BYTES // 10


def test_an_ordinary_workflow_is_still_read(tmp_path: Path) -> None:
    """The guard must cost an honest file nothing, including the finding it is supposed to report."""

    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: ci\non:\n  push:\npermissions:\n  contents: read\njobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n    steps:\n" + TELLTALE,
        encoding="utf-8",
    )

    result = analyze_workflows(tmp_path)

    assert result.parse_errors == []
    assert [ref for _, ref in result.mutable_action_refs] == ["some-vendor/publish@main"]


def test_a_scorecard_document_keeps_the_larger_ceiling_it_already_had(tmp_path: Path) -> None:
    """A Scorecard file is evidence the operator supplied, not CI config a fork wrote.

    Its own boundary admits five times as much, and it checks that before it calls the loader.
    Letting the CI default reach it would have narrowed a contract that is not at fault here --
    the kind of quiet collateral a shared funnel makes easy.
    """

    big = MAX_CI_CONFIG_BYTES * 2
    assert big < MAX_EVIDENCE_BYTES

    path = tmp_path / "scorecard.yaml"
    path.write_text(
        "date: '2026-01-01'\nrepo:\n  name: example.com/o/r\nscore: 7.5\nchecks:\n"
        "  - name: Pinned-Dependencies\n    score: 7\n    reason: '" + "x" * big + "'\n",
        encoding="utf-8",
    )
    assert path.stat().st_size > MAX_CI_CONFIG_BYTES

    bundle = load_scorecard_auto(path)

    assert bundle.aggregate_score == 7.5
    assert [check.name for check in bundle.checks] == ["Pinned-Dependencies"]
