"""A YAML file's cost must be bounded by what it says, not by what it expands to.

`input_limits` already names this threat in its own module docstring -- "an oversized file in an
adopter repository can inflate memory use or slow CI... the response is a clear refusal" -- and
answers it with two measurements: bytes on disk (`MAX_EVIDENCE_BYTES`) and bracket-nesting depth
(`MAX_JSON_DEPTH`). A YAML alias bomb defeats both by construction. It is 399 bytes and its
bracket depth is 1. Neither guard has anything to look at.

The reason it still costs minutes is that PyYAML resolves an alias to the *same object*, so a
document that reads as a tree is really a DAG, and a walker with no notion of node identity
re-descends every shared node once per path that reaches it. Measured on this tree before this
test existed, at fan-out 8:

    depth 6  =  315 bytes  =  2.1M nodes  =   1.0s
    depth 7  =  357 bytes  = 16.8M nodes  =  11.1s
    depth 8  =  399 bytes  =  134M nodes  =  over the 20s cap

The parse itself stays flat at ~0.02s across all of them, which is what pins the cost on the
kit's traversal rather than on PyYAML.

This matters here specifically because the product's whole premise is reading a repository
nobody vouched for -- a fork, a vendor drop, a PR branch -- inside CI. A 399-byte file in that
repository is enough to hang the scanner.

The assertion is behavioural rather than timed: a bomb must be REFUSED and recorded as a parse
error, which is what `parse_errors` already means everywhere else, and what ADR-045 turns into
`manual-review-required` rather than a verdict about the repository. Depth 6 is used on purpose
-- it is unmistakably a bomb, and a failing run costs about a second instead of minutes.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oss_policy_kit.application.evaluators._shared import _update_config_names
from oss_policy_kit.application.input_limits import (
    MAX_CONFIG_BYTES,
    MAX_EXPANDED_NODES,
    expanded_node_count,
    load_capped_document,
)
from oss_policy_kit.domain.errors import InvalidInputError
from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

FAN = 8


def _bomb(depth: int, tail: str) -> str:
    """A YAML document that reads as ``depth`` short lines and expands to ``FAN ** (depth+1)`` nodes."""

    lines = ['a0: &a0 ["x","x","x","x","x","x","x","x"]']
    for level in range(1, depth + 1):
        refs = ",".join(f"*a{level - 1}" for _ in range(FAN))
        lines.append(f"a{level}: &a{level} [{refs}]")
    return "\n".join(lines) + "\n" + tail.format(anchor=f"*a{depth}")


def test_the_counter_charges_an_alias_for_everything_it_expands_to() -> None:
    """An alias costs what it expands to, not the four bytes it is written with."""

    doc = yaml.safe_load(_bomb(6, "build:\n  script: {anchor}\n"))

    assert expanded_node_count(doc) > MAX_EXPANDED_NODES


def test_the_counter_does_not_charge_a_repeated_scalar_as_if_it_were_deep() -> None:
    """Sharing is not by itself suspicious -- the count must follow expansion, not object reuse.

    Both documents below expand to the same thing; only one of them writes it out. If the counter
    charged by unique objects instead, an alias would be free and the guard would never fire.
    """

    aliased = yaml.safe_load("a: &a [1, 2, 3]\nb: *a\nc: *a\n")
    written = yaml.safe_load("a: [1, 2, 3]\nb: [1, 2, 3]\nc: [1, 2, 3]\n")

    assert expanded_node_count(aliased) == expanded_node_count(written)


def test_the_largest_honest_file_in_this_repository_is_nowhere_near_the_limit() -> None:
    """The limit has to be generous enough that no real file meets it.

    The control catalogue is the biggest YAML this project ships (226 controls, ~57 KB) and it
    counts about 3.7k nodes. If a change ever brings a real file close to the cap, this fails
    before an adopter's file does.
    """

    catalog = Path("src/oss_policy_kit/data/controls/catalog.yaml")
    if not catalog.is_file():  # pragma: no cover - only when run outside a source checkout
        pytest.skip("catalogue not present in this layout")

    assert expanded_node_count(yaml.safe_load(catalog.read_text(encoding="utf-8"))) < MAX_EXPANDED_NODES // 100


def test_the_shared_loader_refuses_a_bomb_instead_of_walking_it(tmp_path: Path) -> None:
    """`load_yaml_file` is the funnel every CI parser reads through, so the refusal belongs there.

    A `yaml.YAMLError` is raised on purpose rather than a new exception type: every call site
    already catches parse failures, and `BAD_INPUT_ERRORS` already lists `yaml.YAMLError`, so the
    refusal reaches the existing "could not read this" path without new plumbing.
    """

    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(_bomb(6, "build:\n  script: {anchor}\n"), encoding="utf-8")

    with pytest.raises(yaml.YAMLError) as excinfo:
        load_yaml_file(path)

    assert "expand" in str(excinfo.value).lower()


def test_an_ordinary_pipeline_is_still_read(tmp_path: Path) -> None:
    """The guard must not cost an honest file anything -- including one that uses aliases well."""

    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(
        ".shared: &shared\n"
        "  image: python:3.12\n"
        "  before_script: ['pip install -e .']\n"
        "build:\n"
        "  <<: *shared\n"
        "  script: ['make build']\n"
        "test:\n"
        "  <<: *shared\n"
        "  script: ['make test']\n",
        encoding="utf-8",
    )

    doc = load_yaml_file(path)

    assert doc["build"]["image"] == "python:3.12"
    assert doc["test"]["before_script"] == ["pip install -e ."]


@pytest.mark.parametrize(
    ("relative", "tail", "analyze"),
    [
        (".gitlab-ci.yml", "build:\n  script: {anchor}\n", analyze_gitlab_ci),
        ("azure-pipelines.yml", "steps: {anchor}\n", analyze_azure_pipelines),
        ("buildspec.yml", "phases:\n  build:\n    commands: {anchor}\n", analyze_aws_ci),
    ],
)
def test_a_ci_parser_records_a_bomb_as_unreadable_rather_than_walking_it(
    tmp_path: Path,
    relative: str,
    tail: str,
    analyze: object,
) -> None:
    """Each parser that descends a parsed document generically must refuse, not descend.

    The GitHub workflow parser is deliberately absent: it indexes fixed shapes (`jobs` -> `steps`)
    and never recurses, so the same bomb costs it 2ms. That is the pattern the other three did
    not get, and it is why this defect is a missed sweep rather than a missing idea.
    """

    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_bomb(6, tail), encoding="utf-8")

    result = analyze(tmp_path)  # type: ignore[operator]

    assert result.parse_errors, f"{relative} was walked instead of refused"
    assert any("expand" in message.lower() for _, message in result.parse_errors)


def test_a_cyclic_document_is_counted_rather_than_overflowing_the_stack() -> None:
    """`x: &a [*a]` loads without complaint in PyYAML, so the guard has to survive it.

    A guard whose job is to stop a document from exhausting the process must not be the thing
    that exhausts it. The cycle is charged as a leaf where it closes, which makes the count
    finite; whether the document is then refused is the cap's decision, not the counter's.
    """

    cyclic = yaml.safe_load("x: &a [*a]\n")

    assert expanded_node_count(cyclic) < 10


def test_the_reader_that_bypasses_the_shared_loader_carries_the_guard_itself(tmp_path: Path) -> None:
    """The Dependabot/Renovate reader parses on its own, so the funnel fix does not reach it.

    This is the site I added myself in an earlier fix, carrying the very class this file is
    about -- measured at 7.4s for a 360-byte file before the guard. `None` is this reader's
    existing word for "could not read", which is what an unreadable file deserves.
    """

    config = tmp_path / "dependabot.yml"
    config.write_text(_bomb(6, "updates:\n  - allow: {anchor}\n"), encoding="utf-8")

    assert _update_config_names(config) is None


def test_an_ordinary_update_config_is_still_read(tmp_path: Path) -> None:
    """The guard must cost an honest Dependabot file nothing."""

    config = tmp_path / "dependabot.yml"
    config.write_text(
        "version: 2\nupdates:\n  - package-ecosystem: pip\n    allow:\n      - dependency-name: requests\n",
        encoding="utf-8",
    )

    assert _update_config_names(config) == {"requests"}


def test_the_capped_reader_refuses_a_bombed_project_config(tmp_path: Path) -> None:
    """`oss-policy-kit.yaml` is read out of the TARGET, so it is an untrusted document too.

    `load_capped_document` is the defensive read that maps bad input to exit 2, and it already
    applies a byte cap and a nesting-depth cap. Both measure the text, so the expansion check has
    to run after the parse -- on the object graph, which is the only place an alias is visible.
    """

    config = tmp_path / "oss-policy-kit.yaml"
    config.write_text(_bomb(6, "profile: {anchor}\n"), encoding="utf-8")

    with pytest.raises(InvalidInputError) as excinfo:
        load_capped_document(config, MAX_CONFIG_BYTES, label="Project config")

    assert "expand" in str(excinfo.value).lower()


def test_the_capped_reader_still_reads_an_ordinary_project_config(tmp_path: Path) -> None:
    """And an honest config pays nothing for the guard."""

    config = tmp_path / "oss-policy-kit.yaml"
    config.write_text("profile: github-level-1\nfail_on: fail\n", encoding="utf-8")

    assert load_capped_document(config, MAX_CONFIG_BYTES, label="Project config") == {
        "profile": "github-level-1",
        "fail_on": "fail",
    }
