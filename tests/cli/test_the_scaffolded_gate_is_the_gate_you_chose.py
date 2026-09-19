"""``init`` recorded the gate the adopter picked and scaffolded a weaker one, in the same run.

``init --profile github-level-3 --fail-on degraded --with-workflow`` wrote
``profile: github-level-3`` and ``fail_on: degraded`` into ``oss-policy-kit.yaml``, marked
``profile_source: user``, and then wrote a workflow whose evaluate step passed
``--profile github-level-1 --fail-on fail``. The template was copied byte for byte and there
was no substitution mechanism anywhere in the init path.

It failed in the permissive direction, silently, on the primary onboarding path. An explicit
``evaluate`` flag beats the config file, so the workflow did not merely disagree with what
``init`` had just recorded: it overrode it. A maintainer who ran that command and committed
what the tool handed them had a repository whose config said level-3 and whose pipeline
enforced level-1. The only hint was a comment three lines from the top of the file reading
"Customize --profile and --fail-on to match your desired strictness", phrased as optional
polish rather than as a correction the reader has to make.

The templates on disk keep their working defaults, because ``docs/adoption-guide.md`` tells
adopters to copy one by hand and each has to run as it sits. The substitution happens when
``init`` writes one, and only on the two arguments that carry the gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import Result
from typer.testing import CliRunner

from oss_policy_kit.application import init_writer as iw
from oss_policy_kit.cli.main import app, prepare_cli_args
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()


def _evaluate_args(workflow_body: str) -> dict[str, str]:
    """``{argument: value}`` for the gate arguments in the template's evaluate step."""

    found: dict[str, str] = {}
    for line in workflow_body.splitlines():
        stripped = line.strip().rstrip("\\").strip()
        for name in ("--profile", "--fail-on", "--output-dir"):
            if stripped.startswith(name + " "):
                found[name] = stripped[len(name) :].strip()
    return found


def _init(target: Path, *extra: str) -> Result:
    return runner.invoke(
        app,
        prepare_cli_args(
            ["init", "--target", str(target), "--platform", "github", "--with-workflow", *extra],
        ),
    )


def test_the_scaffolded_workflow_enforces_the_gate_the_config_records(tmp_path: Path) -> None:
    """The defect: one command, two different gates, and the workflow is the one that runs."""

    repo = tmp_path / "repo"
    repo.mkdir()

    result = _init(repo, "--profile", "github-level-3", "--fail-on", "degraded")
    assert result.exit_code == 0, result.output

    config = yaml.safe_load((repo / "oss-policy-kit.yaml").read_text(encoding="utf-8"))
    workflow = (repo / ".github" / "workflows" / "oss-policy-check.yml").read_text(encoding="utf-8")
    args = _evaluate_args(workflow)

    assert config["profile"] == "github-level-3"
    assert config["fail_on"] == "degraded"
    assert args["--profile"] == config["profile"], "the scaffolded gate runs a profile the adopter did not choose"
    assert args["--fail-on"] == config["fail_on"], "the scaffolded gate runs a fail-on the adopter did not choose"


def test_the_default_run_still_scaffolds_the_default_gate(tmp_path: Path) -> None:
    """Nothing changes for the adopter who passes no profile: the recommendation still wins."""

    repo = tmp_path / "repo"
    repo.mkdir()

    result = _init(repo)
    assert result.exit_code == 0, result.output

    config = yaml.safe_load((repo / "oss-policy-kit.yaml").read_text(encoding="utf-8"))
    args = _evaluate_args((repo / ".github" / "workflows" / "oss-policy-check.yml").read_text(encoding="utf-8"))

    assert args["--profile"] == config["profile"] == "github-level-1"
    assert args["--fail-on"] == config["fail_on"] == "fail"


def test_an_external_profile_path_leaves_the_workflow_alone_and_says_so(tmp_path: Path) -> None:
    """A path is not a bundled id. Interpolating one would write a line that cannot run in CI."""

    external = tmp_path / "My Profiles"
    external.mkdir()
    source = Path(iw.__file__).resolve().parents[1] / "data" / "profiles" / "github-level-1" / "profile.yaml"
    profile = external / "p.yaml"
    profile.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    repo = tmp_path / "repo"
    repo.mkdir()
    result = _init(repo, "--profile", str(profile))
    assert result.exit_code == 0, result.output

    workflow = (repo / ".github" / "workflows" / "oss-policy-check.yml").read_text(encoding="utf-8")
    args = _evaluate_args(workflow)

    assert args["--profile"] == "github-level-1", "an external profile path must not reach the workflow's run block"
    assert "My Profiles" not in workflow
    assert "kept the template's own profile" in result.output.lower() or "profile" in result.output.lower()


@pytest.mark.parametrize("dest", sorted(iw._WORKFLOW_SOURCE_BY_DEST))
def test_every_shipped_template_takes_the_plans_gate_settings(dest: str) -> None:
    """Fixing only the template `init` happens to write leaves the same defect in the others."""

    _, body = iw._resolve_workflow_template(dest)
    applied = iw._apply_workflow_settings(
        body, profile="github-level-3", fail_on="degraded", output_dir="./oss-policy-reports"
    )
    args = _evaluate_args(applied)

    assert args["--profile"] == "github-level-3"
    assert args["--fail-on"] == "degraded"
    assert yaml.safe_load(applied), "the substitution left the template unparseable"


@pytest.mark.parametrize("dest", sorted(iw._WORKFLOW_SOURCE_BY_DEST))
def test_substituting_a_templates_own_values_changes_nothing(dest: str) -> None:
    """Identity is the cheapest proof the rewrite touches one value and not the file's shape."""

    _, body = iw._resolve_workflow_template(dest)
    current = _evaluate_args(body)

    assert (
        iw._apply_workflow_settings(
            body,
            profile=current["--profile"],
            fail_on=current["--fail-on"],
            output_dir=current["--output-dir"],
        )
        == body
    )


def test_the_customize_comment_is_not_an_argument() -> None:
    """The anchor: line 3 mentions both flags in prose and must survive untouched."""

    _, body = iw._resolve_workflow_template("oss-policy-check.yml")
    comment = "# Customize --profile and --fail-on to match your desired strictness."
    assert comment in body

    assert comment in iw._apply_workflow_settings(
        body, profile="github-level-3", fail_on="degraded", output_dir="./oss-policy-reports"
    )


def test_a_template_that_hides_its_arguments_is_a_packaging_fault() -> None:
    """Fail closed. A template whose gate is not on its own line would be silently un-substituted."""

    single_line = "jobs:\n  x:\n    steps:\n      - run: evaluate --target . --profile github-level-1 --fail-on fail\n"

    with pytest.raises(InvalidInputError) as caught:
        iw._apply_workflow_settings(single_line, profile="github-level-3", fail_on="degraded", output_dir="./reports")

    # `--output-dir` joined the same contract: a template that hides it would leave the run
    # writing where the template says while the config claims somewhere else.
    message = str(caught.value)
    assert "--profile" in message and "--fail-on" in message and "--output-dir" in message
