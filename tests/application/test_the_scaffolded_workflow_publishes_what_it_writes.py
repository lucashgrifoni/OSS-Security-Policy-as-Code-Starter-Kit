"""`init --output-dir X` has to reach the workflow it scaffolds, in both places.

The chosen directory landed in `oss-policy-kit.yaml` and nowhere else. The generated
workflow kept the template's `--output-dir ./oss-policy-reports` and the template's
`path: ./oss-policy-reports/`, so an adopter who picked a directory got a gate that
ignored the choice. This is the same shape #277 fixed for `profile` and `fail_on`,
surviving in `output_dir`.

What makes it worse than those two is the coupling. The argument decides where the run
writes; the upload step's `path:` decides what gets published. Move one and not the other
and the job writes one directory, publishes another, and finishes green with an empty
artifact. So the two are rewritten from one source and a case below asserts they agree.

The upload `name:` is deliberately left as it is. It is a label, not a path, and an
artifact name cannot contain a slash, so carrying a nested value such as `out/reports`
into it would produce a workflow that fails to upload at all. Every artifact name in this
repository's own workflows is a flat label for the same reason.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

_WORKFLOW = Path(".github") / "workflows" / "oss-policy-check.yml"


def _repo(root: Path) -> Path:
    repo = root / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
        encoding="utf-8",
    )
    return repo


def _scaffold(root: Path, *extra: str) -> tuple[str, str]:
    repo = _repo(root)
    result = runner.invoke(app, ["init", "--target", str(repo), "--with-workflow", *extra])
    assert result.exit_code == 0, result.output
    return (
        (repo / "oss-policy-kit.yaml").read_text(encoding="utf-8"),
        (repo / _WORKFLOW).read_text(encoding="utf-8"),
    )


def _argument_value(workflow: str) -> str:
    match = re.search(r"^[ \t]+--output-dir[ \t]+(?P<value>\S+)", workflow, re.MULTILINE)
    assert match, "the scaffolded workflow has no --output-dir argument at all"
    return match.group("value")


def _published_paths(workflow: str) -> list[str]:
    document = yaml.safe_load(workflow)
    found: list[str] = []
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            if "upload-artifact" in str(step.get("uses", "")):
                found.append(str((step.get("with") or {}).get("path", "")))
    return found


def _normalised(value: str) -> str:
    return value.rstrip("/").removeprefix("./")


@pytest.mark.parametrize("chosen", ["relatorios-customizados", "out/reports", "./with-a-dot-slash"])
def test_the_workflow_runs_against_the_directory_that_was_chosen(chosen: str, tmp_path: Path) -> None:
    config, workflow = _scaffold(tmp_path, "--output-dir", chosen)

    assert yaml.safe_load(config)["output_dir"] == chosen
    assert _normalised(_argument_value(workflow)) == _normalised(chosen), (
        f"the config says `{chosen}` and the scaffolded workflow evaluates into "
        f"`{_argument_value(workflow)}`, so the gate ignores the choice"
    )


@pytest.mark.parametrize("chosen", ["relatorios-customizados", "out/reports", "./with-a-dot-slash"])
def test_the_workflow_publishes_the_directory_it_writes(chosen: str, tmp_path: Path) -> None:
    """The coupling. Publishing a different directory is an empty artifact and exit 0."""

    _, workflow = _scaffold(tmp_path, "--output-dir", chosen)
    published = _published_paths(workflow)

    assert len(published) == 1, f"expected one upload step, found {len(published)}"
    assert _normalised(published[0]) == _normalised(_argument_value(workflow)), (
        f"the run writes `{_argument_value(workflow)}` and the upload publishes "
        f"`{published[0]}`. The job would finish green with an empty artifact."
    )


@pytest.mark.parametrize("chosen", ["out/reports", "relatorios-customizados"])
def test_the_artifact_name_stays_a_label(chosen: str, tmp_path: Path) -> None:
    """A slash in an artifact name is rejected by upload-artifact, so the label stays put."""

    _, workflow = _scaffold(tmp_path, "--output-dir", chosen)
    document = yaml.safe_load(workflow)
    names = [
        str((step.get("with") or {}).get("name", ""))
        for job in (document.get("jobs") or {}).values()
        for step in job.get("steps") or []
        if "upload-artifact" in str(step.get("uses", ""))
    ]

    assert names == ["oss-policy-reports"], f"the artifact name moved with the path: {names}"
    assert "/" not in names[0]


def test_the_default_still_scaffolds_a_consistent_workflow(tmp_path: Path) -> None:
    """Without the flag, the template's own value has to survive in both places."""

    _, workflow = _scaffold(tmp_path)

    assert _normalised(_argument_value(workflow)) == _normalised(_published_paths(workflow)[0])
