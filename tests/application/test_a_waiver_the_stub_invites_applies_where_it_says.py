"""The waivers stub `init --with-waivers` writes must say how an entry takes effect, truthfully.

Found by the end-user validation of the published 10.0.26. `init --with-waivers --with-workflow`
wrote `waivers.yaml`, whose header said waived findings "stop tripping --fail-on", and next to
it a workflow whose evaluate step has no `--waivers`. An entry added to the file changed
nothing in CI: the control the adopter had waived still failed the gate. `evaluate` applies a
waivers file only when it is handed one, which is deliberate -- the versioned file is what
GOV-WAIV-014 looks for, `--waivers` is what applies it -- so the fix is to say so where the
adopter reads it, not to start loading a file from the repository under review.

The stub's example had its own defect: it named `GH-PIN-007`, which is not in the catalog.
Uncommented as the stub invites, it waived nothing and produced an "matched no control"
warning instead. The example is now checked against the catalog, so it cannot drift again.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from oss_policy_kit.application.init_writer import _render_waivers_stub
from oss_policy_kit.application.loader import bundled_kit_root
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli.main import app

_WORKFLOW = ".github/workflows/oss-policy-check.yml"


def _catalog_ids() -> set[str]:
    catalog = yaml.safe_load((bundled_kit_root() / "controls" / "catalog.yaml").read_text(encoding="utf-8"))
    return {str(control["id"]) for control in catalog["controls"]}


def _uncommented_example(stub: str) -> str:
    """The stub as a reader following "uncomment and adjust" would leave it, before adjusting."""

    head, _, example = stub.partition("# Example (uncomment and adjust):\n")
    body = "".join(line.removeprefix("# ") + "\n" for line in example.splitlines())
    return head.replace("waivers: []\n", "") + body


def test_the_example_waives_a_control_the_catalog_has(tmp_path: Path) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text(_uncommented_example(_render_waivers_stub()), encoding="utf-8")

    outcome = parse_waivers_file(path)

    assert outcome.by_control, "the uncommented example parsed to no waiver at all"
    unknown = set(outcome.by_control) - _catalog_ids()
    assert not unknown, f"the stub's example waives {sorted(unknown)}, which no control in the catalog has"


def test_the_stub_says_a_waiver_applies_only_to_a_run_given_the_file() -> None:
    stub = _render_waivers_stub()

    assert "--waivers waivers.yaml" in stub
    assert "init --with-workflow" in stub, "the stub no longer warns that the generated workflow omits the flag"


def _init_next_steps(tmp_path: Path, *extra: str) -> list[str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    argv = ["init", "--target", str(repo), "--platform", "github", "--with-waivers", "--yes", "--format", "json"]
    result = CliRunner().invoke(app, [*argv, *extra], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return list(json.loads(result.output)["next_steps"])


def test_with_a_workflow_the_next_step_names_where_the_flag_goes(tmp_path: Path) -> None:
    steps = _init_next_steps(tmp_path, "--with-workflow")

    waiver_step = next(step for step in steps if step.startswith("Add real entries to waivers.yaml"))
    assert "--waivers waivers.yaml" in waiver_step
    assert _WORKFLOW in waiver_step
    workflow = (tmp_path / "repo" / _WORKFLOW).read_text(encoding="utf-8")
    assert "--waivers" not in workflow, (
        "the generated workflow now passes --waivers itself, so this next step is advice about a "
        "flag that is already there; drop the second half of it"
    )


def test_without_a_workflow_the_next_step_names_only_the_flag(tmp_path: Path) -> None:
    steps = _init_next_steps(tmp_path)

    waiver_step = next(step for step in steps if step.startswith("Add real entries to waivers.yaml"))
    assert "--waivers waivers.yaml" in waiver_step
    assert _WORKFLOW not in waiver_step
