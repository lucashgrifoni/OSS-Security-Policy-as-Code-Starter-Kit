"""When the evaluated repository chooses the gate policy, the operator gets told.

`oss-policy-kit.yaml` is read from the TARGET, and `docs/cli-reference.md` states the precedence
plainly: `fail_on`, `output_dir` and `report_json_contract` are taken from it when the matching
flag is omitted, and an explicit flag always wins. That is deliberate and it is the right design
for the flow `init` was built for -- an adopter configuring their own repository once.

What was not deliberate is the silence. Measured on two repositories identical but for that one
config value, each with nine failing controls:

    fail_on: fail  ->  exit 1
    fail_on: none  ->  exit 0

and the only thing on stderr in both runs was `Using profile from oss-policy-kit.yaml: ...`. So
the kit already had the habit of announcing what the target's config decided, and had applied it
to the profile while leaving silent the one fallback that can turn a red result into a green exit
code.

Scope, stated honestly rather than inflated: the shipped GitHub Action always passes `--fail-on`
explicitly, so the kit's own CI gate cannot be disarmed this way. The exposure is an operator
running the bare CLI against a repository they did not write -- a fork, a vendor drop, a PR
branch -- and omitting the flag. The fix here changes no exit code and no documented precedence.
It only makes the decision visible, which is the part that was actually wrong.

`output_dir` and `report_json_contract` come from the same config and are still announced by
nothing. They are not covered here: `output_dir` is the subject of an open product decision
(PATH-01b) about whether a target may point it outside the repository at all, and pre-empting
that with a message would decide it sideways.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

_CONFIG = """schema_version: oss-policy-kit/config/v1
profile: github-level-1
profile_source: user
fail_on: {fail_on}
output_dir: "./oss-policy-reports"
report_json_contract: "2.0"
"""


def _target(root: Path, fail_on: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    (root / "oss-policy-kit.yaml").write_text(_CONFIG.format(fail_on=fail_on), encoding="utf-8")
    return root


def _flat(text: str) -> str:
    """Rich wraps at the terminal width, so an assertion on a phrase must ignore where it broke."""

    return re.sub(r"\s+", " ", text)


@pytest.mark.parametrize("fail_on", ["none", "fail", "degraded"])
def test_a_gate_policy_taken_from_the_target_is_announced(tmp_path: Path, fail_on: str) -> None:
    """Whatever the target asked for, the operator must be able to see that the target asked."""

    target = _target(tmp_path / fail_on, fail_on)

    result = runner.invoke(app, ["evaluate", "--target", str(target), "--output-dir", str(tmp_path / "out")])

    output = _flat(result.output)
    assert "oss-policy-kit.yaml" in output
    assert f"fail-on {fail_on}" in output or f"fail_on: {fail_on}" in output or f"--fail-on {fail_on}" in output, (
        f"the run took fail_on={fail_on!r} from the target and said nothing identifiable: {output}"
    )


def test_the_announcement_names_the_consequence_when_the_gate_is_switched_off(tmp_path: Path) -> None:
    """`none` is the value that costs something, so it must read as more than a setting echo.

    An operator skimming a green run needs the message to say that nothing can fail it, not just
    that a value was loaded.
    """

    target = _target(tmp_path / "disarmed", "none")

    result = runner.invoke(app, ["evaluate", "--target", str(target), "--output-dir", str(tmp_path / "out")])

    assert "never fail" in _flat(result.output).lower()


def test_an_explicit_flag_is_the_operator_speaking_and_needs_no_announcement(tmp_path: Path) -> None:
    """The message is about the target deciding. When the operator decides, there is nothing to report.

    The assertion is that NO gate-policy announcement appears, not merely that the `none` wording
    is absent. A first version checked only for "never fail" and a mutation walked straight past
    it: moving the call outside the `fail_on_provided` guard announces the *flag's* value, which
    takes the generic branch, so the weaker assertion stayed green while the distinction the whole
    finding rests on was gone.
    """

    target = _target(tmp_path / "explicit", "none")

    result = runner.invoke(
        app,
        ["evaluate", "--target", str(target), "--output-dir", str(tmp_path / "out"), "--fail-on", "fail"],
    )

    assert "--fail-on" not in _flat(result.output), (
        "the run announced a gate policy from the config although the operator passed the flag"
    )
    assert result.exit_code == 1, "an explicit --fail-on must still win over the config"


def test_the_exit_codes_themselves_are_left_exactly_as_documented(tmp_path: Path) -> None:
    """The documented precedence is not being changed here -- only the silence around it.

    Pinning both halves in one place so a later attempt to 'harden' this by ignoring the config
    has to face the documented contract it would be breaking.
    """

    disarmed = _target(tmp_path / "a", "none")
    armed = _target(tmp_path / "b", "fail")

    out_a = runner.invoke(app, ["evaluate", "--target", str(disarmed), "--output-dir", str(tmp_path / "oa")])
    out_b = runner.invoke(app, ["evaluate", "--target", str(armed), "--output-dir", str(tmp_path / "ob")])

    assert out_a.exit_code == 0
    assert out_b.exit_code == 1
