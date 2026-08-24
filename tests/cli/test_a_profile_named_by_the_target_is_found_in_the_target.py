"""A relative profile path written in the target's config means "inside the target".

`load_profile_by_id` accepts either a bundled id or a path to a YAML profile, and resolves the
path form against the process working directory. That is correct for `--profile ./mine.yaml`,
where the operator typed it. It is wrong for the same value arriving from `oss-policy-kit.yaml`,
because that file lives in the repository being evaluated and the operator may be standing
anywhere.

Reproduced before this test existed, with a `perfil.yaml` in each place and the target's config
naming `perfil.yaml`:

    Using profile from oss-policy-kit.yaml: perfil.yaml
    -> profile loaded: perfil-do-operador (3 controls)   # the operator's file, not the target's

The verdict was computed from the wrong profile, and the announcement gave no hint, because from
its point of view it had simply used "the profile the config named".

This is the same defect `output_dir` had (PATH-01) and the same half is fixed here: a relative
value in a file that lives in the target is measured from the target. An ABSOLUTE value is left
alone on purpose -- whether a repository nobody audited may point the kit at a file outside
itself is the open product question recorded as PATH-01b, and settling it inside a path helper
would decide it sideways.

A first version of the fix kept a third guard -- pass the raw value through when the anchored
file does not exist -- justified as avoiding an M-002 host-path leak in the resulting error. Two
mutations survived, and investigating why showed the justification was wrong: `display_path`
already anonymises that message, and the guard's actual effect was to fall back to the operator's
working directory, preserving half the defect. It also masked the bundled-id guard, so neither
could be killed by a mutation while both were present. The guard is gone and both halves are
pinned below.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

_CONFIG = """schema_version: oss-policy-kit/config/v1
profile: {profile}
profile_source: user
fail_on: fail
output_dir: "./oss-policy-reports"
report_json_contract: "2.0"
"""

_PROFILE = """id: {ident}
title: {ident}
description: a profile used only by this test
audience: nobody
controls: [{controls}]
"""


def _run_from(workdir: Path, args: list[str]) -> object:
    cwd = os.getcwd()
    try:
        os.chdir(workdir)
        return runner.invoke(app, args)
    finally:
        os.chdir(cwd)


def _loaded_profile(out_dir: Path) -> dict[str, object]:
    report = json.loads((out_dir / "evaluation-report.json").read_text(encoding="utf-8"))
    return {"id": report["profile"]["id"], "controls": report["controls_total"]}


def test_the_target_s_own_profile_wins_over_a_same_named_file_beside_the_operator(tmp_path: Path) -> None:
    """The reproduction: two files named alike, and the one in the target is the one meant."""

    target = tmp_path / "target"
    (target).mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    (target / "perfil.yaml").write_text(
        _PROFILE.format(ident="perfil-do-alvo", controls="GOV-LIC-004"), encoding="utf-8"
    )
    (target / "oss-policy-kit.yaml").write_text(_CONFIG.format(profile="perfil.yaml"), encoding="utf-8")

    workdir = tmp_path / "operator"
    workdir.mkdir()
    (workdir / "perfil.yaml").write_text(
        _PROFILE.format(ident="perfil-do-operador", controls="GOV-SEC-001, GOV-CON-002, GOV-LIC-004"),
        encoding="utf-8",
    )

    out = tmp_path / "out"
    _run_from(workdir, ["evaluate", "--target", str(target), "--output-dir", str(out)])

    assert _loaded_profile(out) == {"id": "perfil-do-alvo", "controls": 1}


def test_a_bundled_id_in_the_config_is_still_an_id_and_not_a_path(tmp_path: Path) -> None:
    """`init` writes an id, which is what the config field is documented to hold.

    Anchoring must not turn `github-level-1` into a filename lookup inside the target.
    """

    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    (target / "oss-policy-kit.yaml").write_text(_CONFIG.format(profile="github-level-1"), encoding="utf-8")

    out = tmp_path / "out"
    runner.invoke(app, ["evaluate", "--target", str(target), "--output-dir", str(out)])

    assert _loaded_profile(out)["id"] == "github-level-1"


def test_an_explicit_flag_is_still_resolved_where_the_operator_is_standing(tmp_path: Path) -> None:
    """`--profile ./mine.yaml` is the operator typing a path, so their working directory is right.

    Without this, fixing the config case by changing the shared resolver would silently move
    where an operator's own `--profile` path is looked up.
    """

    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    (target / "perfil.yaml").write_text(
        _PROFILE.format(ident="perfil-do-alvo", controls="GOV-LIC-004"), encoding="utf-8"
    )

    workdir = tmp_path / "operator"
    workdir.mkdir()
    (workdir / "perfil.yaml").write_text(
        _PROFILE.format(ident="perfil-do-operador", controls="GOV-SEC-001, GOV-LIC-004"),
        encoding="utf-8",
    )

    out = tmp_path / "out"
    _run_from(workdir, ["evaluate", "--target", str(target), "--output-dir", str(out), "--profile", "perfil.yaml"])

    assert _loaded_profile(out)["id"] == "perfil-do-operador"


def test_a_profile_missing_from_the_target_is_not_silently_taken_from_the_operator(tmp_path: Path) -> None:
    """The half the removed guard was preserving: a config naming a file the repository lacks.

    Falling back to the operator's working directory here is the same wrong answer as the case
    above, just harder to notice -- the target asked for a profile it does not ship, and the
    operator happens to have one by that name.
    """

    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    (target / "oss-policy-kit.yaml").write_text(_CONFIG.format(profile="ausente.yaml"), encoding="utf-8")

    workdir = tmp_path / "operator"
    workdir.mkdir()
    (workdir / "ausente.yaml").write_text(
        _PROFILE.format(ident="perfil-do-operador", controls="GOV-LIC-004"), encoding="utf-8"
    )

    out = tmp_path / "out"
    result = _run_from(workdir, ["evaluate", "--target", str(target), "--output-dir", str(out)])

    assert result.exit_code == 2, "the operator's same-named profile was loaded instead of refusing"  # type: ignore[attr-defined]
    assert not (out / "evaluation-report.json").is_file()


def test_the_refusal_does_not_print_the_host_path(tmp_path: Path) -> None:
    """Anchoring builds a path the kit prints, so the message must not carry the host layout.

    The first version asserted `Path.home().name not in output`. It passed on Windows, failed in
    CI, and BOTH results were wrong. On Windows the temporary directory renders as the 8.3 short
    form, so the account name never appeared literally and the test passed while the leak was
    real. In CI it appeared because pytest names its own temp directory `pytest-of-<user>` -- a
    directory the kit never chose -- so the failure pointed at the fixture rather than the defect.
    One assertion, two wrong reasons, with a real leak sitting in between: the refusal was
    printing the whole constructed path.

    The marker below is a directory name this test invents. It cannot reach the output except
    through the path, it is present on every platform, and no short-form or fixture-naming
    accident can hide it.
    """

    marker = "opk-host-layout-marker"
    target = tmp_path / marker / "target"
    target.mkdir(parents=True)
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    (target / "oss-policy-kit.yaml").write_text(_CONFIG.format(profile="ausente.yaml"), encoding="utf-8")

    result = runner.invoke(app, ["evaluate", "--target", str(target), "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 2
    assert marker not in result.output, (
        "the refusal printed the directories above the target, which is host layout the operator "
        f"never asked to publish: {result.output!r}"
    )
    assert "ausente.yaml" in result.output, (
        "the refusal no longer names the missing file, which makes it useless to act on"
    )
