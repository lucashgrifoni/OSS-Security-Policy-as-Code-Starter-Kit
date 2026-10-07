"""A profile named by the target's config must come from the target or from the kit.

`oss-policy-kit.yaml` lives in the repository being evaluated, and an operator evaluates
repositories that are not theirs: a fork, a pull request branch, a vendor drop. PATH-01b
(2026-10-06) settled that such a file cannot send the reports outside the repository. The
same file names the profile, and two shapes of that value reached outside it:

- a YAML path, absolute or relative with `..`, loaded whatever profile file sat at that
  place on the operator's machine;
- a value without a YAML suffix is treated as a bundled id and joined into
  `<kit>/profiles/<id>/profile.yaml`, so `../../../elsewhere` walked out of the kit.

Both now stop with exit 2 and point at `--profile`, which is the operator choosing a file.
A bundled id and a YAML file inside the repository keep working.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.loader import bundled_kit_root
from oss_policy_kit.cli.main import app

runner = CliRunner()

_CONFIG = """schema_version: oss-policy-kit/config/v1
profile: {profile}
profile_source: user
fail_on: none
output_dir: "./oss-policy-reports"
report_json_contract: "2.0"
"""

_PROFILE = """id: {ident}
title: {ident}
description: a profile used only by this test
audience: nobody
controls: [GOV-LIC-004]
"""


def _target(tmp_path: Path, profile: str) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    (target / "oss-policy-kit.yaml").write_text(_CONFIG.format(profile=profile), encoding="utf-8")
    return target


def _evaluate(target: Path, out: Path) -> object:
    return runner.invoke(app, ["evaluate", "--target", str(target), "--output-dir", str(out)])


def _outside_profile(tmp_path: Path) -> Path:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "profile.yaml").write_text(_PROFILE.format(ident="perfil-de-fora"), encoding="utf-8")
    return outside / "profile.yaml"


def test_an_absolute_profile_file_outside_the_target_is_refused(tmp_path: Path) -> None:
    outside = _outside_profile(tmp_path)
    target = _target(tmp_path, json.dumps(str(outside)))
    out = tmp_path / "out"

    result = _evaluate(target, out)

    assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
    assert "--profile" in result.output  # type: ignore[attr-defined]
    assert not (out / "evaluation-report.json").is_file()


def test_a_relative_profile_file_that_climbs_out_of_the_target_is_refused(tmp_path: Path) -> None:
    _outside_profile(tmp_path)
    target = _target(tmp_path, "../elsewhere/profile.yaml")
    out = tmp_path / "out"

    result = _evaluate(target, out)

    assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
    assert not (out / "evaluation-report.json").is_file()


def test_an_id_that_climbs_out_of_the_kit_is_refused(tmp_path: Path) -> None:
    """The reproduction: a suffix-less value walks from `<kit>/profiles/` to a file outside."""

    # Both sides resolved: on Windows the temporary directory may come as an 8.3 short name,
    # and a relative path between a short and a long form does not land anywhere.
    outside = _outside_profile(tmp_path).parent.resolve()
    climb = os.path.relpath(outside, bundled_kit_root().resolve() / "profiles")
    if not (bundled_kit_root() / "profiles" / climb / "profile.yaml").is_file():
        # The unnormalised path can pass Windows' MAX_PATH when the checkout is deep; the loader
        # could not open it either, so there is nothing to reproduce here. CI runs it on Linux.
        pytest.skip("the climbing path is too long for this platform to open")
    target = _target(tmp_path, json.dumps(climb))
    out = tmp_path / "out"

    result = _evaluate(target, out)

    assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
    assert not (out / "evaluation-report.json").is_file()


@pytest.mark.parametrize("value", ["github-level-1/../../x", "a/b", "a\\\\b", ".."])
def test_an_id_that_is_really_a_path_is_refused(tmp_path: Path, value: str) -> None:
    target = _target(tmp_path, json.dumps(value))
    out = tmp_path / "out"

    result = _evaluate(target, out)

    assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
    assert not (out / "evaluation-report.json").is_file()


def test_a_bundled_id_still_works(tmp_path: Path) -> None:
    target = _target(tmp_path, "github-level-1")
    out = tmp_path / "out"

    result = _evaluate(target, out)

    assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["profile"]["id"] == "github-level-1"


def test_an_absolute_profile_file_inside_the_target_still_works(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "perfil.yaml").write_text(_PROFILE.format(ident="perfil-do-alvo"), encoding="utf-8")
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    profile = json.dumps(str(target / "perfil.yaml"))
    (target / "oss-policy-kit.yaml").write_text(_CONFIG.format(profile=profile), encoding="utf-8")
    out = tmp_path / "out"

    result = _evaluate(target, out)

    assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["profile"]["id"] == "perfil-do-alvo"


def test_the_operator_can_still_pick_an_outside_profile_with_the_flag(tmp_path: Path) -> None:
    outside = _outside_profile(tmp_path)
    target = _target(tmp_path, "github-level-1")
    out = tmp_path / "out"

    result = runner.invoke(
        app, ["evaluate", "--target", str(target), "--output-dir", str(out), "--profile", str(outside)]
    )

    assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["profile"]["id"] == "perfil-de-fora"


def test_init_refuses_to_record_a_profile_file_outside_the_target(tmp_path: Path) -> None:
    """`evaluate` would refuse the config `init` wrote, so `init` refuses first."""

    outside = _outside_profile(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--target", str(target), "--profile", str(outside)])

    assert result.exit_code == 2, result.output  # type: ignore[attr-defined]
    assert "--profile" in result.output  # type: ignore[attr-defined]
    assert not (target / "oss-policy-kit.yaml").exists()


def test_init_still_records_a_profile_file_inside_the_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    inside = target / "perfil.yaml"
    inside.write_text(_PROFILE.format(ident="perfil-do-alvo"), encoding="utf-8")

    result = runner.invoke(app, ["init", "--target", str(target), "--profile", str(inside)])

    assert result.exit_code == 0, result.output  # type: ignore[attr-defined]
    # init records fail_on: fail, so a failing control makes evaluate exit 1; what matters
    # here is that the config's profile was accepted and loaded.
    evaluated = _evaluate(target, tmp_path / "out")
    assert evaluated.exit_code in {0, 1}, evaluated.output  # type: ignore[attr-defined]
    report = json.loads((tmp_path / "out" / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["profile"]["id"] == "perfil-do-alvo"
