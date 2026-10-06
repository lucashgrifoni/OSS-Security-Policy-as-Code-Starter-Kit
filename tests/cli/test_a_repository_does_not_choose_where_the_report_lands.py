"""A relative `output_dir` in the target's config resolves against the target, not the CWD.

`oss-policy-kit.yaml` is loaded from the TARGET, so in the flow this product is built for -- a
maintainer triaging a fork, a CI job scanning a PR branch, a security team scanning a vendor --
that file is written by whoever wrote the repository under review.

Its `output_dir` was turned into a bare `Path`, which is worse than it sounds: a relative value
resolved against the OPERATOR'S working directory. Reproduced by hand before this test existed --
a target carrying `output_dir: ../ELSEWHERE/hijacked` made `evaluate` create that tree and write
both reports beside the operator's *other projects*, nowhere near the repository being scanned,
and exit 0.

What this file pins is the half that is indefensible under any reading: a relative `output_dir` in
a file that lives in the target means "inside the target", never "wherever the operator happened
to stand".

A relative value that climbs out of the target with `..` is refused: by the same reading it would
have to mean "inside the target", and it cannot.

The other half -- whether an ABSOLUTE value may point outside the repository -- was left open as
PATH-01b, because `init` writes this file for the adopter's OWN repository and "put my reports in
the shared folder" was a real flow, while the kit cannot tell from the config alone whether the
repository is the adopter's or a stranger's. Decided on 2026-10-06: an absolute value outside the
repository is refused too. The shared-folder flow moves to `--output-dir`, which is the operator
speaking; an absolute path that lands inside the repository is still accepted.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

_CONFIG = """schema_version: oss-policy-kit/config/v1
profile: github-level-1
fail_on: fail
output_dir: {output_dir}
"""

#: Relative values, each of which used to land somewhere decided by the operator's CWD.
_RELATIVE = ["reports", "out/nested", "out/../reports"]


def _target(root: Path, output_dir: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    (root / "oss-policy-kit.yaml").write_text(_CONFIG.format(output_dir=output_dir), encoding="utf-8")
    return root


def _run_from(workdir: Path, args: list[str]) -> object:
    cwd = os.getcwd()
    try:
        os.chdir(workdir)
        return runner.invoke(app, args)
    finally:
        os.chdir(cwd)


@pytest.mark.parametrize("relative", _RELATIVE)
def test_a_relative_config_output_dir_never_lands_relative_to_the_cwd(tmp_path: Path, relative: str) -> None:
    """Where the operator stands must not decide where the report goes.

    The destination is measured from the TARGET, so it is a property of the repository being
    evaluated rather than of the operator's shell.
    """

    workdir = tmp_path / "cwd"
    workdir.mkdir()
    target = _target(tmp_path / "target", relative)

    result = _run_from(workdir, ["evaluate", "--target", str(target)])

    assert result.exit_code in (0, 1), result.output  # type: ignore[attr-defined]

    expected = (target / relative).resolve()
    assert (expected / "evaluation-report.json").is_file(), (
        f"output_dir={relative!r} did not resolve against the target; expected it under {expected}"
    )
    from_cwd = (workdir / relative).resolve()
    assert from_cwd == expected or not (from_cwd / "evaluation-report.json").is_file(), (
        f"output_dir={relative!r} resolved against the operator's CWD ({from_cwd}) instead of the target ({expected})"
    )


def test_an_explicit_flag_is_still_the_operators_own_choice(tmp_path: Path) -> None:
    """`--output-dir` is the operator speaking, not the repository, so it stays unconstrained."""

    target = _target(tmp_path / "target", "reports")
    elsewhere = tmp_path / "operator-chose-this"

    result = runner.invoke(app, ["evaluate", "--target", str(target), "--output-dir", str(elsewhere)])

    assert result.exit_code in (0, 1), result.output
    assert (elsewhere / "evaluation-report.json").is_file()
    assert not (target / "reports").exists(), "the flag did not win over the config"


@pytest.mark.parametrize("escaping", ["../sibling-of-target", "reports/../../up", ".."])
def test_a_relative_config_output_dir_cannot_leave_the_target(tmp_path: Path, escaping: str) -> None:
    """A relative `output_dir` that climbs out of the target is refused, and nothing is written.

    Reproduced before the fix: `output_dir: ../x` in a scanned repository made `evaluate` write
    both reports beside the target and exit 0.
    """

    target = _target(tmp_path / "target", escaping)

    result = runner.invoke(app, ["evaluate", "--target", str(target)])

    assert result.exit_code == 2, result.output
    assert "points outside the repository" in result.output
    assert not list(tmp_path.rglob("evaluation-report.json"))


def test_an_absolute_config_output_dir_outside_the_target_is_refused(tmp_path: Path) -> None:
    """PATH-01b: a scanned repository does not choose a destination outside itself, even absolute."""

    outside = tmp_path / "shared-reports"
    target = _target(tmp_path / "target", outside.as_posix())

    result = runner.invoke(app, ["evaluate", "--target", str(target)])

    assert result.exit_code == 2, result.output
    assert "points outside the repository" in result.output
    assert "--output-dir" in result.output
    assert not outside.exists()
    assert not list(tmp_path.rglob("evaluation-report.json"))


def test_an_absolute_config_output_dir_inside_the_target_is_kept(tmp_path: Path) -> None:
    """An absolute path that names a directory inside the repository is the same place, so it stays."""

    root = tmp_path / "target"
    inside = root / "reports"
    target = _target(root, inside.as_posix())

    result = runner.invoke(app, ["evaluate", "--target", str(target)])

    assert result.exit_code in (0, 1), result.output
    assert (inside / "evaluation-report.json").is_file()


def test_the_shared_folder_flow_still_works_through_the_flag(tmp_path: Path) -> None:
    """What PATH-01b took from the config, `--output-dir` still gives the operator."""

    outside = tmp_path / "shared-reports"
    target = _target(tmp_path / "target", outside.as_posix())

    result = runner.invoke(app, ["evaluate", "--target", str(target), "--output-dir", str(outside)])

    assert result.exit_code in (0, 1), result.output
    assert (outside / "evaluation-report.json").is_file()
