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

The other half -- whether a config may point outside the repository at all -- is NOT settled here.
`test_v10_0_1_config_init.py::test_config_output_dir_used_when_flag_omitted` pins the opposite,
deliberately using an absolute path outside the repo, because `init` writes this file for the
adopter's OWN repository and "put my reports in the shared folder" is a real flow. The kit cannot
tell from the config alone whether the repository is the adopter's or a stranger's. That is a
product decision, recorded as PATH-01b, not something to settle inside a path helper.
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
_RELATIVE = ["reports", "out/nested", "../sibling-of-target"]


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

    `../sibling-of-target` is included on purpose: it still leaves the repository, and this test
    does not claim that is refused -- see PATH-01b. It claims only that the destination is
    measured from the TARGET, so it is a property of the repository being evaluated rather than of
    the operator's shell.
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
