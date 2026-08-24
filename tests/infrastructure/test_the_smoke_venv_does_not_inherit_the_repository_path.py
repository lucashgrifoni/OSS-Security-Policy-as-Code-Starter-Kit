"""The consumer smoke venv must not inherit the repository's path length.

`scripts/consumer_smoke.py` is one of the canonical baseline commands, and playbook 05's consumer
campaign requires running it against paths with spaces and Unicode. On this checkout it does not
run at all:

    ERROR: Could not install packages due to an OSError: [Errno 2] No such file or directory:
    '...\\.consumer-smoke-venv\\Lib\\site-packages\\oss_policy_kit\\data\\schema\\
     evidence-github-environment-protection.schema.json'

`ENOENT` rather than `ENAMETOOLONG` is the Windows MAX_PATH symptom. Measured: repository root 143
characters, worst installed path 274, limit 260, `LongPathsEnabled` 0. The venv was anchored inside
the repository with no way to move it, so the script's ability to run depended on where the
adopter had cloned.

The obvious repair -- put the venv in a temp directory -- would have quietly removed a guard that
is there on purpose. `_remove_virtualenv` runs `shutil.rmtree`, and every path into it is forced
through `_resolve_repo_child`, which refuses anything outside the repository. Deleting that
containment to gain a shorter path trades a broken script for a dangerous one.

So containment is kept and its ROOT is parameterised: the script creates the root itself and
confines deletion to that. The guard is not relaxed; it is pointed at the tree the venv actually
belongs to.

A `--venv-dir` override shipped with the first version of this fix and was withdrawn after Snyk
Code reported the operator-chosen interpreter path as a command-injection dataflow. The reasoning
is on `_resolve_smoke_venv`; what matters here is that the MAX_PATH repair never depended on it,
so the tests below exercise the only path that remains.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from scripts import consumer_smoke


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def test_the_default_venv_is_not_created_inside_the_repository(tmp_path: Path) -> None:
    """The reproduction, stated as a property: the repository's path must not bound the venv's."""

    repo_root = _repo(tmp_path)

    venv_dir, containment = consumer_smoke._resolve_smoke_venv()
    try:
        assert not consumer_smoke._is_relative_to(venv_dir, repo_root), (
            "the venv is still anchored to the repository, so its path length follows the clone location"
        )
        assert consumer_smoke._is_relative_to(venv_dir, containment), "the venv escaped its own containment root"
    finally:
        shutil.rmtree(containment, ignore_errors=True)


def test_the_default_location_is_a_direct_child_of_the_systems_temporary_directory(tmp_path: Path) -> None:
    """Being "not in the repository" is not enough -- it has to be somewhere short and disposable.

    The assertion compares the PARENT, and that is the whole point of it. A first version asked
    only whether the root was somewhere under `tempfile.gettempdir()`, and a mutation restoring
    the repository anchoring sailed past: pytest's own `tmp_path` lives under the system temp
    directory too, so the check was true either way and measured nothing.
    """

    venv_dir, containment = consumer_smoke._resolve_smoke_venv()
    try:
        assert containment.parent == Path(tempfile.gettempdir()).resolve(), (
            f"the containment root is nested somewhere else entirely: {containment}"
        )
        assert consumer_smoke._is_relative_to(venv_dir, containment)
    finally:
        shutil.rmtree(containment, ignore_errors=True)


def test_the_venv_path_is_short_enough_for_the_limit_that_broke_it(tmp_path: Path) -> None:
    """The defect was measured in characters, so the guard is measured in characters too.

    An earlier version compared two repositories at different depths and asserted their venv paths
    came out the same length. That was a real test while `_resolve_smoke_venv` still took the
    repository as an argument. Once the `--venv-dir` override was withdrawn the function stopped
    seeing any caller path at all, and the comparison decayed into asserting that two `mkdtemp`
    results are the same length -- true by construction, and no longer about the defect.

    What still needs holding is the number that broke it: the reproduction had the worst installed
    path at 274 against a 260 limit. The venv root is the part this function controls, and what
    gets installed underneath needs room to fit, so the root has to stay far below the limit
    rather than merely somewhere else.
    """

    venv_dir, containment = consumer_smoke._resolve_smoke_venv()
    try:
        assert len(str(venv_dir)) < 120, (
            f"the venv root is {len(str(venv_dir))} characters, leaving too little of the "
            f"260-character budget for the paths installed beneath it: {venv_dir}"
        )
    finally:
        shutil.rmtree(containment, ignore_errors=True)


def test_the_cleanup_guard_still_refuses_a_directory_that_is_not_a_virtualenv(tmp_path: Path) -> None:
    """Unchanged behaviour, pinned here because this fix moves the root the guard is measured from."""

    repo_root = _repo(tmp_path)
    not_a_venv = repo_root / "not-a-venv"
    not_a_venv.mkdir()

    with pytest.raises(SystemExit):
        consumer_smoke._remove_virtualenv(repo_root, not_a_venv)

    assert not_a_venv.is_dir(), "the guard refused but deleted anyway"
