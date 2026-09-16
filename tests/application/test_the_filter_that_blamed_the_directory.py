"""`evaluate-many` said the directory was empty when the filter was what emptied it.

A run with `--include` that matches nothing answered `No subdirectories to evaluate under
<root>`, which sends the operator to look at a directory that is not the problem. The
neighbouring check one branch below already gets this right for `--skip-non-repos`, naming the
flag it was given, so the shape of the fix is the one already in the file.

All three cases raise before any evaluation starts, so none of them needs a real repository.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.domain.errors import InvalidInputError


def _run(root: Path, out: Path, *, include: str | None = None, exclude: str | None = None) -> None:
    run_batch_evaluation(
        target_root=root,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=include,
        exclude=exclude,
    )


def _root_with_two_repos(tmp_path: Path) -> Path:
    root = tmp_path / "apps"
    for name in ("alpha", "beta"):
        (root / name).mkdir(parents=True)
    return root


def test_a_filter_that_matches_nothing_names_the_filter(tmp_path: Path) -> None:
    root = _root_with_two_repos(tmp_path)

    with pytest.raises(InvalidInputError) as caught:
        _run(root, tmp_path / "out", include="no-such-*")

    message = str(caught.value)
    assert "no-such-*" in message, message
    assert "No subdirectories to evaluate under" not in message, "the directory has two; the filter removed them"


def test_an_exclude_that_removes_everything_names_the_filter(tmp_path: Path) -> None:
    root = _root_with_two_repos(tmp_path)

    with pytest.raises(InvalidInputError) as caught:
        _run(root, tmp_path / "out", exclude="*")

    message = str(caught.value)
    assert "--exclude" in message, message
    assert "No subdirectories to evaluate under" not in message


def test_a_genuinely_empty_directory_still_says_so(tmp_path: Path) -> None:
    """The other direction. With no filter given, the directory is the honest answer."""

    root = tmp_path / "empty"
    root.mkdir()

    with pytest.raises(InvalidInputError) as caught:
        _run(root, tmp_path / "out")

    assert "No subdirectories to evaluate under" in str(caught.value)
