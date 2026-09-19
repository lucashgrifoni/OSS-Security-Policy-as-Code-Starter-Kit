"""The guard that catches a commit release-please read and did not write.

The defect: a commit BODY the conventional-commits parser rejects makes release-please omit
that commit from the CHANGELOG while the run stays green. It ate a security fix from the
10.0.22 cycle. The parser's exact rejection rule is not pinned, so the guard compares the
OUTCOME instead of replaying the rule -- and these tests exercise that comparison directly,
because the guard itself passes silently on `master`, where the newest section is already
tagged and therefore published history.

Without the cases below, the script would be a check that never fails anywhere anyone looks.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts.check_changelog_kept_every_commit import (
    dropped_commits,
    released_range,
    visible_types,
)
from tests.conftest import ROOT

_CONFIG = ROOT / ".github" / "release-please-config.json"

_HEADER = (
    "## [10.0.23](https://github.com/o/r/compare/v10.0.22...v10.0.23) (2026-09-16)\n\n"
    "### Fixes\n\n"
    "* **ci:** kept ([#1](https://github.com/o/r/issues/1)) "
    "([aaaaaaa](https://github.com/o/r/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa))\n"
)


def test_the_range_comes_from_the_section_header() -> None:
    """The denominator is release-please's own statement of what it read."""

    assert released_range(_HEADER) == ("v10.0.22", "v10.0.23")


def test_a_changelog_with_no_compare_link_is_not_a_range() -> None:
    assert released_range("# Changelog\n\nNothing released yet.\n") is None


def test_the_visible_types_are_read_from_the_real_config() -> None:
    """Derived, not restated: a type hidden or added in the config moves this set with it."""

    config = json.loads(_CONFIG.read_text(encoding="utf-8"))
    hidden = {e["type"] for e in config["changelog-sections"] if e.get("hidden")}

    types = visible_types(_CONFIG)

    assert "fix" in types and "deps" in types
    assert not (types & hidden), "a hidden type is being demanded in the CHANGELOG"


def test_a_cited_commit_is_not_reported() -> None:
    commits = [("a" * 40, "fix(ci): kept")]

    assert dropped_commits(commits, _HEADER, visible_types(_CONFIG)) == []


def test_a_commit_the_changelog_never_cites_is_reported() -> None:
    """The defect itself: in the range, of a visible type, absent from the text."""

    commits = [("a" * 40, "fix(ci): kept"), ("b" * 40, "fix(evaluate): dropped by the parser")]

    missing = dropped_commits(commits, _HEADER, visible_types(_CONFIG))

    assert [subject for _, subject in missing] == ["fix(evaluate): dropped by the parser"]


def test_a_hidden_type_is_expected_to_be_absent() -> None:
    """`chore` and `test` are configured hidden, so their absence is the contract, not a bug."""

    commits = [("c" * 40, "chore: bump something"), ("d" * 40, "test: add a case")]

    assert dropped_commits(commits, _HEADER, visible_types(_CONFIG)) == []


def test_a_subject_with_no_conventional_type_is_skipped() -> None:
    """Stated as a limitation in the script: no type to classify, so nothing to demand."""

    commits = [("e" * 40, "just some words with no type")]

    assert dropped_commits(commits, _HEADER, visible_types(_CONFIG)) == []


def test_a_scoped_breaking_subject_still_resolves_its_type() -> None:
    """`fix(scope)!: ...` is the shape a breaking change takes, and it is still a `fix`."""

    commits = [("f" * 40, "fix(api)!: drop the old flag")]

    missing = dropped_commits(commits, _HEADER, visible_types(_CONFIG))

    assert [sha for sha, _ in missing] == ["f" * 40]


def test_the_script_is_reachable_as_a_module() -> None:
    """It runs from the workflow by path; importing it here is what makes it testable at all."""

    import scripts.check_changelog_kept_every_commit as guard

    assert Path(guard.__file__).name == "check_changelog_kept_every_commit.py"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, encoding="utf-8")


def _repo_at_the_window(tmp_path: Path, *, tag_previous: bool) -> Path:
    """A repo in the state that exists between merging a release PR and pushing its tag.

    The newest CHANGELOG section is the NEXT version, so `previous` is the release that was
    just merged. `tag_previous` decides whether that release already carries its tag.
    """

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "T")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "tag.gpgsign", "false")

    config_dir = repo / ".github"
    config_dir.mkdir()
    (config_dir / "release-please-config.json").write_text(_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")

    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n"
        "## [11.0.0](https://github.com/o/r/compare/v10.0.24...v11.0.0) (2026-09-19)\n\n"
        "### Fixes\n\n* **ci:** kept\n",
        encoding="utf-8",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "chore: the 10.0.24 release, merged")
    if tag_previous:
        _git(repo, "tag", "v10.0.24")

    (repo / "later.txt").write_text("after the merge\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "fix(ci): kept")
    return repo


def test_an_untagged_previous_version_is_reported_not_crashed(tmp_path: Path, capsys) -> None:
    """The window between merging a release PR and pushing its tag must not look like a defect.

    `git log v10.0.24..HEAD` exits 128 while that tag is missing, and the traceback reads as
    "a commit was dropped" -- the single thing this guard exists to say. Measured on the real
    10.0.24 release: the check went red on `bad9676` for exactly this reason, minutes before
    the tag was pushed, and green once it was.

    The script already handles the mirror case, a `current` that is tagged. This is the other
    side of the same question.
    """

    import scripts.check_changelog_kept_every_commit as guard

    repo = _repo_at_the_window(tmp_path, tag_previous=False)

    assert guard.main(["--repo", str(repo)]) == 0

    out = capsys.readouterr().out
    assert "v10.0.24 is not tagged yet" in out
    assert "push the tag" in out


def test_a_tagged_previous_version_still_catches_a_dropped_commit(tmp_path: Path, capsys) -> None:
    """The early return must defer the comparison, never disable it.

    The cheap version of this test would assert a clean pass once the tag exists, and it
    would still pass if the early return had been written to fire unconditionally. So the
    fixture leaves a `fix(ci)` commit **uncited** in the CHANGELOG and asserts the guard
    still reports it: proof the comparison ran and can fail, not merely that it was reached.
    """

    import scripts.check_changelog_kept_every_commit as guard

    repo = _repo_at_the_window(tmp_path, tag_previous=True)

    assert guard.main(["--repo", str(repo)]) == 1

    out = capsys.readouterr().out
    assert "is not tagged yet" not in out
    assert "Range v10.0.24..v11.0.0" in out
    assert "fix(ci): kept" in out
