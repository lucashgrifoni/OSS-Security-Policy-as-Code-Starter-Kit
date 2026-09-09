"""The same repository has to get the same verdict on NTFS and on ext4.

``(directory / "CODEOWNERS").is_file()`` asks the filesystem, and filesystems disagree:
NTFS and APFS answer without regard to case, ext4 does not. So a repository holding
`contributing.md`, `changelog.md` and `.github/codeowners` was reported fully green on a
maintainer's laptop and failed three controls on the Linux runner gating the same pull
request -- green locally, red in CI, for byte-identical input.

The rule is not the same for every file, which is why this is not one blanket fix:

* `CONTRIBUTING` -- GitHub states "Contributing guidelines filenames are not case
  sensitive", so matching exactly disagreed with the platform being audited;
* `CODEOWNERS` -- GitHub uses a case-sensitive filesystem, writes the name uppercase
  everywhere, and documents case-insensitivity when it applies (as it does for
  CONTRIBUTING) but not here. A lowercase `codeowners` routes no review, so counting it
  was a false pass;
* `CHANGELOG` -- a convention no forge assigns meaning to, and every changelog tool
  accepts either casing.

The helpers list the directory instead of asking the filesystem, so each rule holds
everywhere rather than being whatever the host happens to do.
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators._shared import (
    _file_named_any_case,
    _file_named_exactly,
)
from oss_policy_kit.application.evaluators.governance import (
    eval_gov_con_002,
    eval_gov_cown_003,
    eval_rel_change_012,
)


class _Ctx:
    def __init__(self, repo: Path) -> None:
        self.repo_root = repo


# --------------------------------------------------------------------------- the helpers


def test_an_exact_lookup_ignores_what_the_filesystem_would_answer(tmp_path: Path) -> None:
    """This is the assertion that fails on NTFS if the lookup goes back to `.is_file()`."""

    (tmp_path / "codeowners").write_text("* @a\n", encoding="utf-8")

    assert _file_named_exactly(tmp_path, "CODEOWNERS") is None, (
        "a case-insensitive filesystem answered for the lookup; the verdict would differ on Linux"
    )
    assert _file_named_exactly(tmp_path, "codeowners") is not None


def test_an_insensitive_lookup_finds_a_differently_cased_name(tmp_path: Path) -> None:
    """And this is the one that fails on ext4 if the lookup goes back to `.is_file()`."""

    (tmp_path / "contributing.md").write_text("hi\n", encoding="utf-8")

    found = _file_named_any_case(tmp_path, "CONTRIBUTING.md")

    assert found is not None and found.name == "contributing.md"


def test_a_missing_directory_is_not_an_error(tmp_path: Path) -> None:
    assert _file_named_exactly(tmp_path / "nope", "CODEOWNERS") is None
    assert _file_named_any_case(tmp_path / "nope", "CONTRIBUTING.md") is None


# --------------------------------------------------------------------------- the controls


def _repo(tmp_path: Path, files: dict[str, str]) -> _Ctx:
    repo = tmp_path / "repo"
    for rel, body in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return _Ctx(repo)


def test_a_lowercase_contributing_counts_because_github_says_it_does(tmp_path: Path) -> None:
    ctx = _repo(tmp_path, {"contributing.md": "how to contribute\n"})

    assert eval_gov_con_002(ctx).status.value == "pass"  # type: ignore[arg-type]


def test_a_lowercase_codeowners_does_not_count_because_github_ignores_it(tmp_path: Path) -> None:
    """The direction that matters: this used to be a false pass on Windows."""

    ctx = _repo(tmp_path, {".github/codeowners": "* @a\n"})

    outcome = eval_gov_cown_003(ctx)  # type: ignore[arg-type]

    assert outcome.status.value != "pass", (
        "a lowercase `codeowners` routes no review on GitHub, so counting it tells the "
        f"adopter they have code owners when they have none: {outcome.reason!r}"
    )


def test_the_canonical_codeowners_still_counts(tmp_path: Path) -> None:
    ctx = _repo(tmp_path, {".github/CODEOWNERS": "* @a\n"})

    assert eval_gov_cown_003(ctx).status.value == "pass"  # type: ignore[arg-type]


def test_a_lowercase_changelog_counts(tmp_path: Path) -> None:
    ctx = _repo(tmp_path, {"changelog.md": "# 1.0\n"})

    assert eval_rel_change_012(ctx).status.value == "pass"  # type: ignore[arg-type]
