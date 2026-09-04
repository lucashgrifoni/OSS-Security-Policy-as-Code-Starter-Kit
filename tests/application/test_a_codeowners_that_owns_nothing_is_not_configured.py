"""A CODEOWNERS file that assigns ownership to nobody is not a configured one.

``GOV-COWN-003`` is titled "CODEOWNERS configured" and is declared ``assurance: deterministic``
and ``lifecycle: stable`` in the catalog -- the level that promises the verdict follows from
what was read. It answered from the existence of the file alone, so a `CODEOWNERS` holding
nothing but comments, or nothing at all, reported "CODEOWNERS file present." at high
confidence and earned its full weight.

GitHub requests a review from code owners only for paths matched by a rule that names an
owner. A file with no such rule assigns ownership to nobody: no reviewer is ever added, and
a branch protection rule requiring review from Code Owners has no owners to require. The
effect on the repository is identical to having no file, which is the case the control
already fails.

A pattern with no owner after it is valid CODEOWNERS syntax and deliberately means "these
files have no owner", so it does not count as ownership either.

Reading the file also made *where* it is read from load-bearing, and the cases for that live
here too: GitHub searches ``.github/``, the repository root and ``docs/`` in that order and
uses the first file it finds, so the lookup has to search the same places in the same order.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators._shared import _codeowners_file, _codeowners_text
from oss_policy_kit.application.evaluators.governance import eval_gov_cown_003


class _Ctx:
    def __init__(self, repo: Path) -> None:
        self.repo_root = repo


def _repo_with(tmp_path: Path, body: str, *, at: str = ".github/CODEOWNERS") -> _Ctx:
    repo = tmp_path / "repo"
    target = repo / at
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return _Ctx(repo)


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ("", "the file is empty"),
        ("   \n\n\t\n", "the file holds only whitespace"),
        ("# * @platform-team\n# /src/ @backend\n", "every rule is commented out"),
        ("# ownership paused during the reorg\n", "the file holds only a comment"),
        ("*\n", "the pattern names no owner"),
        ("/src/\n/docs/\n", "no pattern names an owner"),
    ],
    ids=[
        "empty",
        "whitespace-only",
        "rules-commented-out",
        "comment-only",
        "pattern-without-owner",
        "several-patterns-without-owners",
    ],
)
def test_a_codeowners_that_names_no_owner_is_not_configured(tmp_path: Path, body: str, why: str) -> None:
    outcome = eval_gov_cown_003(_repo_with(tmp_path, body))  # type: ignore[arg-type]

    assert outcome.status.value != "pass", (
        f"{why}, yet the control reported {outcome.status.value!r}: {outcome.reason!r}. "
        f"No reviewer is ever requested for this repository."
    )


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ("* @lucashgrifoni\n", "a global owner"),
        ("/src/ @org/backend-team\n", "a team owner"),
        ("* maintainer@example.com\n", "an email owner"),
        ("# routing\n* @a\n", "a live rule below a comment"),
        ("* @a  # primary maintainer\n", "a live rule with a trailing comment"),
    ],
    ids=["user", "team", "email", "rule-below-comment", "trailing-comment"],
)
def test_a_codeowners_that_names_an_owner_still_passes(tmp_path: Path, body: str, why: str) -> None:
    """The other half: a fix that stopped recognising real ownership would be worse."""

    outcome = eval_gov_cown_003(_repo_with(tmp_path, body))  # type: ignore[arg-type]

    assert outcome.status.value == "pass", f"{why} should count as configured, got {outcome.reason!r}"


@pytest.mark.parametrize("at", [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"])
def test_every_location_github_reads_is_read_here(tmp_path: Path, at: str) -> None:
    """GitHub looks in `.github/`, the repository root and `docs/`, and uses the first it finds.

    `docs/` was missing here, so a repository whose code owners live there -- a real layout, and
    the one GitHub's own documentation lists last -- was told it had no CODEOWNERS at all while
    reviews were being routed normally.
    """

    outcome = eval_gov_cown_003(_repo_with(tmp_path, "* @a\n", at=at))  # type: ignore[arg-type]

    assert outcome.status.value == "pass", f"a CODEOWNERS at {at} is the one GitHub would use"


@pytest.mark.parametrize(
    ("winner", "loser"),
    [(".github/CODEOWNERS", "CODEOWNERS"), ("CODEOWNERS", "docs/CODEOWNERS")],
    ids=["github-beats-root", "root-beats-docs"],
)
def test_the_first_location_wins_even_when_a_later_one_is_empty(tmp_path: Path, winner: str, loser: str) -> None:
    """Reading the wrong file is how a search order turns into a wrong verdict.

    The predecessor of this lookup was a boolean `or`, so its order could never be observed.
    Returning a path makes the order load-bearing: with a working file at `winner` and an empty
    one at `loser`, GitHub reads only `winner`, and so must this.
    """

    ctx = _repo_with(tmp_path, "* @a\n", at=winner)
    empty = ctx.repo_root / loser
    empty.parent.mkdir(parents=True, exist_ok=True)
    empty.write_text("", encoding="utf-8")

    outcome = eval_gov_cown_003(ctx)  # type: ignore[arg-type]

    assert outcome.status.value == "pass", (
        f"{loser} is empty but GitHub never reads it -- {winner} is the file that decides"
    )


def test_a_missing_codeowners_still_fails(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    outcome = eval_gov_cown_003(_Ctx(repo))  # type: ignore[arg-type]

    assert outcome.status.value == "fail"
    for where in (".github/CODEOWNERS", "docs/CODEOWNERS"):
        assert where in outcome.reason, f"the reason must name every location that was searched, and it omits {where}"


def test_an_unreadable_codeowners_is_not_a_pass(tmp_path: Path) -> None:
    """Undecodable bytes are not ownership, and they are not an excuse to claim ownership."""

    repo = tmp_path / "repo"
    (repo / ".github").mkdir(parents=True)
    (repo / ".github" / "CODEOWNERS").write_bytes(b"\xff\xfe\x00\x00 \xd8\x00")

    assert eval_gov_cown_003(_Ctx(repo)).status.value != "pass"  # type: ignore[arg-type]


def test_a_codeowners_the_kit_cannot_open_is_manual_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-045: evidence the kit could not read is not a verdict in either direction.

    A file it cannot open is not "no code owners" -- the repository may be configured
    perfectly and the kit simply could not look. Failing it would be as wrong as passing it,
    and the operator is told to check by hand instead.
    """

    ctx = _repo_with(tmp_path, "* @a\n")
    real_read_bytes = Path.read_bytes

    def _refuse(self: Path) -> bytes:
        if self.name == "CODEOWNERS":
            raise PermissionError(13, "Permission denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _refuse)

    outcome = eval_gov_cown_003(ctx)  # type: ignore[arg-type]

    assert outcome.status.value == "manual-review-required"
    assert "could not be read" in outcome.reason


@pytest.mark.parametrize("at", [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"])
def test_both_readers_agree_on_which_file_decides(tmp_path: Path, at: str) -> None:
    """There is one search, and this is what stops a second one from growing back.

    `_codeowners_text` backs AI-AGENT-003 and had its own copy of the search that listed the
    repository root before `.github/` -- so the two could name different files for the same
    repository. They now share `_codeowners_file`, and this pins that.
    """

    ctx = _repo_with(tmp_path, "* @a\n", at=at)
    entry = _codeowners_text(ctx.repo_root)

    assert entry is not None
    assert entry[0] == _codeowners_file(ctx.repo_root)


def test_both_readers_pick_the_file_github_would_read(tmp_path: Path) -> None:
    """With a file in every location, both readers must land on `.github/`."""

    ctx = _repo_with(tmp_path, "* @github-dir\n", at=".github/CODEOWNERS")
    for at, owner in (("CODEOWNERS", "@root"), ("docs/CODEOWNERS", "@docs")):
        other = ctx.repo_root / at
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_text(f"* {owner}\n", encoding="utf-8")

    chosen = _codeowners_file(ctx.repo_root)
    entry = _codeowners_text(ctx.repo_root)

    assert chosen is not None and chosen.parent.name == ".github"
    assert entry is not None and entry[0] == chosen
    assert "github-dir" in entry[1], "the text came from a file GitHub would not have read"
