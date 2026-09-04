"""A configuration file that exists but configures nothing must not earn a PASS.

Two controls answered from the shape of a file rather than from what it does, and both are
declared ``assurance: deterministic`` and ``lifecycle: stable`` in the catalog -- the level
that promises the verdict follows from what was read:

``SEC-GITIGNORE-051`` -- ".gitignore present with basic secret protection patterns" --
substring-matched the raw file, so a `.gitignore` whose every pattern is commented out
still reported "includes basic secret-protection patterns (.env, *.pem, *.key)". A
commented `.env` ignores nothing; the file would be committed.

``DEP-UPDATE-001`` -- "Automated dependency update tool configured" -- returned PASS at
high confidence for any `dependabot.yml` that exists. A file whose `updates:` block is
commented out watches no ecosystem: GitHub reports a configuration error and Dependabot
opens nothing. `updates` is required by the schema, so its absence is decidable rather
than a guess.

Renovate is deliberately left on file existence: an empty renovate config is valid and
runs with defaults, so the file being there really is the signal.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators.cicd import eval_sec_gitignore_051
from oss_policy_kit.application.evaluators.governance import eval_dep_update_001


class _Ctx:
    def __init__(self, repo: Path) -> None:
        self.repo_root = repo


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


# --------------------------------------------------------------------------- .gitignore


def test_a_gitignore_whose_patterns_are_commented_protects_nothing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text(
        "# we stopped ignoring these while debugging the deploy\n# .env\n# *.pem\n# *.key\n",
        encoding="utf-8",
    )

    outcome = eval_sec_gitignore_051(_Ctx(repo))  # type: ignore[arg-type]

    assert outcome.status.value != "pass", (
        f"a .gitignore with every pattern commented out reported {outcome.status.value!r}: "
        f"{outcome.reason!r}. Those files would be committed."
    )


def test_a_real_gitignore_still_passes(tmp_path: Path) -> None:
    """The other half: a fix that stopped recognising a working .gitignore would be worse."""

    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("# secrets\n.env\n*.pem\n*.key\n", encoding="utf-8")

    outcome = eval_sec_gitignore_051(_Ctx(repo))  # type: ignore[arg-type]

    assert outcome.status.value == "pass"
    assert ".env" in outcome.reason


def test_a_pattern_on_a_line_with_a_trailing_comment_still_counts(tmp_path: Path) -> None:
    """`.gitignore` treats `#` as a comment only at the start of a line."""

    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text(".env  # local only, never commit\n", encoding="utf-8")

    assert eval_sec_gitignore_051(_Ctx(repo)).status.value == "pass"  # type: ignore[arg-type]


# --------------------------------------------------------------------------- dependabot


_PARKED_DEPENDABOT = """version: 2
# paused while we deal with the backlog
# updates:
#   - package-ecosystem: "pip"
#     directory: "/"
#     schedule:
#       interval: weekly
"""

_LIVE_DEPENDABOT = """version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: weekly
"""


@pytest.mark.parametrize("name", ["dependabot.yml", "dependabot.yaml"])
def test_a_dependabot_file_that_watches_nothing_is_not_configured(tmp_path: Path, name: str) -> None:
    repo = _repo(tmp_path)
    (repo / ".github").mkdir()
    (repo / ".github" / name).write_text(_PARKED_DEPENDABOT, encoding="utf-8")

    outcome = eval_dep_update_001(_Ctx(repo))  # type: ignore[arg-type]

    assert outcome.status.value != "pass", (
        f"a {name} whose updates block is commented out reported {outcome.status.value!r}: "
        f"{outcome.reason!r}. Dependabot opens no pull request for it."
    )


def test_a_dependabot_file_with_an_ecosystem_still_passes(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".github").mkdir()
    (repo / ".github" / "dependabot.yml").write_text(_LIVE_DEPENDABOT, encoding="utf-8")

    outcome = eval_dep_update_001(_Ctx(repo))  # type: ignore[arg-type]

    assert outcome.status.value == "pass"


def test_renovate_is_still_recognised_by_the_file_alone(tmp_path: Path) -> None:
    """An empty Renovate config is valid and runs with defaults, so presence is the signal."""

    repo = _repo(tmp_path)
    (repo / "renovate.json").write_text("{}\n", encoding="utf-8")

    assert eval_dep_update_001(_Ctx(repo)).status.value == "pass"  # type: ignore[arg-type]


def test_an_unreadable_dependabot_file_is_not_a_pass(tmp_path: Path) -> None:
    """Unparseable is not configured either, and it is not an excuse to claim it is."""

    repo = _repo(tmp_path)
    (repo / ".github").mkdir()
    (repo / ".github" / "dependabot.yml").write_text("{{{ not yaml :::\n", encoding="utf-8")

    assert eval_dep_update_001(_Ctx(repo)).status.value != "pass"  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("body", "why"),
    [
        ("- just\n- a list\n", "the file parses to a list, not a mapping"),
        ("version: 2\nupdates: not-a-list\n", "`updates` is not a list"),
        ("version: 2\nupdates:\n  - just-a-string\n", "an entry is not a mapping"),
        ('version: 2\nupdates:\n  - directory: "/"\n', "an entry names no ecosystem"),
        ('version: 2\nupdates:\n  - package-ecosystem: "   "\n', "the ecosystem is blank"),
    ],
    ids=[
        "not-a-mapping",
        "updates-not-a-list",
        "entry-not-a-mapping",
        "no-ecosystem",
        "blank-ecosystem",
    ],
)
def test_every_shape_that_watches_nothing_is_reported_as_such(tmp_path: Path, body: str, why: str) -> None:
    """Dependabot opens no pull request for any of these, so none of them may report PASS.

    Each is a real way a config ends up inert -- a stray list, a key holding the wrong type,
    an entry someone half-deleted -- and the parser accepts all of them, so only the reader
    can tell them apart from a working config.
    """

    repo = _repo(tmp_path)
    (repo / ".github").mkdir()
    (repo / ".github" / "dependabot.yml").write_text(body, encoding="utf-8")

    outcome = eval_dep_update_001(_Ctx(repo))  # type: ignore[arg-type]

    assert outcome.status.value != "pass", f"{why}, yet the control reported {outcome.reason!r}"
