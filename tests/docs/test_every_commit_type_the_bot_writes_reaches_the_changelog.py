"""A commit whose type nobody declared is a commit no reader ever sees.

`changelog-sections` REPLACES release-please's defaults, it does not extend them, so a type
absent from that list is dropped from the CHANGELOG with the release run green -- the same
shape as the gitleaks config that replaced the default ruleset and scanned nothing.

This was not hypothetical, and the repository holds a controlled measurement of it. Dependabot
writes `ci` for the github-actions ecosystem and `deps` for the other four. Same bot, same
repository, same workflow; the only variable is the type token:

    ci(deps): ...      32 of 32 reached CHANGELOG.md
    deps(deps): ...     0 of 12 reached CHANGELOG.md

Twelve dependency bumps -- boto3, botocore, python-hcl2, semgrep, ruff, zizmor -- left no trace
in the changelog of a security tool, which is the one place a reader looks to find out whether
a pinned scanner was updated.

The guard derives both sides rather than restating a list: every commit-message prefix declared
in `.github/dependabot.yml` must be a NON-HIDDEN type in `.github/release-please-config.json`.
Adding an ecosystem with a new prefix fails here instead of quietly producing invisible commits.

What it does NOT check: a type a human types by hand. `style`, `update` and `add` appear in this
history and are equally invisible, but nothing declares them anywhere, so there is no second list
to derive them from -- only the commit convention in docs/packaging-and-release.md, which this
file checks for accuracy rather than for enforcement.
"""

from __future__ import annotations

import json
import re

import yaml

from tests.conftest import ROOT

_DEPENDABOT = ROOT / ".github" / "dependabot.yml"
_CONFIG = ROOT / ".github" / "release-please-config.json"
_PACKAGING_DOC = ROOT / "docs" / "packaging-and-release.md"


def _declared_sections() -> dict[str, dict[str, object]]:
    config = json.loads(_CONFIG.read_text(encoding="utf-8"))
    return {entry["type"]: entry for entry in config["changelog-sections"]}


def _bot_prefixes() -> list[tuple[str, str]]:
    """Every commit-message prefix Dependabot is configured to write, with its ecosystem.

    Both `prefix` and `prefix-development` are read: Dependabot supports the second for dev
    dependencies, and an entry that adds one later must be covered without editing this helper.
    """

    config = yaml.safe_load(_DEPENDABOT.read_text(encoding="utf-8"))
    found: list[tuple[str, str]] = []
    for entry in config["updates"]:
        where = f"{entry['package-ecosystem']} in {entry['directory']}"
        message = entry.get("commit-message") or {}
        for key in ("prefix", "prefix-development"):
            if message.get(key):
                found.append((where, message[key]))
    return found


def _invisible(sections: dict[str, dict[str, object]], prefixes: list[tuple[str, str]]) -> list[str]:
    """The decision, as a pure function, so both ways of losing a commit can be tested.

    Two distinct shapes lose a bump, and only the first was ever observed here: a type absent
    from `changelog-sections`, and a type present but `hidden: true`. The second is one word
    away in a file where `chore` and `test` already carry it, so it is exercised below against
    a synthetic config rather than left to a future reader to discover in production.
    """

    invisible = []
    for where, prefix in prefixes:
        entry = sections.get(prefix)
        if entry is None:
            invisible.append(f"{where}: prefix {prefix!r} is not in changelog-sections at all")
        elif entry.get("hidden"):
            invisible.append(f"{where}: prefix {prefix!r} is declared hidden")
    return invisible


def test_the_bot_writes_no_type_the_changelog_discards() -> None:
    invisible = _invisible(_declared_sections(), _bot_prefixes())

    assert not invisible, (
        "Dependabot writes commit types the CHANGELOG discards, so these bumps ship "
        "invisibly:\n  " + "\n  ".join(invisible)
    )


def test_the_guard_sees_a_type_that_is_merely_hidden() -> None:
    """A declared-but-hidden type drops the commit exactly as an undeclared one does.

    `hidden: true` is not a formatting preference: release-please omits the section, so the
    bump never reaches a reader. Without this case the guard would pass a config that hid
    every dependency bump.
    """

    hidden_config = {"deps": {"type": "deps", "section": "Notes", "hidden": True}}
    complaints = _invisible(hidden_config, [("pip in /", "deps")])

    assert complaints == ["pip in /: prefix 'deps' is declared hidden"]


def test_the_guard_sees_a_type_nobody_declared() -> None:
    """The shape this file was written for, held against a synthetic config.

    The real configuration is fixed now, so the live check passes and stops demonstrating
    anything. This keeps the undeclared-type branch exercised after the fix that closed it.
    """

    complaints = _invisible({}, [("cargo in /rust", "deps")])

    assert complaints == ["cargo in /rust: prefix 'deps' is not in changelog-sections at all"]


def test_at_least_one_prefix_was_actually_read() -> None:
    """The guard above passes vacuously if the parse returns nothing.

    A renamed key or a restructured dependabot.yml would empty the list and turn this file
    into decoration. Five ecosystems are configured today; asserting a non-empty read is the
    part that survives a restructure, so the number is not restated here.
    """

    assert _bot_prefixes(), f"no commit-message prefix parsed out of {_DEPENDABOT}"


def test_the_documented_mapping_names_every_visible_type() -> None:
    """docs/packaging-and-release.md enumerates the mapping; an added section makes it stale.

    The enumeration is a parenthetical of backticked type names. This compares that set against
    the non-hidden types in the config, so a section added to one side has to reach the other.
    """

    doc = _PACKAGING_DOC.read_text(encoding="utf-8")
    match = re.search(r"grouped by the `changelog-sections` in that file\s*\n?\s*\((.*?)\)", doc, re.S)
    assert match, f"the changelog-sections enumeration is no longer in {_PACKAGING_DOC}"

    documented = set(re.findall(r"`([a-z]+)`", match.group(1)))
    visible = {name for name, entry in _declared_sections().items() if not entry.get("hidden")}

    assert documented == visible, (
        f"{_PACKAGING_DOC.name} documents {sorted(documented)} but the config makes "
        f"{sorted(visible)} visible; undocumented={sorted(visible - documented)}, "
        f"documented-but-not-visible={sorted(documented - visible)}"
    )
