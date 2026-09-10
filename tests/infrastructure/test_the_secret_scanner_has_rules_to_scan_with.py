"""`.gitleaks.toml` never leaves gitleaks with an empty ruleset.

A gitleaks config replaces the default ruleset; it does not add to it. A file that
declares only an `[allowlist]` therefore leaves the scanner with no rules, and every scan
reports "no leaks found" whatever the input. The CLI picks this file up automatically from
the repository root, so the blindness reaches the `Secrets History - Gitleaks` job, any
pre-commit hook, and every `gitleaks detect` anyone runs in a clone.

This repository stood in exactly that state from 2026-05-01 (fd95f6f) until 2026-09-10,
when the global gate ran the scan against a planted canary instead of trusting its verdict.
Measured with gitleaks 8.30.1: a directory holding an AWS key pair and a `ghp_` token
scanned clean inside the repository and reported both findings outside it, and passing this
config explicitly reproduced the miss in the isolated directory. The job had been green for
four months over a scan of nothing.

The failure has no symptom -- the tool exits 0 and prints a reassuring line -- so the guard
has to be structural. This test asserts the invariant that was violated: the config either
extends the default ruleset or carries rules of its own, and its allowlist stays a list of
named literals rather than a pattern that exempts whole files or directories.

What it cannot do is run gitleaks: the binary is not installed in the quality job, and
installing it to assert one config property would be a heavier trade than the property is
worth. The functional check -- plant a secret, confirm it is reported -- is the manual step
recorded above, and it is the step to repeat if this file changes shape again.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / ".gitleaks.toml"

#: Allowlist patterns that would exempt more than a named value. `paths` exempts whole
#: files; a regex containing a quantified wildcard exempts whatever happens to sit next to
#: it. Either turns a narrow exception into a hole the next reader cannot size.
_WILDCARD_FRAGMENTS = (".*", ".+", "[\\s\\S]", "(?s)")


def _config() -> dict[str, Any]:
    return tomllib.loads(_CONFIG.read_text(encoding="utf-8"))


def _has_no_rules(config: dict[str, Any]) -> bool:
    """True when gitleaks would load this config and end up with nothing to match."""

    extends_default = bool(config.get("extend", {}).get("useDefault"))
    own_rules = config.get("rules") or []
    return not extends_default and not own_rules


def test_the_emptiness_check_recognises_the_config_that_broke() -> None:
    """Sanity: the predicate below flags the shape this file actually had.

    Without this, the assertion that follows could pass because the predicate never
    returns True for anything.
    """

    # The literal is deliberately not credential-shaped: the predicate reads the shape of the
    # config, and a real-looking key here would only give the public-hygiene gate something
    # to flag in a file that is about configuration, not about secrets.
    broken = {"allowlist": {"description": "only an allowlist", "regexes": ["a-value-the-allowlist-names"]}}
    assert _has_no_rules(broken), "the predicate no longer recognises a config with no rules"

    assert not _has_no_rules({"extend": {"useDefault": True}})
    assert not _has_no_rules({"rules": [{"id": "something"}]})


def test_the_scanner_is_left_with_rules_to_scan_with() -> None:
    config = _config()
    assert not _has_no_rules(config), (
        f"{_CONFIG.name} leaves gitleaks with an empty ruleset: it neither sets "
        "`extend.useDefault = true` nor declares rules of its own. Every scan that reads "
        "this file will report no leaks regardless of what the tree or the history holds."
    )


def test_the_allowlist_names_values_rather_than_exempting_places() -> None:
    """A scoped exception stays readable; a wildcard one hides its own blast radius."""

    allowlist = _config().get("allowlist", {})
    assert allowlist, "sanity: the allowlist went missing from the parse"

    regexes = allowlist.get("regexes") or []
    assert len(regexes) >= 2, f"sanity: only {len(regexes)} allowlist entries parsed"

    assert "paths" not in allowlist, (
        "the allowlist now exempts paths. A file-scoped exception hides every future "
        "secret committed to that file, which is not what the two literal entries do."
    )

    for pattern in regexes:
        for fragment in _WILDCARD_FRAGMENTS:
            assert fragment not in pattern, (
                f"allowlist entry {pattern!r} exempts more than a named value ({fragment!r})"
            )
