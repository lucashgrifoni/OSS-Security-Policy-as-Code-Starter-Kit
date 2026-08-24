"""A slug read from the evaluated repository must not be able to steer the API path.

`collect-evidence` derives `owner/repo` from the target repository's own `.git/config` when
`--repo` is not given, so that value is controlled by whoever wrote the repository being
evaluated. It is then interpolated into the collector's request paths.

The validator accepted `../..`: two non-empty segments, which was the whole test. `httpx`
normalises `..` in a path, so `/repos/../../rulesets` becomes `https://api.github.com/rulesets`
-- a different endpoint from the one the operator asked for, requested with the operator's token.

The blast radius was small: the host is a pinned constant, so the token never left GitHub, and
capping at two segments meant no arbitrary path could be appended. This is defence in depth on a
trust boundary rather than a repaired exploit, and it is cheap: GitHub owner and repository names
are drawn from a narrow alphabet that excludes `.` and `..` outright.
"""

from __future__ import annotations

import pytest

from oss_policy_kit.infrastructure.collectors.github_collector import _parse_owner_repo

_REJECTED = [
    "../..",
    "./..",
    "%2e%2e/%2e%2e",
    "..%2f..",
    ".",
    "../evil",
    "org/..",
    "../repo",
    "org/repo/extra",
    "org",
    "",
    "/",
    "org/re po",
    "org/repo?x=1",
    "org/repo#frag",
]

_ACCEPTED = [
    ("org/repo", ("org", "repo")),
    ("My-Org/my_repo", ("My-Org", "my_repo")),
    ("a.b/c.d", ("a.b", "c.d")),
    ("  org/repo  ", ("org", "repo")),
    ("0/9", ("0", "9")),
]


@pytest.mark.parametrize("slug", _REJECTED, ids=[s or "<vazio>" for s in _REJECTED])
def test_a_slug_that_is_not_owner_slash_repo_is_refused(slug: str) -> None:
    with pytest.raises(ValueError, match="Invalid GitHub repo slug"):
        _parse_owner_repo(slug)


@pytest.mark.parametrize(("slug", "expected"), _ACCEPTED, ids=[s[0].strip() for s in _ACCEPTED])
def test_a_real_slug_still_parses(slug: str, expected: tuple[str, str]) -> None:
    """The counterpart: a validator that refused everything would pass the test above."""

    assert _parse_owner_repo(slug) == expected
