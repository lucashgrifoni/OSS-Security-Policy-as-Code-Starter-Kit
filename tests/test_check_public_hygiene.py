"""Regression tests for ``scripts/check_public_hygiene.py``.

These tests pin the regex behavior of the public hygiene scanner — both
that it still catches real private tokens and that it does not flag
in-source identifiers that merely happen to share substrings with home-
path prefixes (e.g. ``Roles/Users/Groups``).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_hygiene_module():
    """Import ``scripts/check_public_hygiene.py`` despite the hyphenated path."""

    path = _REPO_ROOT / "scripts" / "check_public_hygiene.py"
    spec = importlib.util.spec_from_file_location("check_public_hygiene", path)
    assert spec and spec.loader, "could not locate scripts/check_public_hygiene.py"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _posix_home_path_regex() -> re.Pattern[str]:
    module = _load_hygiene_module()
    for label, pattern, is_regex in module.DEFAULT_FORBIDDEN_TOKENS:
        if label == "posix-home-path":
            assert is_regex, "posix-home-path entry must be a regex"
            return re.compile(pattern)
    raise AssertionError("posix-home-path token entry missing from DEFAULT_FORBIDDEN_TOKENS")


def test_posix_home_path_detects_users_prefix() -> None:
    rgx = _posix_home_path_regex()
    assert rgx.search("/Users/alice/private")


def test_posix_home_path_detects_home_prefix() -> None:
    rgx = _posix_home_path_regex()
    assert rgx.search("/home/alice/private")


def test_posix_home_path_detects_inside_comment_with_leading_space() -> None:
    rgx = _posix_home_path_regex()
    assert rgx.search("# leak: /Users/bob/secret.json")


def test_posix_home_path_skips_identifier_prefixed_path_segment() -> None:
    """Prose like ``Roles/Users/Groups`` must NOT be flagged."""

    rgx = _posix_home_path_regex()
    assert rgx.search("Inline policies on Roles/Users/Groups.") is None


def test_posix_home_path_skips_identifier_prefixed_home_segment() -> None:
    rgx = _posix_home_path_regex()
    assert rgx.search("foo/home/bar baz") is None
