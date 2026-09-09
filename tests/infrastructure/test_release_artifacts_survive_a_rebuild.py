"""Guards on the two things that decide whether a published wheel can be rebuilt.

A release is traceable only as far as somebody else can rebuild it and compare. Both
guards here come from an attempt to do exactly that against the published v10.0.20
wheel: 227 of its 231 entries matched byte for byte on the first try, and the four
that did not were `dist-info/licenses/LICENSE`, `NOTICE`, the `RECORD` that hashes
them, and `METADATA`. None of them was a code difference -- they were CRLF, because
`.gitattributes` listed extensions and those files have none.

Fixing that left one difference: the ZIP timestamps. The published wheel carries the
runner's clock, which nobody else has, so `SOURCE_DATE_EPOCH` has to come from the
commit instead.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
_GITATTRIBUTES_PATH = _REPO_ROOT / ".gitattributes"
_PYPROJECT_PATH = _REPO_ROOT / "pyproject.toml"


def _attribute_rules() -> list[tuple[str, list[str]]]:
    """`(pattern, attributes)` for every rule line, comments and blanks dropped."""

    rules: list[tuple[str, list[str]]] = []
    for line in _GITATTRIBUTES_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pattern, *attributes = stripped.split()
        rules.append((pattern, attributes))
    return rules


def test_gitattributes_normalises_everything_not_a_list_of_extensions() -> None:
    """A catch-all must lead, so an unlisted extension is never silently uncovered.

    The allowlist that shipped through v10.0.20 covered `*.md`, `*.py`, `*.json`,
    `*.yml`, `*.yaml`, `*.toml`, `*.rego`, `*.cel` and `.gitignore`. `LICENSE`,
    `NOTICE`, `Dockerfile`, `CODEOWNERS` and the hash-pinned requirement locks matched
    none of them.
    """

    rules = _attribute_rules()
    assert rules, ".gitattributes has no rules"

    pattern, attributes = rules[0]
    assert pattern == "*", (
        f"the first .gitattributes rule is '{pattern}'; a later catch-all still leaves "
        "earlier rules deciding, so the catch-all has to lead"
    )
    assert "text=auto" in attributes, f"catch-all must set text=auto, got {attributes}"
    assert "eol=lf" in attributes, f"catch-all must set eol=lf, got {attributes}"


def test_no_gitattributes_rule_asks_for_crlf() -> None:
    """One `eol=crlf` anywhere reintroduces the divergence for whatever it matches."""

    for pattern, attributes in _attribute_rules():
        for attribute in attributes:
            assert attribute != "eol=crlf", f"'{pattern}' asks for CRLF in the working tree"


def test_license_files_that_ship_inside_the_wheel_are_lf() -> None:
    """`license-files` land in `dist-info/licenses/` and are hashed into RECORD.

    LICENSE was 11358 bytes in git and 11560 on a Windows checkout. A wheel built from
    that checkout could not match the published hash, which is indistinguishable from a
    tampered artifact to anyone verifying it.
    """

    declared = tomllib.loads(_PYPROJECT_PATH.read_text(encoding="utf-8"))["project"]["license-files"]
    assert declared, "pyproject declares no license-files"

    for name in declared:
        path = _REPO_ROOT / name
        assert path.is_file(), f"{name} is declared in license-files but not present"
        raw = path.read_bytes()
        assert b"\r\n" not in raw, (
            f"{name} holds {raw.count(b'\r\n')} CRLF line endings; it ships inside the wheel, "
            "so this changes the artifact hash"
        )
