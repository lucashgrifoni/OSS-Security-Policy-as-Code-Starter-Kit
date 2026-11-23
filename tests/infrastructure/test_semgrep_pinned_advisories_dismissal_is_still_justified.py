"""The SECURITY.md dismissal of three Semgrep-pinned packages must not outlive its reason.

On 2026-11-23 sixteen Dependabot alerts against `mcp`, `opentelemetry-api` and `wcmatch`
were dismissed as tolerable risk, because `semgrep 1.186.0` pins all three below their
fixed versions and there is no upgrade to take. SECURITY.md records the reasoning and the
review condition: once Semgrep relaxes a pin, regenerate the lock and the alerts close.

That condition is a sentence, and nobody regenerating `semgrep.txt` has a reason to read
it. This guard ties the paragraph to the lock: while the paragraph is present, every
package it names must still be pinned below the version that fixes it. A lock that has
moved past a fixed version fails here, at the moment the decision becomes re-decidable,
with no network needed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SEMGREP_PINS = _REPO_ROOT / ".github" / "requirements" / "semgrep.txt"
_SECURITY_MD = _REPO_ROOT / "SECURITY.md"

_PARAGRAPH_MARKER = "Dependabot alerts on `mcp`, `opentelemetry-api` and `wcmatch` in the Semgrep lock"

#: Fixed versions named by the dismissed advisories (highest fix per package).
_FIXED_IN = {
    "mcp": (1, 30, 0),
    "opentelemetry-api": (1, 45, 2),
    "wcmatch": (11, 2),
}


def _parse_version(raw: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in raw.split("."):
        digits = re.match(r"\d+", chunk)
        if digits is None:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def _pinned(package: str) -> tuple[int, ...] | None:
    text = _SEMGREP_PINS.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(package)}==(\S+?)(?:\s|\\|$)", text, re.MULTILINE)
    return _parse_version(match.group(1)) if match else None


def test_both_files_are_readable() -> None:
    assert _SEMGREP_PINS.is_file(), f"missing {_SEMGREP_PINS.relative_to(_REPO_ROOT)}"
    assert _SECURITY_MD.is_file(), "missing SECURITY.md"


@pytest.mark.parametrize("package", sorted(_FIXED_IN))
def test_dismissal_is_dropped_once_the_lock_reaches_the_fix(package: str) -> None:
    if _PARAGRAPH_MARKER not in _SECURITY_MD.read_text(encoding="utf-8"):
        pytest.skip("the dismissal paragraph is gone; nothing to hold in place")

    pinned = _pinned(package)
    fixed = _FIXED_IN[package]
    if pinned is None:
        pytest.fail(
            f"semgrep.txt no longer pins `{package}`, so its advisories cannot reach CI "
            "through Semgrep. Remove it from the SECURITY.md dismissal paragraph (and the "
            "paragraph itself once no package is left), and update _FIXED_IN here."
        )
    assert pinned < fixed, (
        f"semgrep.txt now pins {package}=={'.'.join(map(str, pinned))}, at or past the "
        f"fixed {'.'.join(map(str, fixed))}. The reason for the SECURITY.md dismissal is "
        "gone for this package: drop it from the paragraph and from _FIXED_IN, and confirm "
        "its Dependabot alerts closed as fixed rather than staying dismissed."
    )
