"""Detect unfilled scaffold tokens in evidence JSON."""

from __future__ import annotations

import re

_PLACEHOLDER_PATTERNS: tuple[str, ...] = (
    "REPLACE_ME",
    "REPLACE-ME",
    "YOUR_",
    "YOUR-",
    "YYYY-MM-DD",
    "<CHANGEME>",
    "TODO",
    "FIXME",
    "placeholder",
    "PLACEHOLDER",
)

# SHA-256 digests copied from scaffold templates (evidence_scaffold.py) — not real artifacts.
_KNOWN_TEMPLATE_DIGEST_HEX: frozenset[str] = frozenset(
    {
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "0" * 64,
        "f" * 64,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
# Entire digest is a short substring repeated (e.g. deadbeefdeadbeef...).
_LOW_ENTROPY_REPEAT = re.compile(r"^(.{1,16})\1{2,}$")


def is_placeholder_digest(value: str) -> bool:
    """Return True when a 64-char hex string is clearly a template or toy digest, not a real artifact hash."""

    v = value.strip().lower()
    if not _HEX64.match(v):
        return False
    if v in _KNOWN_TEMPLATE_DIGEST_HEX:
        return True
    if len(set(v)) <= 1:
        return True
    return bool(_LOW_ENTROPY_REPEAT.match(v))


def has_placeholder_values(data: object) -> list[str]:
    """Return distinct placeholder tokens found in nested string values.

    Args:
        data: Arbitrary nested structure (dict, list, str).

    Returns:
        List of matched pattern labels (from :data:`_PLACEHOLDER_PATTERNS`). Empty when clean.
    """

    found: list[str] = []
    seen: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, str):
            _record_placeholders(node, found, seen)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return found


def _record_placeholders(text: str, found: list[str], seen: set[str]) -> None:
    """Append any new placeholder patterns found in ``text`` (case-insensitive) to ``found``."""

    upper = text.upper()
    for pattern in _PLACEHOLDER_PATTERNS:
        p = pattern.upper()
        if p in upper and p not in seen:
            seen.add(p)
            found.append(pattern)
