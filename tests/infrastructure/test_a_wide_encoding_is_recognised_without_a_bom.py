"""`decode_source` deduces a wide encoding from its NUL pattern, and never reads less for trying.

The invariant this primitive exists to keep is stated in its own docstring: *never read less than
the previous release read*. Two earlier attempts at making it stricter shipped worse bugs than the
one they fixed, both by refusing a file the previous release had read.

This module used to claim the BOM-less detection was *incapable* of that -- "anything it guesses
wrong about falls straight back to the old read". That was false, and the tests below are the
reason it no longer is. A wrong guess only falls back when it RAISES, and whether it raises is
decided by the file's length parity. On the other parity the mis-decode succeeds, and a
successful mis-decode has no fallback: it returns confident garbage that parses to nothing, so
`CI-PIN-008` went FAIL -> PASS on a workflow whose only change was one NUL byte. Detection is now
required to hold its stride across a sample of the head, which is what a forged four-byte prefix
cannot survive.

These tests exercise the primitive directly. The behaviour that actually matters to a user -- a
workflow saved as UTF-16 still failing CI-PIN-008 on its mutable pin -- is pinned in
`tests/application/test_an_encoding_is_not_a_hiding_place.py`.
"""

from __future__ import annotations

import pytest

from oss_policy_kit.infrastructure.source_text import decode_source

_SAMPLE = "name: ci\nsteps: [a]\n"


@pytest.mark.parametrize(
    "codec",
    ["utf-16", "utf-32", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be", "utf-8", "utf-8-sig"],
)
def test_every_encoding_yaml_permits_round_trips(codec: str) -> None:
    """YAML 1.2 requires UTF-8, UTF-16 and UTF-32 support, with or without a BOM."""

    assert decode_source(_SAMPLE.encode(codec)) == _SAMPLE


def test_utf_32_le_is_not_mistaken_for_utf_16_le() -> None:
    """`xx 00 00 00` opens the same way as UTF-16LE, so width must be decided before byte order.

    Getting this backwards does not raise -- it decodes, and yields garbage that no parser
    recognises, which is precisely the silent failure this whole repair is about.
    """

    assert decode_source(_SAMPLE.encode("utf-32-le")) == _SAMPLE


@pytest.mark.parametrize("data", [b"", b"a", b"\x00"], ids=["empty", "one-byte", "one-nul"])
def test_a_file_too_short_to_classify_is_still_read(data: bytes) -> None:
    """Two bytes are the minimum the pattern needs; below that there is nothing to deduce."""

    assert decode_source(data) == data.decode("utf-8", errors="replace")


def test_a_two_byte_file_is_classified_without_the_four_byte_pattern() -> None:
    """UTF-32 needs four bytes to identify; UTF-16 needs two, and a file may only have two.

    Without this the short-file path skips straight past UTF-16 classification, and a two- or
    three-byte wide file reads as mojibake -- rare, but it is the same silent-garbage failure at
    a smaller size, and the branch is either right or it is decoration.
    """

    assert decode_source(b"\x00a") == "a"


def test_a_file_that_only_looks_wide_falls_back_instead_of_failing() -> None:
    """The NUL pattern is strong evidence, not proof, and a wrong guess must cost nothing.

    An odd byte count cannot be valid UTF-16, so the detected codec raises. The old lossy read
    has to answer instead -- if the exception escaped, a file the previous release read would
    now crash the caller, which is the exact regression this primitive was rewritten twice to
    avoid.
    """

    malformed = b"\x00a\x00b\x00"

    assert decode_source(malformed) == malformed.decode("utf-8", errors="replace")


def test_a_lone_high_byte_is_still_replaced_rather_than_refused() -> None:
    """The cp1252 case the docstring cites: one bad byte must not cost the rest of the file."""

    assert decode_source(b"# revis\xe3o\nname: ci\n") == "# revis�o\nname: ci\n"


def test_line_endings_are_normalised_the_way_text_mode_did() -> None:
    """Callers used to read in text mode, which translates CRLF; decoding bytes does not.

    Skipping this cost twelve Terraform rules once, when a stray `\\r` made the HCL grammar
    reject a file it had always accepted.
    """

    assert decode_source("a\r\nb\rc\n".encode("utf-16")) == "a\nb\nc\n"


#: A workflow that really is UTF-8 and really does carry a mutable pin, with one NUL byte in
#: front of it. NUL is a valid UTF-8 character (U+0000), so this file is well-formed UTF-8 --
#: and its first two bytes are `00 6F`, which is exactly the pattern a UTF-16BE stream shows.
_UTF8_WITH_A_STRAY_NUL = b"\x00" + b"on: push\njobs:\n  a:\n    steps:\n      - uses: v/p@main\n"


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("nul-first", _UTF8_WITH_A_STRAY_NUL),
        ("nul-second", _UTF8_WITH_A_STRAY_NUL[1:2] + b"\x00" + _UTF8_WITH_A_STRAY_NUL[2:]),
        # Length parity decides whether the mis-guess raises or succeeds, and an attacker picks
        # it with one extra space. Both parities have to survive, or the test only pins the half
        # that happened to fail loudly.
        ("nul-first-odd-length", _UTF8_WITH_A_STRAY_NUL + b" "),
    ],
)
def test_a_stray_nul_does_not_turn_a_utf8_file_into_a_wide_one(label: str, data: bytes) -> None:
    """The half of "never read less" that a successful mis-decode defeats.

    A guess that FAILS falls back and costs nothing -- that is the case this module's docstring
    described. A guess that SUCCEEDS does not fall back: it returns confident garbage, the `uses:`
    key stops existing, and the control that reads it reports a repository with no mutable pins.
    Measured end to end before this test existed: `CI-PIN-008` went FAIL -> PASS, exit 0, with no
    diagnostic anywhere. Decoding is not allowed to be the thing that hides a finding.
    """

    text = decode_source(data)

    assert "uses:" in text, (
        f"{label}: a UTF-8 workflow was decoded as a wide encoding because of one NUL byte, and "
        f"its steps stopped existing. Decoded to {text[:40]!r}"
    )


#: Forged UTF-16BE prefixes of growing length. A window of any fixed size is defeated by writing
#: one byte more than the window: the check passes on what it sampled and the rest of the file --
#: ordinary UTF-8 carrying the mutable pin -- is decoded as wide and turns to mojibake.
#:
#: The first version of this test used four bytes only, and the fix it guarded sampled thirty-two.
#: An adversarial review wrote thirty-two and walked straight through. Measured through the real
#: Kubernetes scanner on a Pod with `privileged: true`: clean UTF-8 gave `files_scanned=1,
#: parse_errors=0, findings=9`; the same pod behind a 32-byte forged prefix gave `files_scanned=1,
#: parse_errors=0, findings=0` -- a declared clean scan, not an UNKNOWN.
_FORGED_PREFIX_BYTES = (4, 32, 64, 256)


@pytest.mark.parametrize("prefix_bytes", _FORGED_PREFIX_BYTES)
def test_a_forged_wide_prefix_does_not_buy_the_rest_of_the_file(prefix_bytes: int) -> None:
    """No prefix length may hand the rest of a UTF-8 file to a wide decoder.

    Parametrised rather than fixed because the defect is not "the window is too small" -- it is
    that a window exists at all. The stride now has to hold to the end of the file, so an attacker
    who keeps it has written UTF-16 and decoding it as UTF-16 is correct.
    """

    forged = ("# " + "a" * (prefix_bytes // 2 - 3) + "\n").encode("utf-16-be")
    payload = b"on: push\njobs:\n  a:\n    steps:\n      - uses: v/p@main\n"
    data = forged + payload

    assert "uses:" in decode_source(data), (
        f"a {prefix_bytes}-byte UTF-16 prefix was enough to have the rest of a UTF-8 file decoded "
        "as wide, and the step carrying the mutable pin stopped existing"
    )
