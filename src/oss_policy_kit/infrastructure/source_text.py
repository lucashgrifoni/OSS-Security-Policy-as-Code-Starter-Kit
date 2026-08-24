"""Decode a source file the way the format it is written in says it should be decoded.

The scanners used to read every file as UTF-8 with ``errors="replace"``. A file saved in
another encoding therefore became mojibake, the mojibake failed whatever "is this a
CloudFormation template / a Kubernetes manifest" check came next, and the file left through
the *nothing to see here* door -- so a repository whose only manifest declared
``privileged: true`` reported a clean scan.

The obvious repair -- read strictly, and record the file as unreadable -- was tried twice and
was worse than the bug both times, because **these files are not broken**:

* YAML 1.2 *requires* a processor to accept UTF-8, UTF-16 and UTF-32 with a BOM. A UTF-16
  ``pod.yaml`` is a valid manifest that ``kubectl apply`` would happily install.
* JSON parsers detect UTF-8/16/32 from the first bytes (RFC 4627 §3).
* Python honours a PEP 263 ``# -*- coding: latin-1 -*-`` line, so refusing such a module
  deleted a genuine ``acl="public-read"`` finding and turned ``--fail-on fail`` green.
* And a ``.yaml`` saved as cp1252 with one accented byte in a comment -- which any Windows
  editor will produce -- is 99% ASCII. The old lossy read turned that byte into U+FFFD and
  found the ``privileged: true`` underneath it; refusing the file found nothing.

So the rule is narrower than it first looks: **honour a BOM, and otherwise read exactly what
was read before.** The improvement is additive, never subtractive, which is the only shape
that cannot delete a finding. See ``decode_source`` for the invariant in full.
"""

from __future__ import annotations

import codecs
import contextlib

#: (BOM, codec). Longest first: the UTF-32-LE BOM starts with the UTF-16-LE BOM, so testing
#: the short one first would decode a UTF-32 file as UTF-16 and produce silent garbage.
_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def _codec_without_bom(data: bytes) -> str | None:
    """The wide encoding *data* is written in, deduced from where its NUL bytes fall, or ``None``.

    YAML 1.2 §5.2 and RFC 4627 §3 both specify this, and for the same reason: the first character
    of a YAML or JSON stream is always ASCII, so in a wide encoding the padding NULs land in
    positions that name the width and the byte order. ``name:`` begins ``6E 61`` in UTF-8,
    ``00 6E 00 61`` in UTF-16BE, ``6E 00 61 00`` in UTF-16LE.

    A BOM is not required by either spec and several tools do not write one, so recognising only
    the BOM left the commonest deliberate way to hide a line still working. UTF-32 is tested
    first: its little-endian pattern ``xx 00 00 00`` starts with the same two bytes as UTF-16LE,
    so testing the narrower one first would decode a UTF-32 file as UTF-16 and produce garbage.

    Returning ``None`` means "no wide encoding recognised", which is the ordinary UTF-8 case.
    """

    head = data[:4]
    if len(head) < 2:
        return None
    nul = tuple(byte == 0 for byte in head)
    candidate: str | None = None
    if len(head) == 4:
        if nul == (True, True, True, False):
            candidate = "utf-32-be"
        elif nul == (False, True, True, True):
            candidate = "utf-32-le"
    if candidate is None:
        if nul[:2] == (True, False):
            candidate = "utf-16-be"
        elif nul[:2] == (False, True):
            candidate = "utf-16-le"
    if candidate is None or not _stride_holds(data, candidate):
        return None
    return candidate


#: Where the padding NULs fall inside one code unit, per codec.
_WIDE_NUL_OFFSETS: dict[str, tuple[int, ...]] = {
    "utf-32-be": (0, 1, 2),
    "utf-32-le": (1, 2, 3),
    "utf-16-be": (0,),
    "utf-16-le": (1,),
}


def _stride_holds(data: bytes, codec: str) -> bool:
    """Whether *data* keeps *codec*'s NUL stride across the sampled head.

    Four bytes are not enough to name an encoding. ``NUL`` is a valid UTF-8 character, so a
    genuinely UTF-8 file carrying one at the front matches UTF-16's pattern exactly -- and whether
    the mis-guess then RAISES or SUCCEEDS is decided by the file's length parity, which anyone can
    set with a trailing space. On the succeeding parity there is no fallback and no error: the
    decode returns confident garbage, ``uses:`` stops existing, and the control reading it reports
    a repository with no mutable action pins. Measured: `CI-PIN-008` FAIL -> PASS, exit 0.

    So the pattern has to hold for the WHOLE FILE, not for a window. A window of any fixed size is
    defeated by writing one byte more than the window -- an adversarial review wrote thirty-two
    against a thirty-two byte sample and walked through. Measured through the Kubernetes scanner
    on a Pod with `privileged: true`: clean UTF-8 gave `files_scanned=1, parse_errors=0,
    findings=9`, and the same pod behind a forged prefix gave `files_scanned=1, parse_errors=0,
    findings=0` -- a declared clean scan of a privileged pod, which is worse than an error.

    Checked with strided slices so the cost is a memcpy rather than a Python loop, and paid only
    by files whose first bytes already match a wide pattern. An attacker who keeps the stride to
    the end of the file has written UTF-16, and decoding it as UTF-16 is then correct.

    LIMITATION, stated rather than hidden: a wide-encoded file containing any character outside
    Latin-1 loses the NUL at that position and is not recognised. It then reads exactly as it did
    before this detection existed, which is the one outcome this primitive is never allowed to be
    worse than.
    """

    width = 4 if codec.startswith("utf-32") else 2
    offsets = _WIDE_NUL_OFFSETS[codec]
    usable = len(data) // width * width
    if usable < width * 2:
        # A file holding a single code unit has no second unit to corroborate anything, and it
        # also has nothing to hide: no `uses:`, no key, no finding fits in one character. The
        # four-byte pattern stays sufficient there, which keeps the two-byte wide file reading as
        # the character it is rather than as mojibake. No length guard here: reaching this line
        # already means two bytes were seen for UTF-16 and four for UTF-32, so one would always
        # be true -- and a guard that cannot fail is one this project deletes rather than keeps.
        return True
    return not any(any(data[offset:usable:width]) for offset in offsets)


def decode_source(data: bytes) -> str:
    """Return *data* as text. Always. There is no failure mode here.

    **The invariant this function exists to keep: never read less than the previous release
    read.** It took three attempts to learn that, and two of them shipped a worse bug than the
    one being fixed.

    The scanners used to read UTF-8 with ``errors="replace"``. That is lossy, but it never
    loses a *file*: a manifest saved as cp1252 with one accented byte in a comment kept its
    structure, the one bad byte became U+FFFD, and the ``privileged: true`` inside it was still
    found. Replacing that with a strict read and an honest "could not read this" sounds more
    rigorous and is strictly worse -- it deletes findings a working scanner used to report, and
    a control that answers `manual-review-required` trips no `--fail-on fail`. Turning a red
    pipeline green is not a smaller mistake than a wrong verdict; it is a larger one.

    So the improvement is only ever additive:

    * a BOM is honoured, which is what fixes the original bug -- YAML 1.2 requires UTF-16 and
      UTF-32 support, and a UTF-16 ``pod.yaml`` is a manifest ``kubectl apply`` installs, not a
      broken file;
    * anything else falls back to exactly what the scanners did before.

    A file that genuinely holds no source is still handled -- as nothing parses out of it, the
    scanner records no findings, which is the same answer it always gave.

    Line endings are normalised the way Python's text mode does. Every caller used to read in
    text mode, which translates CRLF silently; decoding bytes does not, and on Windows -- where
    a checkout has CRLF unless told otherwise -- the stray ``\\r`` made the HCL grammar reject a
    file it had always accepted, and twelve Terraform rules stopped firing.
    """

    decoded: str | None = None
    for bom, codec in _BOMS:
        if data.startswith(bom):
            with contextlib.suppress(UnicodeDecodeError):
                decoded = data[len(bom) :].decode(codec)
            break
    if decoded is None:
        # Not named `codec`: the BOM loop above already binds that name in this scope.
        deduced = _codec_without_bom(data)
        if deduced is not None:
            # Suppressed rather than trusted: the byte pattern is strong evidence, not proof, and
            # a file that matches it without being valid in that codec must still read exactly as
            # well as it did before. Detection can only ever add a successful decode here.
            with contextlib.suppress(UnicodeDecodeError):
                decoded = data.decode(deduced)
    if decoded is None:
        # `errors="replace"`, deliberately: this is the read the scanners have always done, and
        # keeping it is what guarantees no input reads worse than it did before.
        decoded = data.decode("utf-8", errors="replace")
    return decoded.replace("\r\n", "\n").replace("\r", "\n")
