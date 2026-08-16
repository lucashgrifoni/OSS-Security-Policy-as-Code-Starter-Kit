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
        # `errors="replace"`, deliberately: this is the read the scanners have always done, and
        # keeping it is what guarantees no input reads worse than it did before.
        decoded = data.decode("utf-8", errors="replace")
    return decoded.replace("\r\n", "\n").replace("\r", "\n")
