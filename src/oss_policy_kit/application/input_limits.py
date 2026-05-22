"""Size caps for user-controlled SARIF / evidence / scorecard / waiver inputs.

Local CI denial-of-service hardening (backlog: v6 input size limits). Several
loaders read an entire user-controlled file before parsing; an oversized file in
an adopter repository can inflate memory use or slow CI. Impact is local to the
evaluator/CLI process (not RCE), so the response is a clear refusal:

- Evaluator paths return ``(None, reason, ...)`` so the control degrades to
  ``manual-review-required`` / ``not-evaluated`` instead of crashing.
- CLI paths raise :class:`InvalidInputError` (exit 2) via ``read_text_capped``.

Defaults are deliberately generous (real SARIF can be large; evidence files are
small attestations). There is no override flag yet — add one only when a concrete
adopter use case appears (per the backlog acceptance criteria).
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.domain.errors import InvalidInputError

#: Evidence/scorecard/waiver JSON or YAML — small attestations.
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024  # 5 MiB
#: SARIF documents (scanner output) — can be larger than evidence files.
MAX_SARIF_BYTES = 20 * 1024 * 1024  # 20 MiB


def _file_size(path: Path) -> int | None:
    """Return file size in bytes, or None when it cannot be stat-ed."""
    try:
        return path.stat().st_size
    except OSError:
        return None


def oversize_reason(path: Path, max_bytes: int, *, label: str) -> str | None:
    """Return a human-readable refusal message if *path* exceeds *max_bytes*, else None.

    No file content is read. Use this at evaluator boundaries that must not raise.
    """
    size = _file_size(path)
    if size is None or size <= max_bytes:
        return None
    return (
        f"{label} file '{path.name}' is {size} bytes, exceeding the "
        f"{max_bytes}-byte limit; refusing to read it to avoid local CI "
        "memory/time exhaustion. Reduce the file or split the input."
    )


def read_text_capped(
    path: Path,
    max_bytes: int,
    *,
    label: str,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> str:
    """Read *path* as text, but refuse files larger than *max_bytes*.

    Raises :class:`InvalidInputError` (CLI exit 2) when the file is oversized.
    """
    reason = oversize_reason(path, max_bytes, label=label)
    if reason is not None:
        raise InvalidInputError(reason)
    return path.read_text(encoding=encoding, errors=errors)
