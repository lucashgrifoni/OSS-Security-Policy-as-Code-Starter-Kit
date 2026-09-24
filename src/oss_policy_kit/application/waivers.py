"""Parse and validate versioned waiver files."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from oss_policy_kit.application.input_limits import bad_input_detail, is_bad_input
from oss_policy_kit.application.vuln_waivers import (
    ACTIVE_WAIVER_STATUSES,
    DEFAULT_WAIVER_STATUS,
    expiry_date_from_text,
    iso_date_prefix,
    pinned_expiry_clock_note,
)
from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.domain.models import WaiverRecord, utc_today
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

_EXPECTED_STATUSES = ", ".join(sorted(ACTIVE_WAIVER_STATUSES))


@dataclass(slots=True)
class WaiverParseOutcome:
    """Waiver file parse result."""

    by_control: dict[str, WaiverRecord]
    warnings: list[str]


def _parse_date(value: Any) -> date | None:
    """Coerce a waiver expiry to a date; raise ``ValueError`` when the text is not one.

    A string must parse WHOLE (see :func:`vuln_waivers.expiry_date_from_text`). This
    used to read ``value[:10]``, so ``"2099-01-01-NOT-A-DATE"`` silently became
    2099-01-01 and the waiver kept suppressing its control with nothing on screen.
    """

    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        text = value.strip()
        parsed = expiry_date_from_text(text)
        if parsed is not None:
            return parsed
        prefix = iso_date_prefix(text)
        if prefix is not None:
            raise ValueError(
                f"trailing text after {prefix.isoformat()} in {value!r}; "
                'use exactly "YYYY-MM-DD" (the text after the date is not dropped silently)'
            )
        raise ValueError(f"not an ISO-8601 date: {value!r}")
    return None


def parse_waivers_file(path: Path) -> WaiverParseOutcome:  # noqa: C901
    """Load waivers from YAML. Invalid entries are skipped with warnings."""

    try:
        raw = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001
        # In the words the rest of the CLI uses for a bad input. `str(exc)` put Python's
        # "maximum recursion depth exceeded" in front of an operator whose waivers file was
        # nested 600 levels deep, and an OSError's text repeats the path already printed.
        reason = bad_input_detail(exc) if is_bad_input(exc) else str(exc)
        raise LoadError(f"Failed to read waivers file {path}: {reason}") from exc

    warnings: list[str] = []
    by_control: dict[str, WaiverRecord] = {}

    if not isinstance(raw, dict):
        raise LoadError("Waivers file root must be a mapping")

    entries = raw.get("waivers")
    if entries is None:
        warnings.append("No 'waivers' list found; nothing applied.")
        return WaiverParseOutcome(by_control=by_control, warnings=warnings)
    if not isinstance(entries, list):
        raise LoadError("'waivers' must be a list")

    today = utc_today()

    for idx, item in enumerate(entries):
        record = _parse_waiver_record(idx, item, today, warnings)
        if record is not None:
            by_control[record.control_id] = record

    return WaiverParseOutcome(by_control=by_control, warnings=warnings)


def _waiver_applies_to(applies: object) -> list[str] | None:
    """Normalize a waiver ``applies_to`` value (list or single string) to a list, or None."""

    if isinstance(applies, list):
        return [str(x) for x in applies]
    if isinstance(applies, str) and applies.strip():
        return [applies.strip()]
    return None


def _waiver_status(cid: str, item: dict[str, Any], warnings: list[str]) -> str | None:
    """Return the normalized active status, or None (with a warning) when it must not waive.

    Keeps the documented ``approved`` default only when ``status`` is absent; a
    pending, rejected or revoked waiver is dropped here so the operator sees why,
    instead of it reaching the engine as a record that silently never applies.
    """

    if "status" not in item:
        return DEFAULT_WAIVER_STATUS
    raw = item["status"]
    if not isinstance(raw, str):
        warnings.append(
            f"Waiver for {cid} ignored: status={raw!r} is not a status word (expected one of {_EXPECTED_STATUSES})."
        )
        return None
    status = raw.strip().lower()
    if status not in ACTIVE_WAIVER_STATUSES:
        warnings.append(
            f"Waiver for {cid} ignored: status={raw!r} does not authorize a waiver "
            f"(expected one of {_EXPECTED_STATUSES})."
        )
        return None
    return status


def _waiver_expiry(cid: str, item: dict[str, Any], warnings: list[str]) -> tuple[date | None, bool]:
    """Return ``(expires_at, ok)`` for the canonical ``expires_at`` / legacy ``expires_on`` key.

    Only an absent (or explicitly null) value means "no expiry". A present value
    that is not a date or a date string — an integer, or the boolean YAML produces
    for an unquoted ``yes``/``no`` — is a typo; reading it as "never expires" would
    silently turn an expired waiver into a permanent one.
    """

    value = item.get("expires_at") if "expires_at" in item else item.get("expires_on")
    if value is not None and not isinstance(value, (str, date)):
        warnings.append(
            f"Waiver for {cid} ignored: expires_at={value!r} is not a date; "
            'quote it as "YYYY-MM-DD" (a malformed expiry is never read as "no expiry").'
        )
        return None, False
    try:
        return _parse_date(value), True
    except ValueError as exc:
        warnings.append(f"Waiver for {cid} ignored: invalid expires_at ({exc})")
        return None, False


def _parse_waiver_record(idx: int, item: object, today: date, warnings: list[str]) -> WaiverRecord | None:
    """Parse one waiver entry into a :class:`WaiverRecord`, or None (with a warning) when invalid."""

    if not isinstance(item, dict):
        warnings.append(f"Waiver entry {idx} ignored: not a mapping")
        return None
    cid = str(item.get("control_id", "")).strip()
    if not cid:
        vuln_ids = item.get("vulnerability_ids")
        if isinstance(vuln_ids, list) and vuln_ids:
            # Informational, not an error: vulnerability_ids-keyed entries are
            # consumed by emit-vex and correlate-findings, never the control gate.
            warnings.append(
                f"Waiver entry {idx} targets vulnerability_ids (handled by emit-vex / "
                "correlate-findings); not a control-gate waiver."
            )
        else:
            warnings.append(f"Waiver entry {idx} ignored: missing control_id")
        return None
    # Accept both the canonical ``justification`` key and the legacy ``reason``
    # spelling that the scaffolded stub/docs historically documented (v9.0.2).
    justification = str(item.get("justification") or item.get("reason") or "").strip()
    if not justification:
        warnings.append(f"Waiver for {cid} ignored: empty justification")
        return None
    owner = str(item.get("owner", "")).strip()
    if not owner:
        warnings.append(f"Waiver for {cid} ignored: empty owner")
        return None
    status = _waiver_status(cid, item, warnings)
    if status is None:
        return None
    expires_at, ok = _waiver_expiry(cid, item, warnings)
    if not ok:
        return None
    if expires_at is not None and expires_at < today:
        warnings.append(f"Waiver for {cid} ignored: expired at {expires_at.isoformat()}")
        return None
    note = pinned_expiry_clock_note(expires_at, today)
    if note is not None:
        warnings.append(f"Waiver for {cid} still applies, but {note}")
    return WaiverRecord(
        control_id=cid,
        justification=justification,
        owner=owner,
        status=status,
        expires_at=expires_at,
        applies_to=_waiver_applies_to(item.get("applies_to")),
    )
