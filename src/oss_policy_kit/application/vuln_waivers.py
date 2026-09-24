"""Vulnerability-keyed waiver parsing shared by emit-vex and correlate-findings (A-S7).

Hoisted verbatim from ``cli/emit_vex.py`` (v10.0.0) so both surfaces read the
same ``waivers/waivers.yaml`` entries that carry a ``vulnerability_ids: [...]``
field. Distinct from the control-keyed :class:`WaiverRecord` path that steers
the ``evaluate`` gate — a vulnerability-keyed waiver NEVER changes any control
state, ``summary_by_status``, or ``results_digest`` (fence FT-3): its effect is
confined to the VEX document, the findings/1.0 waiver blocks, and the
findings-surface ``--fail-on-*`` gates.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from oss_policy_kit.application.input_limits import path_free_error_text
from oss_policy_kit.domain.models import utc_today
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

#: Waiver statuses that actually authorize suppression. Mirrors the control-gate
#: set in ``application.engine._apply_waiver``: a waiver that is pending, rejected,
#: revoked, withdrawn — or simply misspelled — was never granted, so it must not
#: suppress a finding or exempt it from the findings-surface ``--fail-on-*`` gates.
ACTIVE_WAIVER_STATUSES: frozenset[str] = frozenset({"approved", "active"})

#: Applied only when a waiver entry omits ``status`` entirely (documented default).
DEFAULT_WAIVER_STATUS = "approved"

_EXPECTED_STATUSES = ", ".join(sorted(ACTIVE_WAIVER_STATUSES))

#: The canonical expiry key, then the legacy spelling. ``expires_on`` is accepted
#: exactly as the control-gate loader accepts it (``application.waivers._waiver_expiry``,
#: v9.0.2) because the kit's own remediation text and docs teach that spelling —
#: reading only ``expires_at`` here silently turned every documented waiver into a
#: waiver that never expires. Canonical wins when both are present and agree.
EXPIRY_KEYS: tuple[str, ...] = ("expires_at", "expires_on")

_EXPECTED_EXPIRY_KEYS = " or ".join(f'"{key}"' for key in EXPIRY_KEYS)

#: Near-miss spellings that unambiguously mean "expiry" without being one of
#: :data:`EXPIRY_KEYS`. Anything normalizing to an ``expir`` prefix (``expiry``,
#: ``expiration_date``, ``Expires-At``) is caught by the prefix rule; these are the
#: non-``expir`` phrasings worth naming. Such a key must never be read as "no
#: expiry" — that silent default is how this fail-open class keeps recurring.
_EXPIRY_LOOKALIKES: frozenset[str] = frozenset({"validuntil", "validthrough", "validto"})

#: CycloneDX 1.6 allowed enum values for analysis.justification.
CDX_JUSTIFICATIONS: frozenset[str] = frozenset(
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compensating_control",
        "inline_mitigations_already_exist",
    }
)


@dataclass(frozen=True, slots=True)
class VulnWaiver:
    """Per-vulnerability waiver entry from waivers/waivers.yaml.

    Distinct from the kit's main ``WaiverRecord`` (which is keyed by
    ``control_id``). Extending this shape never touches the evaluation engine.
    """

    justification_text: str
    owner: str
    status: str  # always an ACTIVE_WAIVER_STATUSES value: non-active entries never become a record
    expires_at: date | None
    cdx_justification: str | None  # one of CDX_JUSTIFICATIONS or None


def _looks_like_expiry_key(key: object) -> bool:
    """True for a key that means "expiry" but is not one of :data:`EXPIRY_KEYS`."""

    if not isinstance(key, str):
        return False
    normalized = "".join(ch for ch in key.lower() if ch.isalnum())
    return normalized.startswith("expir") or normalized in _EXPIRY_LOOKALIKES


def _unrecognised_expiry_keys(item: dict[str, Any]) -> list[str]:
    """Expiry-shaped keys the loader does not read (``expiry``, ``Expires-At``, ``valid_until``)."""

    return sorted(key for key in item if key not in EXPIRY_KEYS and _looks_like_expiry_key(key))


def expiry_date_from_text(text: str) -> date | None:
    """Parse a whole expiry string as a date; None when the value is not one.

    Accepts a plain ISO-8601 date (``2099-12-31``, or the basic ``20991231``) and a
    full ISO-8601 timestamp (``2099-12-31T00:00:00Z`` — the spelling the tutorial
    teaches, and what YAML hands back as a string when the value is quoted), and
    nothing else: **the whole value must be consumed**.

    Both loaders used to parse ``text[:10]``, so everything after a valid date
    prefix was thrown away without a word: ``"2099-01-01-NOT-A-DATE"`` and
    ``"2099-01-01 please ignore"`` both became 2099-01-01. That is fail-open in the
    common case — the junk is usually a note ("2026-01-01 pending re-review") or a
    second date, and the operator has no way to tell the value was not read whole.
    """

    try:
        return date.fromisoformat(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        return None


def iso_date_prefix(text: str) -> date | None:
    """The ``YYYY-MM-DD`` the value STARTS with, when the rest of it is junk.

    Only used to phrase the rejection: telling the operator which date was found
    is what turns "unparseable" into an edit they can make.
    """

    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def _pinned_today() -> date | None:
    """The date ``SOURCE_DATE_EPOCH`` pins the kit to, or None when it changes nothing.

    None means the pinned clock cannot have altered an expiry decision: either the
    variable is unset, or it resolves to the current date anyway.
    """

    if not os.environ.get("SOURCE_DATE_EPOCH"):
        return None
    pinned = utc_today()
    return pinned if pinned != datetime.now(UTC).date() else None


def _real_today() -> date:
    """The wall-clock date, deliberately NOT honouring ``SOURCE_DATE_EPOCH``.

    The only place in the kit that reads the unpinned clock, and it reads it to answer
    one question: is this waiver dead in reality? Every outcome-affecting read goes
    through :func:`domain.models.utc_now` and stays pinned, which is what keeps artifacts
    reproducible; this one exists so a pinned clock cannot disarm a gate *silently*.

    It is a named function rather than an inline ``datetime.now`` so a test can pin it.
    The suite pins ``SOURCE_DATE_EPOCH`` and forbids tests from reading the wall clock
    (``tests/test_suite_clock_hygiene.py``), so without this seam the "pinned to the real
    date" case could not be expressed at all.
    """

    return datetime.now(UTC).date()


def pinned_expiry_clock_note(expires_at: date | None, today: date) -> str | None:
    """Warn when the pinned clock — and only the pinned clock — kept a waiver alive.

    ``SOURCE_DATE_EPOCH`` deliberately drives every outcome-affecting clock read
    (:func:`domain.models.utc_now`): that is what makes an artifact reproducible and
    the test suite calendar-immune, and moving expiry off it would resurrect the
    date-rot class v9.0.3 killed. So the expiry comparison stays on the pinned
    clock — but a pinned clock must never DISARM a gate silently. With
    ``SOURCE_DATE_EPOCH`` set to a date before the expiry, a waiver that lapsed in
    2020 applies again: exit 0 instead of 1, and ``"state": "not_affected"`` in the
    VEX document. Returns the note to attach in exactly that case (the waiver is
    live against the pinned date and dead against the real one), else None.

    The real date is deliberately kept out of the text so the artifact stays
    byte-identical from one day to the next once the waiver has lapsed.
    """

    if expires_at is None:
        return None
    pinned = _pinned_today()
    if pinned is None or today != pinned:
        return None  # this comparison did not use the pinned clock
    if expires_at < today:
        # Dead against the pinned clock too, so the pin kept nothing alive -- the waiver
        # is simply expired and the caller already dropped it. Reachable only through the
        # public helper, but a note claiming SOURCE_DATE_EPOCH disarmed a gate that was
        # never armed would send the reader to unset a variable that changes nothing.
        return None
    if expires_at >= _real_today():
        return None  # live on both clocks; nothing was disarmed
    return (
        f"it expired at {expires_at.isoformat()} and still applies only because SOURCE_DATE_EPOCH "
        f"pins the evaluation date to {pinned.isoformat()}; unset SOURCE_DATE_EPOCH to enforce the expiry."
    )


def parse_waiver_expiry(idx: int, item: dict[str, Any], today: date, warnings: list[str]) -> tuple[date | None, bool]:
    """Return ``(expires_at, ok)``; ``ok`` is False when the entry should be skipped (bad/expired).

    Reads the canonical ``expires_at`` and the legacy ``expires_on`` alias, so a
    waiver written the way the kit's own remediation text and docs teach actually
    expires (before v10.0.7 ``expires_on`` was ignored, which meant *never
    expires* — an expired entry still produced ``"state": "not_affected"``).

    Only an absent (or explicitly null) expiry means "no expiry". Everything else
    fails the entry closed with a visible reason: a value that is present but not
    a date (an integer, a float, or the boolean YAML produces for an unquoted
    ``yes``/``no``), two expiry keys that disagree, or an expiry-shaped key the
    loader does not read. Reading any of those as "never expires" would silently
    turn an expired waiver into a permanent one.
    """

    stray = _unrecognised_expiry_keys(item)
    if stray:
        names = ", ".join(repr(key) for key in stray)
        warnings.append(
            f"Waiver entry {idx} ignored: unrecognised expiry field(s) {names}; "
            f'use {_EXPECTED_EXPIRY_KEYS} (an unrecognised expiry key is never read as "no expiry").'
        )
        return None, False

    present = [key for key in EXPIRY_KEYS if key in item and item[key] is not None]
    if not present:
        return None, True

    parsed: dict[str, date] = {}
    for key in present:
        value = _expiry_from_value(idx, key, item[key], warnings)
        if value is None:
            return None, False
        parsed[key] = value

    if len(set(parsed.values())) > 1:
        detail = ", ".join(f"{key}={value.isoformat()}" for key, value in parsed.items())
        warnings.append(
            f"Waiver entry {idx} ignored: expiry fields disagree ({detail}); "
            "keep exactly one so the effective expiry is unambiguous."
        )
        return None, False

    expires_at = parsed[present[0]]
    if expires_at < today:
        warnings.append(f"Waiver entry {idx} ignored: expired at {expires_at.isoformat()}.")
        return None, False
    note = pinned_expiry_clock_note(expires_at, today)
    if note is not None:
        warnings.append(f"Waiver entry {idx} still applies, but {note}")
    return expires_at, True


def _expiry_from_value(idx: int, key: str, raw: Any, warnings: list[str]) -> date | None:
    """Coerce one expiry value to a date; None (with a warning) when it is not a date."""

    if isinstance(raw, str):
        return _expiry_from_text(idx, key, raw, warnings)
    if isinstance(raw, datetime):
        return raw.date()
    if isinstance(raw, date):
        return raw
    warnings.append(
        f"Waiver entry {idx} ignored: {key}={raw!r} is not a date; "
        'quote it as "YYYY-MM-DD" (a malformed expiry is never read as "no expiry").'
    )
    return None


def _expiry_from_text(idx: int, key: str, raw: str, warnings: list[str]) -> date | None:
    """Parse a textual expiry; None (with a warning) when it is blank or unparseable.

    The value must parse whole. A date followed by anything else is rejected with the
    date it found named, because the trailing text is exactly where the operator's
    real intent hides — and dropping it silently is how an entry that reads
    ``"2026-01-01 renewed to 2030"`` became a waiver nobody re-checked.
    """

    text = raw.strip()
    if not text:
        warnings.append(f"Waiver entry {idx} ignored: {key} is blank; use a date or drop the field.")
        return None
    parsed = expiry_date_from_text(text)
    if parsed is not None:
        return parsed
    prefix = iso_date_prefix(text)
    if prefix is not None:
        warnings.append(
            f"Waiver entry {idx} ignored: {key}={raw!r} has trailing text after {prefix.isoformat()}; "
            'use exactly "YYYY-MM-DD" (the text after the date is not dropped silently).'
        )
        return None
    warnings.append(f"Waiver entry {idx} has unparseable {key}={raw!r}; ignored.")
    return None


def parse_waiver_status(idx: int, item: dict[str, Any], warnings: list[str]) -> str | None:
    """Return the normalized active status, or None when the entry must not waive.

    An omitted ``status`` keeps the documented ``approved`` default; a status that
    is present must be explicitly active, so pending / rejected / revoked — and
    anything unrecognised — fails closed with a visible reason.
    """

    if "status" not in item:
        return DEFAULT_WAIVER_STATUS
    raw = item["status"]
    if not isinstance(raw, str):
        warnings.append(
            f"Waiver entry {idx} ignored: status={raw!r} is not a status word (expected one of {_EXPECTED_STATUSES})."
        )
        return None
    status = raw.strip().lower()
    if status not in ACTIVE_WAIVER_STATUSES:
        warnings.append(
            f"Waiver entry {idx} ignored: status={raw!r} does not authorize a waiver "
            f"(expected one of {_EXPECTED_STATUSES})."
        )
        return None
    return status


def parse_cdx_justification(idx: int, item: dict[str, Any], warnings: list[str]) -> str | None:
    """Validate the optional CycloneDX VEX justification enum value."""

    cdx_just = item.get("vex_justification")
    if not isinstance(cdx_just, str):
        return None
    cdx_just = cdx_just.strip()
    if cdx_just not in CDX_JUSTIFICATIONS:
        warnings.append(
            f"Waiver entry {idx} has vex_justification={cdx_just!r} not in CycloneDX enum; field will be omitted."
        )
        return None
    return cdx_just


def parse_vuln_waiver_entry(
    idx: int, item: Any, today: date, warnings: list[str]
) -> tuple[list[Any], VulnWaiver] | None:
    """Parse one waiver entry into ``(vulnerability_ids, record)`` or None when it should be skipped."""

    if not isinstance(item, dict):
        return None
    vuln_ids = item.get("vulnerability_ids")
    if not isinstance(vuln_ids, list) or not vuln_ids:
        return None  # control-id-only waiver — not our concern here
    justification = str(item.get("justification", "")).strip()
    if not justification:
        warnings.append(f"Waiver entry {idx} ignored: empty justification.")
        return None
    owner = str(item.get("owner", "")).strip()
    if not owner:
        warnings.append(f"Waiver entry {idx} ignored: empty owner.")
        return None
    status = parse_waiver_status(idx, item, warnings)
    if status is None:
        return None
    expires_at, ok = parse_waiver_expiry(idx, item, today, warnings)
    if not ok:
        return None
    record = VulnWaiver(
        justification_text=justification,
        owner=owner,
        status=status,
        expires_at=expires_at,
        cdx_justification=parse_cdx_justification(idx, item, warnings),
    )
    return vuln_ids, record


def load_vuln_waivers(path: Path) -> tuple[dict[str, VulnWaiver], list[str]]:
    """Return (vulnerability_id → waiver, warnings).

    Reads ``waivers/waivers.yaml`` (or the supplied path) and collects only
    entries that carry a ``vulnerability_ids: [...]`` field. Entries that key
    on ``control_id`` alone are ignored — they steer the evaluation gate, not
    the VEX document or the findings surface.
    """

    warnings: list[str] = []
    if not path.is_file():
        return {}, warnings
    try:
        raw = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001
        # basename only: the warning lands verbatim in the shareable findings/1.0
        # extensions.waiver_warnings; never leak the absolute path / username (M-002).
        # The basename alone did not keep that promise: an OSError's own text ends with
        # the path it opened, which correlate-findings resolves under --target first.
        warnings.append(f"Could not read waivers file {path.name}: {path_free_error_text(exc)}")
        return {}, warnings
    if not isinstance(raw, dict):
        warnings.append(f"Waivers file {path.name} is not a YAML mapping; ignoring.")
        return {}, warnings
    entries = raw.get("waivers")
    if not isinstance(entries, list):
        if "waivers" in raw:
            warnings.append(f"Waivers file {path.name} 'waivers' is not a list; ignored.")
        return {}, warnings
    today = utc_today()
    out: dict[str, VulnWaiver] = {}
    for idx, item in enumerate(entries):
        parsed = parse_vuln_waiver_entry(idx, item, today, warnings)
        if parsed is None:
            continue
        vuln_ids, record = parsed
        for v in vuln_ids:
            if isinstance(v, str) and v.strip():
                out[v.strip()] = record
    return out, warnings
