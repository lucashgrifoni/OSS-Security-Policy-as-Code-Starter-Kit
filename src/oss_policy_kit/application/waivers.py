"""Parse and validate versioned waiver files."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.domain.models import WaiverRecord, utc_today
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file


@dataclass(slots=True)
class WaiverParseOutcome:
    """Waiver file parse result."""

    by_control: dict[str, WaiverRecord]
    warnings: list[str]


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        return date.fromisoformat(value.strip()[:10])
    return None


def parse_waivers_file(path: Path) -> WaiverParseOutcome:
    """Load waivers from YAML. Invalid entries are skipped with warnings."""

    try:
        raw = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001
        raise LoadError(f"Failed to read waivers file {path}: {exc}") from exc

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
        if not isinstance(item, dict):
            warnings.append(f"Waiver entry {idx} ignored: not a mapping")
            continue
        cid = str(item.get("control_id", "")).strip()
        if not cid:
            warnings.append(f"Waiver entry {idx} ignored: missing control_id")
            continue
        justification = str(item.get("justification", "")).strip()
        if not justification:
            warnings.append(f"Waiver for {cid} ignored: empty justification")
            continue
        owner = str(item.get("owner", "")).strip()
        if not owner:
            warnings.append(f"Waiver for {cid} ignored: empty owner")
            continue
        status = str(item.get("status", "approved")).strip() or "approved"
        try:
            expires_at = _parse_date(item.get("expires_at"))
        except ValueError as exc:
            warnings.append(f"Waiver for {cid} ignored: invalid expires_at ({exc})")
            continue
        if expires_at is not None and expires_at < today:
            warnings.append(f"Waiver for {cid} ignored: expired at {expires_at.isoformat()}")
            continue
        applies = item.get("applies_to")
        applies_list: list[str] | None = None
        if isinstance(applies, list):
            applies_list = [str(x) for x in applies]
        elif isinstance(applies, str) and applies.strip():
            applies_list = [applies.strip()]

        by_control[cid] = WaiverRecord(
            control_id=cid,
            justification=justification,
            owner=owner,
            status=status,
            expires_at=expires_at,
            applies_to=applies_list,
        )

    return WaiverParseOutcome(by_control=by_control, warnings=warnings)
