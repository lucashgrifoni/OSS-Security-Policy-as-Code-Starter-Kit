"""Diff two kit catalogs — control + profile delta between versions (T1.4).

Single source of truth for the ``diff-catalogs`` CLI command. Loads two kit
*snapshots* and computes the added / removed / changed controls and profiles
between them, so an adopter can see exactly what a kit upgrade changes (for
example the v7.3.0 -> v8.0.0 control additions and the applicability default).

A *snapshot* is either a bundled-shaped data directory (``controls/catalog.yaml``
plus ``profiles/<id>/profile.yaml``) or a bare ``catalog.yaml`` file for a
controls-only diff. Profiles are read directly from YAML (not through the strict
profile loader) so the tool stays robust against historical snapshots that may
reference controls removed in a later major.

Read-only and generated: it never executes anything from either snapshot and
changes no ``evaluate`` verdict — it only explains what changed.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES, bad_input_detail, load_capped_document
from oss_policy_kit.application.loader import ControlSpec, load_catalog
from oss_policy_kit.domain.errors import InvalidInputError, LoadError

#: Scalar control fields compared to decide a control "changed", in display order.
_COMPARED_FIELDS: tuple[str, ...] = (
    "title",
    "category",
    "automation",
    "lifecycle",
    "assurance",
    "weight",
)


@dataclasses.dataclass(frozen=True)
class CatalogSnapshot:
    """One side of a diff: the controls (and, when present, profiles) of a kit."""

    label: str
    controls: dict[str, ControlSpec]
    profiles: dict[str, tuple[str, ...]]
    #: True when a ``profiles/`` directory was present; lets the diff distinguish
    #: "no profiles to compare" (a bare catalog.yaml) from "profiles all removed".
    has_profiles: bool


@dataclasses.dataclass(frozen=True)
class FieldChange:
    """A single changed scalar field on a control that exists on both sides."""

    field: str
    old: str
    new: str


@dataclasses.dataclass(frozen=True)
class ControlRef:
    """A control identified for the added/removed lists (id + human title)."""

    id: str
    title: str


@dataclasses.dataclass(frozen=True)
class ControlChange:
    """A control present on both sides whose metadata changed."""

    id: str
    title: str
    changes: tuple[FieldChange, ...]


@dataclasses.dataclass(frozen=True)
class ProfileChange:
    """A profile present on both sides whose control membership changed."""

    id: str
    added: tuple[str, ...]
    removed: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class CatalogDiff:
    """The computed delta between two snapshots (old -> new)."""

    from_label: str
    to_label: str
    profiles_compared: bool
    added_controls: tuple[ControlRef, ...]
    removed_controls: tuple[ControlRef, ...]
    changed_controls: tuple[ControlChange, ...]
    added_profiles: tuple[str, ...]
    removed_profiles: tuple[str, ...]
    changed_profiles: tuple[ProfileChange, ...]

    @property
    def is_empty(self) -> bool:
        return not (
            self.added_controls
            or self.removed_controls
            or self.changed_controls
            or self.added_profiles
            or self.removed_profiles
            or self.changed_profiles
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_label,
            "to": self.to_label,
            "profiles_compared": self.profiles_compared,
            "controls": {
                "added": [{"id": r.id, "title": r.title} for r in self.added_controls],
                "removed": [{"id": r.id, "title": r.title} for r in self.removed_controls],
                "changed": [
                    {
                        "id": c.id,
                        "title": c.title,
                        "changes": [{"field": f.field, "old": f.old, "new": f.new} for f in c.changes],
                    }
                    for c in self.changed_controls
                ],
            },
            "profiles": {
                "added": list(self.added_profiles),
                "removed": list(self.removed_profiles),
                "changed": [
                    {"id": p.id, "added": list(p.added), "removed": list(p.removed)} for p in self.changed_profiles
                ],
            },
        }


def _load_profiles(profiles_dir: Path) -> dict[str, tuple[str, ...]]:
    """Read ``profiles/<id>/profile.yaml`` membership directly (id -> control ids).

    Bypasses the strict profile loader on purpose: a diff must tolerate historical
    snapshots whose profiles reference controls removed in a later major.
    """

    out: dict[str, tuple[str, ...]] = {}
    for child in sorted(profiles_dir.iterdir()):
        profile_file = child / "profile.yaml"
        if not profile_file.is_file():
            continue
        # A snapshot is user-supplied: `--from` can point at any directory on disk, so
        # this file is as untrusted as any other input. Catching only OSError/YAMLError
        # let a RecursionError from a deeply nested profile escape as exit 3, and left
        # the read uncapped. `load_capped_document` is the same one defensive read the
        # scorecard, config and Insights readers use, so the refusal, the budget and the
        # wording are identical here -- and it names the file without its directory,
        # which the old message leaked (M-002).
        try:
            raw = load_capped_document(profile_file, MAX_EVIDENCE_BYTES, label="Profile")
        except InvalidInputError as exc:
            raise LoadError(str(exc)) from exc
        if not isinstance(raw, dict):
            continue
        pid = str(raw.get("id", "")).strip() or child.name
        controls = raw.get("controls") or []
        ids = tuple(str(c).strip() for c in controls if str(c).strip())
        out[pid] = ids
    return out


def load_snapshot(path: Path, *, label: str) -> CatalogSnapshot:
    """Load a snapshot from a kit data dir or a bare ``catalog.yaml`` file.

    Raises :class:`InvalidInputError` when the path is missing or has no catalog,
    and :class:`LoadError` when the catalog/profile files are malformed.
    """

    try:
        resolved = path.expanduser().resolve()
    except OSError as exc:  # pragma: no cover - resolve rarely raises here
        raise InvalidInputError(f"Invalid {label} path {path}: {bad_input_detail(exc)}") from exc
    if resolved.is_dir():
        catalog_path = resolved / "controls" / "catalog.yaml"
        profiles_dir = resolved / "profiles"
    elif resolved.is_file():
        catalog_path = resolved
        # A catalog.yaml inside a data dir has a sibling ``profiles/`` two levels up.
        profiles_dir = resolved.parent.parent / "profiles"
    else:
        raise InvalidInputError(f"{label} path does not exist: {resolved}")
    if not catalog_path.is_file():
        raise InvalidInputError(
            f"No control catalog found for {label} at {catalog_path}. Point --from/--to at a kit "
            "data directory (containing controls/catalog.yaml) or directly at a catalog.yaml file."
        )
    controls = load_catalog(catalog_path)
    has_profiles = profiles_dir.is_dir()
    profiles = _load_profiles(profiles_dir) if has_profiles else {}
    return CatalogSnapshot(label=label, controls=controls, profiles=profiles, has_profiles=has_profiles)


def diff_catalogs(old: CatalogSnapshot, new: CatalogSnapshot) -> CatalogDiff:
    """Compute the old -> new delta of controls and (when both sides have them) profiles."""

    old_ids = set(old.controls)
    new_ids = set(new.controls)
    added = tuple(ControlRef(cid, new.controls[cid].title) for cid in sorted(new_ids - old_ids))
    removed = tuple(ControlRef(cid, old.controls[cid].title) for cid in sorted(old_ids - new_ids))

    changed: list[ControlChange] = []
    for cid in sorted(old_ids & new_ids):
        old_spec = old.controls[cid]
        new_spec = new.controls[cid]
        field_changes = tuple(
            FieldChange(field=field, old=str(getattr(old_spec, field)), new=str(getattr(new_spec, field)))
            for field in _COMPARED_FIELDS
            if getattr(old_spec, field) != getattr(new_spec, field)
        )
        if field_changes:
            changed.append(ControlChange(id=cid, title=new_spec.title, changes=field_changes))

    profiles_compared = old.has_profiles and new.has_profiles
    added_profiles: tuple[str, ...] = ()
    removed_profiles: tuple[str, ...] = ()
    changed_profiles: list[ProfileChange] = []
    if profiles_compared:
        old_profiles = set(old.profiles)
        new_profiles = set(new.profiles)
        added_profiles = tuple(sorted(new_profiles - old_profiles))
        removed_profiles = tuple(sorted(old_profiles - new_profiles))
        for pid in sorted(old_profiles & new_profiles):
            before = set(old.profiles[pid])
            after = set(new.profiles[pid])
            p_added = tuple(sorted(after - before))
            p_removed = tuple(sorted(before - after))
            if p_added or p_removed:
                changed_profiles.append(ProfileChange(id=pid, added=p_added, removed=p_removed))

    return CatalogDiff(
        from_label=old.label,
        to_label=new.label,
        profiles_compared=profiles_compared,
        added_controls=added,
        removed_controls=removed,
        changed_controls=tuple(changed),
        added_profiles=added_profiles,
        removed_profiles=removed_profiles,
        changed_profiles=tuple(changed_profiles),
    )


def _control_lines(diff: CatalogDiff) -> list[str]:
    """The control section: one counts header, then one line per added/removed/changed control."""

    lines = [
        f"Controls: +{len(diff.added_controls)} added, "
        f"-{len(diff.removed_controls)} removed, "
        f"~{len(diff.changed_controls)} changed"
    ]
    lines.extend(f"  + {ref.id}  {ref.title}" for ref in diff.added_controls)
    lines.extend(f"  - {ref.id}  {ref.title}" for ref in diff.removed_controls)
    for change in diff.changed_controls:
        deltas = "; ".join(f"{c.field}: {c.old} -> {c.new}" for c in change.changes)
        lines.append(f"  ~ {change.id}  {deltas}")
    return lines


def _profile_change_summary(pchange: ProfileChange) -> str:
    """Render one profile's membership delta as ``+a, +b; -c``."""

    parts = []
    if pchange.added:
        parts.append(", ".join(f"+{c}" for c in pchange.added))
    if pchange.removed:
        parts.append(", ".join(f"-{c}" for c in pchange.removed))
    return "; ".join(parts)


def _profile_lines(diff: CatalogDiff) -> list[str]:
    """The profile section, or the one-line explanation of why there is none."""

    if not diff.profiles_compared:
        return ["Profiles: not compared (one side is a bare catalog.yaml without a profiles/ directory)."]
    lines = [
        f"Profiles: +{len(diff.added_profiles)} added, "
        f"-{len(diff.removed_profiles)} removed, "
        f"~{len(diff.changed_profiles)} changed"
    ]
    lines.extend(f"  + {pid}" for pid in diff.added_profiles)
    lines.extend(f"  - {pid}" for pid in diff.removed_profiles)
    lines.extend(f"  ~ {pchange.id}  {_profile_change_summary(pchange)}" for pchange in diff.changed_profiles)
    return lines


def render_human(diff: CatalogDiff) -> str:
    """Render a concise human-readable summary of *diff*."""

    lines = [f"Catalog diff: {diff.from_label} -> {diff.to_label}", ""]
    if diff.is_empty:
        lines.append("No control or profile differences.")
    lines.extend(_control_lines(diff))
    lines.append("")
    lines.extend(_profile_lines(diff))
    lines.append("")
    lines.append("Generated, read-only: explains changes between two kit versions; changes no evaluate verdict.")
    return "\n".join(lines) + "\n"
