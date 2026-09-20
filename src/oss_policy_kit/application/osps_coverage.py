"""Shared OSPS Baseline v2026.02.19 coverage computation (ADR-037).

Single source of truth for how the bundled ``osps-baseline-2026-1`` controls map
to the OpenSSF OSPS Baseline criteria, consumed by both the ``osps-coverage`` CLI
command and ``scripts/generate-osps-coverage.py``. Loads the pinned criteria +
control->criterion signal map from
``data/frameworks/osps-baseline-2026.yaml``, resolves each control's assurance
live from the control catalog, validates integrity, and computes honest per-level
(L1/L2/L3) coverage.

This is an **advisory** mapping, never a conformance certification: a kit control
provides a clone-visible *signal toward* an OSPS criterion, never a guarantee of
an OSPS maturity level. Coverage counts criteria with at least one such signal;
gaps are real.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import yaml

from oss_policy_kit.application.input_limits import bad_input_detail
from oss_policy_kit.application.loader import (
    ControlSpec,
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)
from oss_policy_kit.domain.errors import LoadError

LEVELS: tuple[int, ...] = (1, 2, 3)


@dataclasses.dataclass(frozen=True)
class ControlSignal:
    """A bundled control that provides a clone-visible signal toward a criterion."""

    control_id: str
    assurance: str


@dataclasses.dataclass(frozen=True)
class CriterionCoverage:
    """One OSPS criterion and the kit controls (if any) that signal it."""

    id: str
    family: str
    levels: tuple[int, ...]
    objective: str
    signals: tuple[ControlSignal, ...]

    @property
    def covered(self) -> bool:
        return bool(self.signals)


@dataclasses.dataclass(frozen=True)
class LevelCoverage:
    """Per-maturity-level coverage counts (advisory; not a conformance level)."""

    level: int
    total: int
    covered: int

    @property
    def gaps(self) -> int:
        return self.total - self.covered


@dataclasses.dataclass(frozen=True)
class AggregateControl:
    """A control that asserts an upstream verdict spanning families (not a criterion)."""

    control_id: str
    note: str


@dataclasses.dataclass(frozen=True)
class OspsCoverage:
    """Computed OSPS coverage for the pinned snapshot + bundled profile."""

    version: str
    source: str
    source_tag: str
    profile: str
    disclaimer: str
    criteria: tuple[CriterionCoverage, ...]
    levels: tuple[LevelCoverage, ...]
    aggregate_controls: tuple[AggregateControl, ...]

    @property
    def gap_criteria(self) -> tuple[CriterionCoverage, ...]:
        return tuple(c for c in self.criteria if not c.covered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "source": self.source,
            "source_tag": self.source_tag,
            "profile": self.profile,
            "disclaimer": self.disclaimer,
            "levels": [
                {"level": lc.level, "total": lc.total, "covered": lc.covered, "gaps": lc.gaps} for lc in self.levels
            ],
            "criteria": [
                {
                    "id": c.id,
                    "family": c.family,
                    "levels": list(c.levels),
                    "objective": c.objective,
                    "covered": c.covered,
                    "signals": [{"control": s.control_id, "assurance": s.assurance} for s in c.signals],
                }
                for c in self.criteria
            ],
            "gaps": [c.id for c in self.gap_criteria],
            "aggregate_controls": [{"control": a.control_id, "note": a.note} for a in self.aggregate_controls],
        }


def _data_path(kit_root: Path) -> Path:
    return kit_root / "frameworks" / "osps-baseline-2026.yaml"


def _load_raw(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:  # pragma: no cover - filesystem failure is not unit-testable here
        raise LoadError(f"Could not read OSPS coverage map at {path}: {bad_input_detail(exc)}") from exc
    except yaml.YAMLError as exc:
        raise LoadError(f"OSPS coverage map at {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise LoadError(f"OSPS coverage map at {path} must be a YAML mapping.")
    return raw


def _collect_signals(
    raw: dict[str, Any],
    path: Path,
    catalog: dict[str, ControlSpec],
    profile_id: str,
    profile_control_ids: set[str],
    criterion_ids: set[str],
) -> dict[str, list[ControlSignal]]:
    """Map each criterion id to the controls that signal it, in mapping-file order.

    Every referenced control has to exist in the catalog, belong to the declared
    profile, and appear at most once; every referenced criterion has to be declared.
    A map that fails any of those is structurally inconsistent, not partially usable.
    """

    signals: dict[str, list[ControlSignal]] = {cid: [] for cid in criterion_ids}
    seen_controls: set[str] = set()
    for entry in raw.get("mappings") or []:
        control = str(entry["control"])
        if control in seen_controls:
            raise LoadError(f"OSPS coverage map at {path}: duplicate mapping for control {control}.")
        seen_controls.add(control)
        if control not in catalog:
            raise LoadError(f"OSPS coverage map at {path}: control {control} is not in the catalog.")
        if control not in profile_control_ids:
            raise LoadError(f"OSPS coverage map at {path}: control {control} is not in the {profile_id} profile.")
        assurance = catalog[control].assurance
        for crit in entry.get("criteria") or []:
            crit_id = str(crit)
            if crit_id not in criterion_ids:
                raise LoadError(
                    f"OSPS coverage map at {path}: control {control} references unknown criterion {crit_id}."
                )
            signals[crit_id].append(ControlSignal(control_id=control, assurance=assurance))
    return signals


def _collect_aggregate_controls(
    raw: dict[str, Any],
    path: Path,
    catalog: dict[str, ControlSpec],
) -> tuple[AggregateControl, ...]:
    """Controls that back the map as a whole rather than any single criterion."""

    out = []
    for entry in raw.get("aggregate_controls") or []:
        control = str(entry["control"])
        if control not in catalog:
            raise LoadError(f"OSPS coverage map at {path}: aggregate control {control} is not in the catalog.")
        out.append(AggregateControl(control_id=control, note=str(entry.get("note", ""))))
    return tuple(out)


def load_osps_coverage(root: Path | None = None) -> OspsCoverage:
    """Load + validate + compute OSPS coverage from the bundled data file.

    Raises :class:`LoadError` if the map is structurally inconsistent (an unknown
    or out-of-profile control, an unknown criterion, or a duplicate).
    """

    kit_root = root if root is not None else bundled_kit_root()
    path = _data_path(kit_root)
    raw = _load_raw(path)

    catalog = load_catalog(kit_root / "controls" / "catalog.yaml")
    profile_id = str(raw.get("profile", "")).strip()
    if not profile_id:
        raise LoadError(f"OSPS coverage map at {path} is missing a 'profile'.")
    profile = load_profile_by_id(kit_root, profile_id)
    profile_control_ids = set(profile.control_ids)

    criteria_raw = raw.get("criteria") or []
    criterion_ids = {str(c["id"]) for c in criteria_raw}
    if len(criterion_ids) != len(criteria_raw):
        raise LoadError(f"OSPS coverage map at {path} has duplicate criterion ids.")

    # criterion id -> ordered list of signalling controls (mapping file order).
    signals = _collect_signals(raw, path, catalog, profile_id, profile_control_ids, criterion_ids)

    criteria = tuple(
        CriterionCoverage(
            id=str(c["id"]),
            family=str(c["family"]),
            levels=tuple(int(level) for level in c["levels"]),
            objective=str(c["objective"]),
            signals=tuple(signals[str(c["id"])]),
        )
        for c in criteria_raw
    )

    levels = tuple(
        LevelCoverage(
            level=level,
            total=sum(1 for c in criteria if level in c.levels),
            covered=sum(1 for c in criteria if level in c.levels and c.covered),
        )
        for level in LEVELS
    )

    aggregate_controls = _collect_aggregate_controls(raw, path, catalog)

    return OspsCoverage(
        version=str(raw.get("version", "")),
        source=str(raw.get("source", "")),
        source_tag=str(raw.get("source_tag", "")),
        profile=profile_id,
        disclaimer=str(raw.get("disclaimer", "")).strip(),
        criteria=criteria,
        levels=levels,
        aggregate_controls=aggregate_controls,
    )
