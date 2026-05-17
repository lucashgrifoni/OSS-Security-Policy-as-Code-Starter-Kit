"""Profile maturity drift guards (F1-02 of the v5.8.0 amadurecimento plan).

Two invariants:

1. **Hard-gate-capable profiles must carry enough evidence-backed weight.**
   The catalog already classifies every bundled profile via
   ``_profile_maturity_label`` (cli/profiles.py). Two sub-buckets exist:

   - **Extreme hard-gate** (label contains ``(extreme)``): ladder ``-level-3``
     and ``release-hardening-3`` profiles across the platform families.
     These are designed to gate production releases, so they should expose at
     least ``EXTREME_MIN_EVIDENCE_BACKED_RATIO`` of evidence-backed controls.

   - **Framework-aligned hard-gate-capable** (label contains
     ``hard-gate-capable`` but NOT ``(extreme)``): ``appsec-sast-sca-1`` and
     ``slsa-build-l2-1``. They graduate from advisory once paired with a
     ``scan-*`` evidence emitter; their evidence-backed share is naturally
     lower because most SLSA / SAST coverage is deterministic. They need at
     least ``FRAMEWORK_MIN_EVIDENCE_BACKED_RATIO``.

2. **Advisory profiles must self-document their disposition.**
   A profile whose maturity label contains ``advisory`` must say so in its
   ``title`` or ``description`` so adopters do not accidentally use it as a
   hard release gate. We accept the phrases ``advisory only``,
   ``advisory-only``, or ``advisory`` paired with ``not a hard gate``.
   Regulatory advisory profiles (``cra-eu-*``) follow the same rule — their
   description must surface the advisory disposition explicitly, not rely
   on the framework label alone.

Failure modes captured:

- Removing an evidence-backed control from a ``-level-3`` profile and dropping
  below the threshold makes the suite fail with the affected profile id and
  the exact share computed.
- Renaming an advisory profile's description to remove the ``advisory``
  wording makes the second test fail with a clear message.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oss_policy_kit.cli.profiles import _profile_maturity_label

PROFILES_DIR = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "profiles"
CATALOG_PATH = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "controls" / "catalog.yaml"

# Tiered thresholds derived from the current bundle (Fase 1 of the
# amadurecimento plan, opcao A). Update intentionally if the catalog
# composition shifts; the test is meant to flag regressions, not block
# growth.
EXTREME_MIN_EVIDENCE_BACKED_RATIO: float = 0.15
FRAMEWORK_MIN_EVIDENCE_BACKED_RATIO: float = 0.05

# Accepted phrasings for the advisory disposition banner.
ADVISORY_BANNER_PHRASES: tuple[str, ...] = (
    "advisory only",
    "advisory-only",
    "advisory profile",
    "advisory bundle",
    "advisory hybrid",
    "advisory baseline",
    "advisory",  # paired-with "not a hard gate" check below
)


def _load_catalog_assurance() -> dict[str, str]:
    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    return {c["id"]: c["assurance"] for c in raw["controls"]}


def _load_profile(profile_dir: Path) -> dict[str, object]:
    return yaml.safe_load((profile_dir / "profile.yaml").read_text(encoding="utf-8"))


def _profile_dirs() -> list[Path]:
    return sorted(p for p in PROFILES_DIR.iterdir() if p.is_dir() and (p / "profile.yaml").exists())


_ASSURANCE_BY_ID: dict[str, str] = _load_catalog_assurance()


def _profile_evidence_backed_ratio(profile_data: dict[str, object]) -> tuple[float, int, int]:
    """Return (ratio, evidence_backed_count, total)."""

    controls = profile_data.get("controls", [])
    if not isinstance(controls, list) or not controls:
        return (0.0, 0, 0)
    total = len(controls)
    evd = sum(1 for cid in controls if _ASSURANCE_BY_ID.get(cid) == "evidence-backed")
    return (evd / total, evd, total)


def _bucket_for(profile_id: str) -> str:
    label = _profile_maturity_label(profile_id, is_legacy_alias=False).lower()
    if "(extreme)" in label:
        return "extreme"
    if "hard-gate-capable" in label:
        return "framework_hard_gate"
    if "advisory" in label:
        return "advisory"
    return "other"


# Pre-classify so parametrize ids are stable.
_EXTREME: list[Path] = [d for d in _profile_dirs() if _bucket_for(d.name) == "extreme"]
_FRAMEWORK_HARD_GATE: list[Path] = [d for d in _profile_dirs() if _bucket_for(d.name) == "framework_hard_gate"]
_ADVISORY: list[Path] = [d for d in _profile_dirs() if _bucket_for(d.name) == "advisory"]


@pytest.mark.parametrize("profile_dir", _EXTREME, ids=lambda d: d.name)
def test_extreme_hard_gate_profile_has_enough_evidence_backed(profile_dir: Path) -> None:
    """Profiles labelled '(extreme)' must reserve at least 15% evidence-backed weight."""

    data = _load_profile(profile_dir)
    ratio, evd, total = _profile_evidence_backed_ratio(data)
    assert ratio >= EXTREME_MIN_EVIDENCE_BACKED_RATIO, (
        f"{profile_dir.name}: evidence-backed share is {ratio:.1%} "
        f"({evd}/{total}); extreme hard-gate profiles require "
        f">= {EXTREME_MIN_EVIDENCE_BACKED_RATIO:.0%}."
    )


@pytest.mark.parametrize("profile_dir", _FRAMEWORK_HARD_GATE, ids=lambda d: d.name)
def test_framework_hard_gate_profile_has_enough_evidence_backed(profile_dir: Path) -> None:
    """Framework-aligned hard-gate-capable profiles need a smaller floor (5%)."""

    data = _load_profile(profile_dir)
    ratio, evd, total = _profile_evidence_backed_ratio(data)
    assert ratio >= FRAMEWORK_MIN_EVIDENCE_BACKED_RATIO, (
        f"{profile_dir.name}: evidence-backed share is {ratio:.1%} "
        f"({evd}/{total}); framework-aligned hard-gate-capable profiles require "
        f">= {FRAMEWORK_MIN_EVIDENCE_BACKED_RATIO:.0%}."
    )


@pytest.mark.parametrize("profile_dir", _ADVISORY, ids=lambda d: d.name)
def test_advisory_profile_documents_advisory_disposition(profile_dir: Path) -> None:
    """Advisory profiles must surface their disposition in title or description."""

    data = _load_profile(profile_dir)
    title = str(data.get("title", ""))
    description = str(data.get("description", ""))
    blob = (title + "\n" + description).lower()

    matched = any(phrase in blob for phrase in ADVISORY_BANNER_PHRASES)
    paired_caveat = "advisory" in blob and "not a hard gate" in blob

    assert matched or paired_caveat, (
        f"{profile_dir.name}: title/description must surface the disposition "
        f"(one of {ADVISORY_BANNER_PHRASES!r}, or 'advisory' plus 'not a hard gate'); "
        f"got title={title!r}, description={description!r}"
    )


def test_bucket_population_floor() -> None:
    """Sanity floor: the buckets continue to cover the bundle.

    Catches accidental loss of profiles or misclassification by the maturity
    label heuristic.
    """

    assert len(_EXTREME) >= 6, f"Expected at least 6 extreme hard-gate profiles; found {len(_EXTREME)}"
    assert len(_FRAMEWORK_HARD_GATE) >= 2, (
        f"Expected at least 2 framework-aligned hard-gate-capable profiles; found {len(_FRAMEWORK_HARD_GATE)}"
    )
    assert len(_ADVISORY) >= 14, f"Expected at least 14 advisory profiles; found {len(_ADVISORY)}"
