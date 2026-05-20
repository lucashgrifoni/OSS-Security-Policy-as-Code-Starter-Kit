#!/usr/bin/env python3
"""Regenerate docs/controls-catalog.md from the bundled catalog + profiles.

The page is a single-source-of-truth reference derived from
``src/oss_policy_kit/data/controls/catalog.yaml`` and the bundled profile
definitions. Run this whenever the catalog or profile membership changes:

    python scripts/generate-controls-catalog.py

It writes ``docs/controls-catalog.md`` in place. Pass ``--check`` to fail
(exit 1) if the file is out of date instead of rewriting it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOC_PATH = _REPO_ROOT / "docs" / "controls-catalog.md"

_ASSURANCE_ORDER = ("deterministic", "evidence-backed", "signal")
_ASSURANCE_MEANING = {
    "deterministic": "Structural parse or file presence/absence with high confidence.",
    "evidence-backed": "Depends on a local JSON evidence file or API-collected attestation.",
    "signal": "Heuristic or directional signal; PASS is not proof of runtime behavior.",
}


def _profile_ids(root: Path) -> list[str]:
    return sorted(p.name for p in (root / "profiles").iterdir() if (p / "profile.yaml").is_file())


def _build() -> str:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile_ids = _profile_ids(root)

    membership: dict[str, list[str]] = {cid: [] for cid in catalog}
    for pid in profile_ids:
        spec = load_profile_by_id(root, pid)
        for cid in spec.control_ids:
            if cid in membership:
                membership[cid].append(pid)

    n_controls = len(catalog)
    n_profiles = len(profile_ids)

    cat_counts: dict[str, int] = {}
    asr_counts: dict[str, int] = {}
    for spec in catalog.values():
        cat_counts[spec.category] = cat_counts.get(spec.category, 0) + 1
        asr_counts[spec.assurance] = asr_counts.get(spec.assurance, 0) + 1

    lines: list[str] = []
    lines.append(f"# Controls Catalog ({n_controls} controls)")
    lines.append("")
    lines.append(
        "Single-page reference generated from the bundled control catalog and profiles. "
        "The authoritative source is "
        "[`src/oss_policy_kit/data/controls/catalog.yaml`](../src/oss_policy_kit/data/controls/catalog.yaml)."
    )
    lines.append("")
    lines.append(
        f"Current bundled state: **{n_controls} controls** across **{n_profiles} bundled profiles**. "
        "Regenerate this page whenever the catalog or profile membership changes "
        "(`python scripts/generate-controls-catalog.py`)."
    )
    lines.append("")
    lines.append("## By Category")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for cat in sorted(cat_counts):
        lines.append(f"| `{cat}` | {cat_counts[cat]} |")
    lines.append("")
    lines.append("## By Assurance")
    lines.append("")
    lines.append("| Assurance | Count | Meaning |")
    lines.append("|---|---:|---|")
    for asr in _ASSURANCE_ORDER:
        lines.append(f"| `{asr}` | {asr_counts.get(asr, 0)} | {_ASSURANCE_MEANING[asr]} |")
    lines.append("")
    lines.append("## Full Catalog")
    lines.append("")
    lines.append(
        "Profile counts in the **Profiles** column reflect how many bundled profiles include the "
        "control. See [profiles/overview.md](profiles/overview.md) for the bundled profile ladder."
    )
    lines.append("")
    lines.append("| Control ID | Category | Assurance | Weight | Profiles | Title |")
    lines.append("|---|---|---|---:|---:|---|")
    for cid, spec in catalog.items():
        count = len(membership[cid])
        lines.append(
            f"| `{cid}` | {spec.category} | {spec.assurance} | {spec.weight} | {count} | {spec.title} |"
        )
    lines.append("")
    lines.append("## Per-Control Profile Membership")
    lines.append("")
    lines.append(
        "Each control entry below lists which bundled profiles include it. Controls not present "
        "in any profile are marked `_not bundled in a profile_`."
    )
    lines.append("")
    for cid in catalog:
        profs = membership[cid]
        if profs:
            joined = ", ".join(f"`{p}`" for p in sorted(profs))
            lines.append(f"- `{cid}`: {joined}")
        else:
            lines.append(f"- `{cid}`: _not bundled in a profile_")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the doc is out of date.")
    args = parser.parse_args(argv)

    content = _build()
    if args.check:
        current = _DOC_PATH.read_text(encoding="utf-8") if _DOC_PATH.is_file() else ""
        if current.strip() != content.strip():
            print(f"{_DOC_PATH} is out of date; run scripts/generate-controls-catalog.py", file=sys.stderr)
            return 1
        print(f"{_DOC_PATH} is up to date.")
        return 0
    _DOC_PATH.write_text(content + "\n", encoding="utf-8")
    print(f"Wrote {_DOC_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
