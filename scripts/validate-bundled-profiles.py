#!/usr/bin/env python
"""Bundled profiles and catalog invariant validator.

CLI mirror of the three pytest invariant modules added in v5.8.0:

- tests/application/test_profile_schemas.py
- tests/data/test_catalog_consistency.py
- tests/data/test_evidence_schemas_versioned.py

Use this when running pytest is heavier than needed (pre-commit hook,
fast local sanity check, release-time spot validation). The tests remain
the canonical source of truth; this script replicates the same checks
procedurally so it can run without the full test harness.

Returns exit code 0 when all invariants hold, 1 when violations are
found, 2 on usage errors.

Usage:

    python scripts/validate-bundled-profiles.py
    python scripts/validate-bundled-profiles.py --root /path/to/repo
    python scripts/validate-bundled-profiles.py --quiet
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


def _err(msg: str) -> None:
    sys.stderr.write(msg + "\n")


# ---------------------------------------------------------------------------
# Catalog invariants (mirrors tests/data/test_catalog_consistency.py)
# ---------------------------------------------------------------------------

REQUIRED_CATALOG_FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "category",
    "automation",
    "lifecycle",
    "assurance",
    "weight",
)

ALLOWED_CATEGORIES: frozenset[str] = frozenset(
    {
        "governance",
        "ci_cd",
        "supply_chain",
        "vulnerability_management",
        "release",
        "platform",
        "iac",
        "container",
        "kubernetes",
        "secure_development",
    }
)
ALLOWED_LIFECYCLES: frozenset[str] = frozenset({"stable", "experimental", "deprecated"})
ALLOWED_ASSURANCE: frozenset[str] = frozenset({"deterministic", "signal", "evidence-backed"})
ALLOWED_AUTOMATION: frozenset[str] = frozenset(
    {"automated", "partially_observable", "human_or_policy", "not_observable_locally", "deterministic"}
)
ALLOWED_WEIGHTS: frozenset[int] = frozenset({1, 2, 3})


def _validate_catalog(catalog_path: Path) -> list[str]:
    violations: list[str] = []
    raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return [f"{catalog_path.name}: top-level must be a mapping"]
    controls = raw.get("controls") or []
    if not isinstance(controls, list) or not controls:
        return [f"{catalog_path.name}: 'controls:' must be a non-empty list"]

    ids: list[str] = []
    for c in controls:
        if not isinstance(c, dict):
            violations.append(f"{catalog_path.name}: control entry is not a mapping: {c!r}")
            continue
        cid = c.get("id", "<no-id>")
        ids.append(cid)
        for f in REQUIRED_CATALOG_FIELDS:
            if f not in c:
                violations.append(f"{cid}: missing required field '{f}'")
        title = c.get("title")
        if not isinstance(title, str) or not title.strip():
            violations.append(f"{cid}: 'title' must be a non-empty string")
        if c.get("category") not in ALLOWED_CATEGORIES:
            violations.append(f"{cid}: category={c.get('category')!r} not in {sorted(ALLOWED_CATEGORIES)}")
        if c.get("lifecycle") not in ALLOWED_LIFECYCLES:
            violations.append(f"{cid}: lifecycle={c.get('lifecycle')!r} not in {sorted(ALLOWED_LIFECYCLES)}")
        if c.get("assurance") not in ALLOWED_ASSURANCE:
            violations.append(f"{cid}: assurance={c.get('assurance')!r} not in {sorted(ALLOWED_ASSURANCE)}")
        if c.get("automation") not in ALLOWED_AUTOMATION:
            violations.append(f"{cid}: automation={c.get('automation')!r} not in {sorted(ALLOWED_AUTOMATION)}")
        if c.get("weight") not in ALLOWED_WEIGHTS:
            violations.append(f"{cid}: weight={c.get('weight')!r} not in {sorted(ALLOWED_WEIGHTS)}")

    duplicates = sorted(cid for cid, n in Counter(ids).items() if n > 1)
    if duplicates:
        violations.append(f"{catalog_path.name}: duplicate control IDs: {duplicates}")
    if len(controls) < 120:
        violations.append(f"{catalog_path.name}: expected at least 120 controls; found {len(controls)}")
    return violations


# ---------------------------------------------------------------------------
# Profile invariants (mirrors tests/application/test_profile_schemas.py)
# ---------------------------------------------------------------------------

REQUIRED_PROFILE_FIELDS: tuple[str, ...] = ("id", "title", "description", "audience", "controls")


def _validate_profiles(profiles_dir: Path, catalog_ids: set[str]) -> list[str]:
    violations: list[str] = []
    profile_files = sorted(p / "profile.yaml" for p in profiles_dir.iterdir() if p.is_dir())
    profile_files = [f for f in profile_files if f.exists()]

    if len(profile_files) < 21:
        violations.append(f"{profiles_dir}: expected at least 21 bundled profiles; found {len(profile_files)}")

    for pf in profile_files:
        pid_dir = pf.parent.name
        data = yaml.safe_load(pf.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            violations.append(f"{pid_dir}: profile.yaml root must be a mapping")
            continue
        for f in REQUIRED_PROFILE_FIELDS:
            if f not in data:
                violations.append(f"{pid_dir}: missing required field '{f}'")
        if data.get("id") != pid_dir:
            violations.append(f"{pid_dir}: declared id {data.get('id')!r} differs from directory name")
        controls = data.get("controls") or []
        if not isinstance(controls, list) or not controls:
            violations.append(f"{pid_dir}: 'controls:' must be a non-empty list")
            continue
        missing = [c for c in controls if c not in catalog_ids]
        if missing:
            violations.append(f"{pid_dir}: control IDs not present in catalog.yaml: {missing}")
        counts = Counter(controls)
        dups = [cid for cid, n in counts.items() if n > 1]
        if dups:
            violations.append(f"{pid_dir}: duplicate control IDs in 'controls:': {dups}")
    return violations


# ---------------------------------------------------------------------------
# Evidence schema invariants (mirrors tests/data/test_evidence_schemas_versioned.py)
# ---------------------------------------------------------------------------

EXPECTED_DRAFT = "https://json-schema.org/draft/2020-12/schema"


def _validate_schemas(schema_dir: Path) -> list[str]:
    violations: list[str] = []
    files = sorted(schema_dir.glob("*.schema.json"))
    if len(files) < 24:
        violations.append(f"{schema_dir}: expected at least 24 bundled schemas; found {len(files)}")
    for f in files:
        raw_bytes = f.read_bytes()
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            violations.append(f"{f.name}: file starts with UTF-8 BOM (re-save as UTF-8 without BOM)")
        try:
            data: Any = json.loads(raw_bytes.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            violations.append(f"{f.name}: failed to parse as JSON ({exc})")
            continue
        if not isinstance(data, dict):
            violations.append(f"{f.name}: top-level must be a JSON object")
            continue
        if data.get("$schema") != EXPECTED_DRAFT:
            violations.append(f"{f.name}: $schema must be {EXPECTED_DRAFT!r}; got {data.get('$schema')!r}")
        sid = data.get("$id")
        if not isinstance(sid, str) or not sid.strip():
            violations.append(f"{f.name}: missing or empty $id")
            continue
        if not sid.startswith(("http://", "https://")):
            violations.append(f"{f.name}: $id must be an absolute URL; got {sid!r}")
        if not sid.endswith("/" + f.name):
            violations.append(f"{f.name}: $id={sid!r} does not end with the file's basename")
    return violations


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="validate-bundled-profiles",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root containing src/oss_policy_kit/data (default: parent of this script).",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress section progress lines (only emit violations).")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root.resolve()
    data_root = root / "src" / "oss_policy_kit" / "data"
    catalog_path = data_root / "controls" / "catalog.yaml"
    profiles_dir = data_root / "profiles"
    schema_dir = data_root / "schema"

    for required in (catalog_path, profiles_dir, schema_dir):
        if not required.exists():
            _err(f"Error: expected path not found: {required}")
            return 2

    if not args.quiet:
        sys.stdout.write(f"Validating bundled catalog and profiles under {data_root}\n")

    sections: list[tuple[str, list[str]]] = []

    if not args.quiet:
        sys.stdout.write("  [1/3] Catalog invariants ...\n")
    sections.append(("catalog", _validate_catalog(catalog_path)))

    catalog_raw = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    catalog_ids: set[str] = {
        c["id"]
        for c in catalog_raw.get("controls", [])
        if isinstance(c, dict) and isinstance(c.get("id"), str)
    }

    if not args.quiet:
        sys.stdout.write("  [2/3] Profile invariants ...\n")
    sections.append(("profiles", _validate_profiles(profiles_dir, catalog_ids)))

    if not args.quiet:
        sys.stdout.write("  [3/3] Evidence schema invariants ...\n")
    sections.append(("schemas", _validate_schemas(schema_dir)))

    total_violations = sum(len(v) for _, v in sections)
    if total_violations == 0:
        if not args.quiet:
            sys.stdout.write("OK: all bundled-profile invariants hold.\n")
        return 0

    sys.stdout.write(f"FOUND {total_violations} VIOLATION(S):\n")
    for name, vs in sections:
        if not vs:
            continue
        sys.stdout.write(f"  [{name}] {len(vs)} violation(s):\n")
        for v in vs:
            sys.stdout.write(f"    - {v}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
