"""Schema-file invariants for ``data/schema/evidence-*.schema.json`` and the
``evaluation-report-v*.schema.json`` family.

These tests assert public-contract hygiene on the bundled JSON Schemas:

- Each schema parses as a JSON object.
- Each schema declares ``$schema`` pointing to the JSON Schema 2020-12 draft.
- Each schema declares ``$id`` and the ``$id`` ends with the file's basename
  (the URL host can differ across the bundle; the trailing path must match
  the on-disk name so downstream consumers can resolve consistently).
- Each schema file is UTF-8 **without** BOM. The release-readiness checklist
  treats BOM as a regression (see ``docs/release-readiness.md``).

If any test fails, treat it as a pre-existing inconsistency to be cleaned
up before mergeing the v5.8.0 catalog work (see the Fase 1 plan).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "schema"

EXPECTED_DRAFT = "https://json-schema.org/draft/2020-12/schema"


def _bundled_schema_files() -> list[Path]:
    """Return every ``.schema.json`` file under ``data/schema/`` (sorted)."""

    return sorted(SCHEMA_DIR.glob("*.schema.json"))


SCHEMA_FILES: list[Path] = _bundled_schema_files()


@pytest.mark.parametrize("schema_path", SCHEMA_FILES, ids=lambda p: p.name)
def test_schema_file_parses_as_json_object(schema_path: Path) -> None:
    raw = schema_path.read_text(encoding="utf-8-sig")
    data: Any = json.loads(raw)
    assert isinstance(data, dict), f"{schema_path.name}: top-level must be a JSON object"


@pytest.mark.parametrize("schema_path", SCHEMA_FILES, ids=lambda p: p.name)
def test_schema_declares_2020_12_draft(schema_path: Path) -> None:
    data = json.loads(schema_path.read_text(encoding="utf-8-sig"))
    assert data.get("$schema") == EXPECTED_DRAFT, (
        f"{schema_path.name}: $schema must be {EXPECTED_DRAFT!r}; got {data.get('$schema')!r}"
    )


@pytest.mark.parametrize("schema_path", SCHEMA_FILES, ids=lambda p: p.name)
def test_schema_id_matches_filename(schema_path: Path) -> None:
    """``$id`` must be present, a string URL, and end with the file's basename."""

    data = json.loads(schema_path.read_text(encoding="utf-8-sig"))
    sid = data.get("$id")
    assert isinstance(sid, str) and sid.strip(), f"{schema_path.name}: missing or empty $id"
    assert sid.startswith(("http://", "https://")), f"{schema_path.name}: $id must be an absolute URL; got {sid!r}"
    assert sid.endswith("/" + schema_path.name), (
        f"{schema_path.name}: $id={sid!r} does not end with the file's basename"
    )


@pytest.mark.parametrize("schema_path", SCHEMA_FILES, ids=lambda p: p.name)
def test_schema_file_has_no_bom(schema_path: Path) -> None:
    """Schemas must be UTF-8 without BOM per the release-readiness checklist."""

    raw = schema_path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), (
        f"{schema_path.name}: file starts with a UTF-8 BOM. Re-save as UTF-8 (no BOM)."
    )


def test_at_least_24_bundled_schemas_exist() -> None:
    """Sanity floor: the kit must continue to ship its full evidence schema set."""

    count = len(SCHEMA_FILES)
    assert count >= 24, f"Expected at least 24 bundled JSON Schemas under data/schema/; found {count}"
