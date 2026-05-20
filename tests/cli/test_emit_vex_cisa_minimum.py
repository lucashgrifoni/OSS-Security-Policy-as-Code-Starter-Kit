"""CISA VEX minimum-requirements coverage for ``emit-vex``.

Validates the CycloneDX VEX 1.6 document produced by ``oss-policy-kit emit-vex``
against the field set defined by CISA's *Minimum Requirements for Vulnerability
Exploitability eXchange (VEX)* (2023). Reference:
https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex

The CISA minimum requirements group into four categories:

1. **VEX Metadata** — format identifier, author / identity, author role,
   timestamp, last-updated timestamp, version.
2. **Product details** — product identifier with version.
3. **Vulnerability details** — vulnerability identifier (CVE / GHSA / OSV /
   RUSTSEC accepted).
4. **Product status** — one of ``NOT_AFFECTED`` / ``AFFECTED`` / ``FIXED`` /
   ``UNDER_INVESTIGATION``.

CycloneDX VEX 1.6 maps to the CISA vocabulary as follows:

| CISA field                  | CycloneDX 1.6 field                                    |
|---|---|
| Format identifier           | ``bomFormat`` = ``"CycloneDX"``                        |
| Author identity             | ``metadata.tools[*]`` (kit-emitted entry)              |
| Timestamp                   | ``metadata.timestamp``                                 |
| Version                     | ``version`` (integer, 1 for first emit)                |
| Vulnerability identifier    | ``vulnerabilities[*].id``                              |
| Product status              | ``vulnerabilities[*].analysis.state`` (mapped below)   |

CycloneDX ``analysis.state`` → CISA product status:
- ``in_triage`` → ``UNDER_INVESTIGATION``
- ``not_affected`` / ``false_positive`` → ``NOT_AFFECTED``
- ``exploitable`` → ``AFFECTED``
- ``resolved`` / ``resolved_with_pedigree`` → ``FIXED``

Known gaps relative to CISA strict reading — exercised explicitly via
``test_known_gaps_*`` tests so they regress visibly if the gap is later closed
(and the test should be updated when that happens):

- **Author role** — CISA expects an explicit role tag (e.g.
  ``vulnerability_disclosure_role``). CycloneDX 1.6 emits this via the
  ``manufacturer`` or ``supplier`` block, which ``emit-vex`` does not yet
  populate. v5.9.x scope: deferred. Tracked under v5.9.x extensions in
  ``docs/profiles/deferred-followups.md``.
- **Last-updated timestamp distinct from creation timestamp** — for a freshly
  emitted document these are equal; the kit currently emits only a single
  ``metadata.timestamp``. Acceptable for v0.2 surface.
- **Product identifier with version** — CISA requires a product reference at
  document or vulnerability level. The current ``emit-vex`` surface is OSV-
  driven and does not bind findings to a kit-emitted product identifier. v5.9.x
  scope: deferred (the kit does not generate SBOMs; a future ``--product-purl``
  flag may bind documents to the manufacturer-supplied product reference).

These gaps are documented, not silently passed. The test file makes the present
fields enforceable and the absent fields explicit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.cli.emit_vex import (
    _build_vex_document,
    _validate_vex_structure,
)

# --- Helpers ----------------------------------------------------------------


def _sample_osv_sarif_path(tmp_path: Path) -> Path:
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "osv-scanner",
                        "rules": [
                            {"id": "CVE-2024-12345"},
                            {"id": "GHSA-m5pq-gvj9-9vr8"},
                            {"id": "RUSTSEC-2022-0013"},
                        ],
                    }
                },
                "results": [],
            }
        ],
    }
    p = tmp_path / "osv-scanner.sarif.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _build_doc(tmp_path: Path) -> dict:
    sarif = _sample_osv_sarif_path(tmp_path)
    return _build_vex_document(
        vuln_ids=["CVE-2024-12345", "GHSA-m5pq-gvj9-9vr8", "RUSTSEC-2022-0013"],
        source_path=sarif,
    )


# CycloneDX → CISA product-status mapping. Kept in sync with the module-level
# table in this file's docstring; if either side moves, both move together.
_CDX_TO_CISA_STATUS: dict[str, str] = {
    "in_triage": "UNDER_INVESTIGATION",
    "not_affected": "NOT_AFFECTED",
    "false_positive": "NOT_AFFECTED",
    "exploitable": "AFFECTED",
    "resolved": "FIXED",
    "resolved_with_pedigree": "FIXED",
}

_CISA_REQUIRED_PRODUCT_STATUS_VALUES: frozenset[str] = frozenset(
    {"NOT_AFFECTED", "AFFECTED", "FIXED", "UNDER_INVESTIGATION"}
)


# --- Category 1: VEX Metadata -----------------------------------------------


def test_cisa_metadata_format_identifier_present(tmp_path: Path) -> None:
    """CISA: VEX Metadata → format identifier."""
    doc = _build_doc(tmp_path)
    assert doc.get("bomFormat") == "CycloneDX"


def test_cisa_metadata_format_specversion_declared(tmp_path: Path) -> None:
    """The format identifier alone is not sufficient — specVersion pins which CycloneDX-VEX dialect."""
    doc = _build_doc(tmp_path)
    assert doc.get("specVersion") == "1.6"


def test_cisa_metadata_timestamp_present_and_iso8601(tmp_path: Path) -> None:
    """CISA: VEX Metadata → timestamp (creation)."""
    doc = _build_doc(tmp_path)
    ts = (doc.get("metadata") or {}).get("timestamp")
    assert isinstance(ts, str) and ts.endswith("Z")
    # Minimal ISO-8601 check: YYYY-MM-DDTHH:MM:SSZ
    from datetime import datetime

    datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def test_cisa_metadata_version_present(tmp_path: Path) -> None:
    """CISA: VEX Metadata → version."""
    doc = _build_doc(tmp_path)
    assert doc.get("version") == 1


def test_cisa_metadata_author_identity_present_as_tool(tmp_path: Path) -> None:
    """CISA: VEX Metadata → author identity.

    The kit currently emits the author identity via ``metadata.tools[*]`` —
    sufficient for CISA's machine-parseable identity but does not yet emit
    a separate ``metadata.manufacturer`` or ``metadata.supplier`` block.
    """
    doc = _build_doc(tmp_path)
    tools = (doc.get("metadata") or {}).get("tools")
    assert isinstance(tools, list) and len(tools) >= 1
    kit_entry = next((t for t in tools if t.get("vendor") == "oss-policy-kit"), None)
    assert kit_entry is not None, "expected an oss-policy-kit tool entry in metadata.tools[]"
    assert isinstance(kit_entry.get("name"), str) and kit_entry["name"]
    assert isinstance(kit_entry.get("version"), str) and kit_entry["version"]


# --- Category 3: Vulnerability details ---------------------------------------


def test_cisa_vulnerability_identifier_present_per_finding(tmp_path: Path) -> None:
    """CISA: Vulnerability details → identifier per finding."""
    doc = _build_doc(tmp_path)
    vulns = doc.get("vulnerabilities", [])
    assert len(vulns) == 3
    for v in vulns:
        vid = v.get("id")
        assert isinstance(vid, str) and vid.strip(), f"vulnerability.id missing: {v!r}"


def test_cisa_vulnerability_identifier_supports_multiple_id_systems(tmp_path: Path) -> None:
    """CISA accepts CVE / GHSA / OSV / RUSTSEC etc. as identifier forms."""
    doc = _build_doc(tmp_path)
    ids = [v["id"] for v in doc["vulnerabilities"]]
    assert any(i.startswith("CVE-") for i in ids)
    assert any(i.startswith("GHSA-") for i in ids)
    assert any(i.startswith("RUSTSEC-") for i in ids)


# --- Category 4: Product status ---------------------------------------------


def test_cisa_product_status_mappable_per_finding(tmp_path: Path) -> None:
    """CISA: Product status — every CycloneDX state must map to one of the four CISA values."""
    doc = _build_doc(tmp_path)
    for v in doc["vulnerabilities"]:
        cdx_state = (v.get("analysis") or {}).get("state")
        assert cdx_state in _CDX_TO_CISA_STATUS, (
            f"CycloneDX state {cdx_state!r} has no CISA mapping; update the table or fix the emitter."
        )
        cisa_status = _CDX_TO_CISA_STATUS[cdx_state]
        assert cisa_status in _CISA_REQUIRED_PRODUCT_STATUS_VALUES


def test_cisa_default_state_is_under_investigation(tmp_path: Path) -> None:
    """A finding without an explicit waiver maps to UNDER_INVESTIGATION (per CISA),
    not to silent NOT_AFFECTED. ``in_triage`` is the safe default; any other
    default would risk under-reporting."""
    doc = _build_doc(tmp_path)
    for v in doc["vulnerabilities"]:
        cdx_state = (v.get("analysis") or {}).get("state")
        assert cdx_state == "in_triage"
        assert _CDX_TO_CISA_STATUS[cdx_state] == "UNDER_INVESTIGATION"


# --- Structural validation is a CISA prerequisite ---------------------------


def test_validate_vex_structure_passes_for_emitted_document(tmp_path: Path) -> None:
    """The structural validator must accept the document the emitter just produced.
    If this fails, the CISA-coverage tests above are testing a broken baseline."""
    doc = _build_doc(tmp_path)
    errs = _validate_vex_structure(doc)
    assert errs == [], f"VEX structural validation errors: {errs}"


# --- Known gaps (explicit, not silent) --------------------------------------


def test_known_gap_no_explicit_author_role(tmp_path: Path) -> None:
    """CISA: VEX Metadata → author role. Not yet emitted.

    Document the gap explicitly so it regresses visibly if a future change
    closes it. When the kit starts emitting an explicit author role (e.g. via
    ``metadata.manufacturer.contact.name`` with a role tag), this test should be
    promoted to a positive assertion and the gap removed from the file
    docstring.
    """
    doc = _build_doc(tmp_path)
    metadata = doc.get("metadata") or {}
    # No author-role tag is currently emitted. Update this test when one is.
    assert "manufacturer" not in metadata, (
        "metadata.manufacturer is now emitted — update test_known_gap_no_explicit_author_role "
        "to assert the new shape positively and remove the corresponding gap from the file docstring."
    )


def test_known_gap_no_product_identifier_with_version(tmp_path: Path) -> None:
    """CISA: Product details → product identifier with version. Not yet emitted.

    The kit's ``emit-vex`` is OSV-driven and does not bind findings to a
    kit-emitted product reference. When a ``--product-purl`` (or equivalent)
    flag lands, this test should be promoted to a positive assertion.
    """
    doc = _build_doc(tmp_path)
    for v in doc["vulnerabilities"]:
        # No ``affects[]`` or per-finding product binding today.
        assert "affects" not in v, (
            "vulnerabilities[].affects[] is now emitted — update "
            "test_known_gap_no_product_identifier_with_version to assert the new shape positively."
        )


# --- CISA waiver path (NOT_AFFECTED with justification) ---------------------


def test_cisa_not_affected_state_emitted_when_waiver_supplied(tmp_path: Path) -> None:
    """When a per-vulnerability waiver is supplied, the resulting analysis.state
    maps to CISA NOT_AFFECTED. Justification is preserved in analysis.detail."""
    from datetime import date

    from oss_policy_kit.cli.emit_vex import _VulnWaiver

    waivers = {
        "CVE-2024-12345": _VulnWaiver(
            justification_text="Reachability analysis shows this code path is not exercised in production.",
            owner="appsec@example.com",
            status="open",
            expires_at=date(2026, 12, 31),
            cdx_justification="code_not_reachable",
        )
    }
    sarif = _sample_osv_sarif_path(tmp_path)
    doc = _build_vex_document(
        vuln_ids=["CVE-2024-12345", "GHSA-m5pq-gvj9-9vr8"],
        source_path=sarif,
        waivers=waivers,
    )
    waived = next(v for v in doc["vulnerabilities"] if v["id"] == "CVE-2024-12345")
    assert waived["analysis"]["state"] == "not_affected"
    assert _CDX_TO_CISA_STATUS["not_affected"] == "NOT_AFFECTED"
    assert waived["analysis"]["justification"] == "code_not_reachable"
    assert "Reachability" in waived["analysis"]["detail"]
    unwaived = next(v for v in doc["vulnerabilities"] if v["id"] == "GHSA-m5pq-gvj9-9vr8")
    assert unwaived["analysis"]["state"] == "in_triage"


# --- Sanity: parametric round-trip over all CycloneDX states ----------------


@pytest.mark.parametrize("cdx_state,cisa_status", sorted(_CDX_TO_CISA_STATUS.items()))
def test_every_cdx_state_maps_to_valid_cisa_status(cdx_state: str, cisa_status: str) -> None:
    """Every entry in the mapping table must resolve to a valid CISA status."""
    assert cisa_status in _CISA_REQUIRED_PRODUCT_STATUS_VALUES
