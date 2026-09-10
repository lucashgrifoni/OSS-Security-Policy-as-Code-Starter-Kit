"""emit-vex --format openvex: OpenVEX v0.2.0 emission, mapping, and validation.

Covers the additive OpenVEX surface (ADR-031, v6.6.0): the CycloneDX→OpenVEX
status/justification mapping, the placeholder-vs-supplied product identity, the
not_affected justification/impact rule, structural validation, and a regression
check that the default (CycloneDX) output is unchanged.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from oss_policy_kit.cli.emit_vex import (
    _OPENVEX_CONTEXT,
    _OPENVEX_PRODUCT_PLACEHOLDER,
    _build_openvex_document,
    _validate_openvex_structure,
    _VulnWaiver,
)

# --- Fixtures / helpers -----------------------------------------------------


def _write_sarif(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "osv.sarif.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _sarif_with_rules(*rule_ids: str) -> dict:
    return {"runs": [{"tool": {"driver": {"rules": [{"id": rid} for rid in rule_ids]}}, "results": []}]}


def _write_waivers(tmp_path: Path, entries: list[dict]) -> Path:
    import yaml

    p = tmp_path / "waivers.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "waivers": entries}, sort_keys=False), encoding="utf-8")
    return p


def _waiver(cdx_justification: str | None) -> _VulnWaiver:
    return _VulnWaiver(
        justification_text="vulnerable path is unreachable in our integration",
        owner="appsec@example.org",
        status="approved",
        expires_at=None,
        cdx_justification=cdx_justification,
    )


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
    )


# --- Document structure (unit) ----------------------------------------------


def test_build_openvex_document_structure() -> None:
    doc = _build_openvex_document(["CVE-1", "GHSA-2"], Path("fake.sarif.json"))
    assert doc["@context"] == _OPENVEX_CONTEXT
    assert isinstance(doc["@id"], str)
    assert doc["@id"].strip()
    assert doc["author"] == "oss-policy-kit emit-vex"
    assert "timestamp" in doc
    assert doc["version"] == 1
    assert doc["tooling"].startswith("oss-policy-kit emit-vex")
    assert len(doc["statements"]) == 2


def test_openvex_default_status_is_under_investigation() -> None:
    doc = _build_openvex_document(["CVE-1"], Path("fake.sarif.json"))
    stmt = doc["statements"][0]
    assert stmt["status"] == "under_investigation"
    assert stmt["vulnerability"]["name"] == "CVE-1"
    assert stmt["products"][0]["@id"] == _OPENVEX_PRODUCT_PLACEHOLDER
    assert "status_notes" in stmt


def test_openvex_uses_supplied_product() -> None:
    doc = _build_openvex_document(["CVE-1"], Path("fake.sarif.json"), product="pkg:pypi/acme@1.2.3")
    assert doc["statements"][0]["products"][0]["@id"] == "pkg:pypi/acme@1.2.3"


def test_openvex_blank_product_falls_back_to_placeholder() -> None:
    doc = _build_openvex_document(["CVE-1"], Path("fake.sarif.json"), product="   ")
    assert doc["statements"][0]["products"][0]["@id"] == _OPENVEX_PRODUCT_PLACEHOLDER


# --- Justification mapping (unit) -------------------------------------------


@pytest.mark.parametrize(
    ("cdx", "openvex"),
    [
        ("code_not_present", "vulnerable_code_not_present"),
        ("code_not_reachable", "vulnerable_code_not_in_execute_path"),
        ("requires_configuration", "vulnerable_code_cannot_be_controlled_by_adversary"),
        ("requires_dependency", "vulnerable_code_cannot_be_controlled_by_adversary"),
        ("requires_environment", "vulnerable_code_cannot_be_controlled_by_adversary"),
        ("protected_by_compensating_control", "inline_mitigations_already_exist"),
        ("inline_mitigations_already_exist", "inline_mitigations_already_exist"),
    ],
)
def test_openvex_justification_mapping(cdx: str, openvex: str) -> None:
    doc = _build_openvex_document(["CVE-1"], Path("fake.sarif.json"), waivers={"CVE-1": _waiver(cdx)})
    stmt = doc["statements"][0]
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == openvex
    # Free-text justification is always copied to impact_statement.
    assert stmt["impact_statement"] == "vulnerable path is unreachable in our integration"


def test_openvex_not_affected_without_enum_uses_impact_statement() -> None:
    doc = _build_openvex_document(["CVE-1"], Path("fake.sarif.json"), waivers={"CVE-1": _waiver(None)})
    stmt = doc["statements"][0]
    assert stmt["status"] == "not_affected"
    assert "justification" not in stmt
    assert stmt["impact_statement"] == "vulnerable path is unreachable in our integration"


def test_openvex_advisory_url_maps_to_vulnerability_id() -> None:
    doc = _build_openvex_document(
        ["GHSA-zzzz"],
        Path("fake.sarif.json"),
        references={"GHSA-zzzz": ["https://osv.dev/vulnerability/GHSA-zzzz"]},
    )
    assert doc["statements"][0]["vulnerability"]["@id"] == "https://osv.dev/vulnerability/GHSA-zzzz"


# --- Validation (unit) ------------------------------------------------------


def test_validate_openvex_accepts_well_formed_document() -> None:
    doc = _build_openvex_document(["CVE-1"], Path("fake.sarif.json"), product="pkg:pypi/acme@1")
    assert _validate_openvex_structure(doc) == []


def test_validate_openvex_rejects_missing_products() -> None:
    bad = {
        "@context": _OPENVEX_CONTEXT,
        "@id": "x",
        "author": "a",
        "timestamp": "t",
        "version": 1,
        "statements": [{"vulnerability": {"name": "CVE-1"}, "status": "under_investigation"}],
    }
    errs = _validate_openvex_structure(bad)
    assert any("products" in e for e in errs)


def test_validate_openvex_rejects_not_affected_without_justification_or_impact() -> None:
    bad = {
        "@context": _OPENVEX_CONTEXT,
        "@id": "x",
        "author": "a",
        "timestamp": "t",
        "version": 1,
        "statements": [{"vulnerability": {"name": "CVE-1"}, "products": [{"@id": "pkg:x"}], "status": "not_affected"}],
    }
    errs = _validate_openvex_structure(bad)
    assert any("justification or impact_statement" in e for e in errs)


def test_validate_openvex_rejects_bad_context() -> None:
    bad = _build_openvex_document(["CVE-1"], Path("fake.sarif.json"))
    bad["@context"] = "https://example.com/wrong"
    errs = _validate_openvex_structure(bad)
    assert any("@context" in e for e in errs)


# --- CLI integration --------------------------------------------------------


def test_cli_openvex_stdout(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, _sarif_with_rules("CVE-2024-1", "GHSA-aaaa"))
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--format", "openvex"])
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert doc["@context"] == _OPENVEX_CONTEXT
    names = sorted(s["vulnerability"]["name"] for s in doc["statements"])
    assert names == ["CVE-2024-1", "GHSA-aaaa"]


def test_cli_openvex_placeholder_product_warns(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, _sarif_with_rules("CVE-2024-1"))
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--format", "openvex"])
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert doc["statements"][0]["products"][0]["@id"] == _OPENVEX_PRODUCT_PLACEHOLDER
    assert "product" in proc.stderr.lower()


def test_cli_openvex_product_flag(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, _sarif_with_rules("CVE-2024-1"))
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--format", "openvex", "--product", "pkg:pypi/acme@1.2.3"])
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert doc["statements"][0]["products"][0]["@id"] == "pkg:pypi/acme@1.2.3"


def test_cli_openvex_waiver_not_affected(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, _sarif_with_rules("CVE-2024-1", "CVE-2024-2"))
    waivers = _write_waivers(
        tmp_path,
        [
            {
                "vulnerability_ids": ["CVE-2024-1"],
                "justification": "unreachable in our integration path",
                "owner": "appsec@example.org",
                "status": "approved",
                "expires_at": "2027-12-31",
                "vex_justification": "code_not_reachable",
            }
        ],
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(waivers), "--format", "openvex"])
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    by_name = {s["vulnerability"]["name"]: s for s in doc["statements"]}
    assert by_name["CVE-2024-1"]["status"] == "not_affected"
    assert by_name["CVE-2024-1"]["justification"] == "vulnerable_code_not_in_execute_path"
    assert by_name["CVE-2024-2"]["status"] == "under_investigation"


def test_cli_openvex_validate_passes(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, _sarif_with_rules("CVE-2024-1"))
    proc = _run_cli(
        ["emit-vex", "--osv-sarif", str(sarif), "--format", "openvex", "--validate", "--product", "pkg:pypi/x@1"]
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}"


def test_cli_openvex_include_references(tmp_path: Path) -> None:
    sarif = _write_sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {"rules": [{"id": "GHSA-zzzz", "helpUri": "https://osv.dev/vulnerability/GHSA-zzzz"}]}
                    },
                    "results": [],
                }
            ]
        },
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--format", "openvex", "--include-references"])
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert doc["statements"][0]["vulnerability"]["@id"] == "https://osv.dev/vulnerability/GHSA-zzzz"


def test_cli_default_format_still_cyclonedx(tmp_path: Path) -> None:
    """Regression: the default output is unchanged (no --format) — CycloneDX, not OpenVEX."""
    sarif = _write_sarif(tmp_path, _sarif_with_rules("CVE-2024-1"))
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif)])
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert "@context" not in doc


def test_cli_unknown_format_exits_2(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, _sarif_with_rules("CVE-2024-1"))
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--format", "csaf"])
    assert proc.returncode == 2, proc.stderr + proc.stdout
