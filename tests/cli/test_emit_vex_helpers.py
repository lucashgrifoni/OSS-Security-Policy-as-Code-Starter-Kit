"""Unit coverage for emit-vex pure helpers (waiver parsing, VEX build, structural validation)."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from oss_policy_kit.cli import emit_vex as ev

_TODAY = date(2026, 5, 21)


# --------------------------------------------------------------------------- #
# waiver expiry / justification parsing
# --------------------------------------------------------------------------- #


def test_parse_waiver_expiry_variants() -> None:
    w: list[str] = []
    assert ev._parse_waiver_expiry(0, {"expires_at": "2099-01-01"}, _TODAY, w) == (date(2099, 1, 1), True)
    assert ev._parse_waiver_expiry(1, {}, _TODAY, w) == (None, True)
    # expired
    exp, ok = ev._parse_waiver_expiry(2, {"expires_at": "2000-01-01"}, _TODAY, w)
    assert exp is None and ok is False
    # unparseable
    exp, ok = ev._parse_waiver_expiry(3, {"expires_at": "not-a-date"}, _TODAY, w)
    assert ok is False
    # date object
    future = _TODAY + timedelta(days=10)
    assert ev._parse_waiver_expiry(4, {"expires_at": future}, _TODAY, w) == (future, True)
    assert any("unparseable" in m for m in w)


def test_parse_cdx_justification() -> None:
    w: list[str] = []
    assert ev._parse_cdx_justification(0, {"vex_justification": "code_not_present"}, w) == "code_not_present"
    assert ev._parse_cdx_justification(1, {"vex_justification": "bogus"}, w) is None
    assert ev._parse_cdx_justification(2, {}, w) is None
    assert any("not in CycloneDX enum" in m for m in w)


def test_parse_vuln_waiver_entry() -> None:
    w: list[str] = []
    item = {
        "vulnerability_ids": ["CVE-1"],
        "justification": "false positive after review",
        "owner": "secteam",
        "vex_justification": "code_not_reachable",
    }
    parsed = ev._parse_vuln_waiver_entry(0, item, _TODAY, w)
    assert parsed is not None
    ids, rec = parsed
    assert ids == ["CVE-1"]
    assert rec.owner == "secteam" and rec.cdx_justification == "code_not_reachable"
    # skips
    assert ev._parse_vuln_waiver_entry(1, "notdict", _TODAY, w) is None
    assert ev._parse_vuln_waiver_entry(2, {"vulnerability_ids": []}, _TODAY, w) is None
    assert ev._parse_vuln_waiver_entry(3, {"vulnerability_ids": ["X"], "justification": ""}, _TODAY, w) is None
    assert (
        ev._parse_vuln_waiver_entry(4, {"vulnerability_ids": ["X"], "justification": "j", "owner": ""}, _TODAY, w)
        is None
    )


def test_load_vuln_waivers(tmp_path: Path) -> None:
    # not a file
    assert ev._load_vuln_waivers(tmp_path / "missing.yaml") == ({}, [])
    # not a mapping
    p = tmp_path / "w.yaml"
    p.write_text("- a\n- b\n", encoding="utf-8")
    out, warns = ev._load_vuln_waivers(p)
    assert out == {} and any("not a YAML mapping" in m for m in warns)
    # valid entries
    p.write_text(
        "waivers:\n  - vulnerability_ids: [CVE-9]\n    justification: reviewed, not exploitable\n    owner: appsec\n",
        encoding="utf-8",
    )
    out, warns = ev._load_vuln_waivers(p)
    assert "CVE-9" in out


# --------------------------------------------------------------------------- #
# VEX document build
# --------------------------------------------------------------------------- #


def test_build_vex_document_waived_and_unwaived() -> None:
    waiver = ev._VulnWaiver(
        justification_text="not reachable",
        owner="o",
        status="approved",
        expires_at=None,
        cdx_justification="code_not_reachable",
    )
    doc = ev._build_vex_document(
        ["CVE-A", "CVE-B"],
        Path("osv.sarif.json"),
        waivers={"CVE-A": waiver},
        references={"CVE-B": ["https://osv.dev/CVE-B"]},
    )
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert by_id["CVE-A"]["analysis"]["state"] == "not_affected"
    assert by_id["CVE-A"]["analysis"]["justification"] == "code_not_reachable"
    assert by_id["CVE-B"]["analysis"]["state"] == "in_triage"
    assert by_id["CVE-B"]["advisories"] == [{"url": "https://osv.dev/CVE-B"}]


# --------------------------------------------------------------------------- #
# structural validation
# --------------------------------------------------------------------------- #


def test_validate_vex_structure_ok() -> None:
    doc = ev._build_vex_document(["CVE-X"], Path("s.json"))
    # in_triage default isn't an error for structure (state is in allowed set).
    assert ev._validate_vex_structure(doc) == []


def test_validate_vex_structure_errors() -> None:
    bad = {"bomFormat": "X", "specVersion": "1.4", "version": 2, "vulnerabilities": "nope"}
    errs = ev._validate_vex_structure(bad)
    assert any("bomFormat" in e for e in errs)
    assert any("specVersion" in e for e in errs)
    assert any("version must be 1" in e for e in errs)
    assert any("must be an array" in e for e in errs)


def test_validate_vex_vuln_branches() -> None:
    assert ev._validate_vex_vuln(0, "notdict") == ["vulnerabilities[0] must be an object"]
    errs = ev._validate_vex_vuln(1, {"id": "", "analysis": {"state": "bogus", "justification": "bad"}})
    assert any("id missing" in e for e in errs)
    assert any("state=" in e for e in errs)
    assert any("justification=" in e for e in errs)
    assert ev._validate_vex_vuln(2, {"id": "CVE-1"}) == ["vulnerabilities[2].analysis missing"]
