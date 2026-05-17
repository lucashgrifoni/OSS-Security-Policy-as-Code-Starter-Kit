"""emit-vex subcommand: CycloneDX VEX 1.6 emission from OSV-Scanner SARIF."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from oss_policy_kit.cli.emit_vex import (
    _build_vex_document,
    _extract_vuln_ids_from_sarif,
)

# --- Helper unit tests ------------------------------------------------------


def _write_sarif(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "osv.sarif.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_extract_vuln_ids_from_rules(tmp_path: Path) -> None:
    p = _write_sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "GHSA-m5pq-gvj9-9vr8"},
                                {"id": "CVE-2024-12345"},
                                {"id": "RUSTSEC-2022-0013"},
                            ]
                        }
                    },
                    "results": [],
                }
            ]
        },
    )
    ids, err = _extract_vuln_ids_from_sarif(p)
    assert err is None
    assert ids == ["CVE-2024-12345", "GHSA-m5pq-gvj9-9vr8", "RUSTSEC-2022-0013"]


def test_extract_vuln_ids_dedupes_across_rules_and_results(tmp_path: Path) -> None:
    p = _write_sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {"driver": {"rules": [{"id": "CVE-1"}]}},
                    "results": [{"ruleId": "CVE-1"}, {"ruleId": "CVE-2"}],
                }
            ]
        },
    )
    ids, err = _extract_vuln_ids_from_sarif(p)
    assert err is None
    assert ids == ["CVE-1", "CVE-2"]


def test_extract_vuln_ids_handles_empty_sarif(tmp_path: Path) -> None:
    p = _write_sarif(tmp_path, {"runs": []})
    ids, err = _extract_vuln_ids_from_sarif(p)
    assert err is None
    assert ids == []


def test_extract_vuln_ids_rejects_malformed_json(tmp_path: Path) -> None:
    p = tmp_path / "x.sarif.json"
    p.write_text("{ not json", encoding="utf-8")
    ids, err = _extract_vuln_ids_from_sarif(p)
    assert ids == []
    assert err and ("parse" in err.lower() or "json" in err.lower())


def test_extract_vuln_ids_rejects_missing_runs(tmp_path: Path) -> None:
    p = _write_sarif(tmp_path, {"foo": "bar"})
    ids, err = _extract_vuln_ids_from_sarif(p)
    assert ids == []
    assert err is not None


def test_build_vex_document_structure(tmp_path: Path) -> None:
    src = tmp_path / "fake.sarif.json"
    doc = _build_vex_document(["CVE-1", "GHSA-2"], src)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["version"] == 1
    assert "timestamp" in doc["metadata"]
    assert any(t["name"] == "oss-policy-kit emit-vex" for t in doc["metadata"]["tools"])
    assert len(doc["vulnerabilities"]) == 2
    for v in doc["vulnerabilities"]:
        assert v["analysis"]["state"] == "in_triage"
        assert "fill in state" in v["analysis"]["detail"]


# --- Subcommand integration tests ------------------------------------------


def _run_cli(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_emit_vex_stdout_with_three_findings(tmp_path: Path) -> None:
    sarif = _write_sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "GHSA-aaaa-bbbb-cccc"},
                                {"id": "CVE-2024-99999"},
                            ]
                        }
                    },
                    "results": [],
                }
            ]
        },
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif)])
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    ids = sorted(v["id"] for v in doc["vulnerabilities"])
    assert ids == ["CVE-2024-99999", "GHSA-aaaa-bbbb-cccc"]


def test_emit_vex_writes_to_output_file(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": [{"id": "CVE-2024-1"}]}}, "results": []}]})
    out = tmp_path / "vex.cyclonedx.json"
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--output", str(out)])
    assert proc.returncode == 0
    assert out.is_file()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["specVersion"] == "1.6"
    assert len(doc["vulnerabilities"]) == 1


def test_emit_vex_returns_exit_2_when_sarif_missing(tmp_path: Path) -> None:
    proc = _run_cli(["emit-vex", "--osv-sarif", str(tmp_path / "missing.sarif.json")])
    assert proc.returncode == 2


def test_emit_vex_returns_exit_2_when_sarif_malformed(tmp_path: Path) -> None:
    bad = tmp_path / "broken.sarif.json"
    bad.write_text("{ not json", encoding="utf-8")
    proc = _run_cli(["emit-vex", "--osv-sarif", str(bad)])
    assert proc.returncode == 2


def test_emit_vex_empty_sarif_returns_valid_document_with_no_vulns(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]})
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif)])
    assert proc.returncode == 0
    doc = json.loads(proc.stdout)
    assert doc["vulnerabilities"] == []
    assert doc["specVersion"] == "1.6"


# --- v0.2: per-CVE waiver integration --------------------------------------


def _write_waivers(tmp_path: Path, entries: list[dict]) -> Path:
    import yaml

    p = tmp_path / "waivers.yaml"
    p.write_text(
        yaml.safe_dump({"version": 1, "waivers": entries}, sort_keys=False),
        encoding="utf-8",
    )
    return p


def test_emit_vex_v02_applies_vulnerability_id_waiver(tmp_path: Path) -> None:
    sarif = _write_sarif(
        tmp_path,
        {"runs": [{"tool": {"driver": {"rules": [{"id": "CVE-2024-1"}, {"id": "CVE-2024-2"}]}}, "results": []}]},
    )
    waivers = _write_waivers(
        tmp_path,
        [
            {
                "vulnerability_ids": ["CVE-2024-1"],
                "justification": "code_not_reachable in our integration path",
                "owner": "appsec@example.org",
                "status": "approved",
                "expires_at": "2027-12-31",
                "vex_justification": "code_not_reachable",
            }
        ],
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(waivers)])
    assert proc.returncode == 0
    doc = json.loads(proc.stdout)
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert by_id["CVE-2024-1"]["analysis"]["state"] == "not_affected"
    assert by_id["CVE-2024-1"]["analysis"]["justification"] == "code_not_reachable"
    assert "code_not_reachable" in by_id["CVE-2024-1"]["analysis"]["detail"]
    assert by_id["CVE-2024-2"]["analysis"]["state"] == "in_triage"


def test_emit_vex_v02_ignores_control_id_only_waivers(tmp_path: Path) -> None:
    """control_id-only waivers steer the gate, not the VEX. They are skipped here."""
    sarif = _write_sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": [{"id": "GHSA-aaaa"}]}}, "results": []}]})
    waivers = _write_waivers(
        tmp_path,
        [
            {
                "control_id": "SAST-OSV-068",
                "justification": "Accepted at gate level",
                "owner": "ops",
                "status": "approved",
            }
        ],
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(waivers)])
    assert proc.returncode == 0
    doc = json.loads(proc.stdout)
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_emit_vex_v02_drops_invalid_vex_justification(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": [{"id": "CVE-X"}]}}, "results": []}]})
    waivers = _write_waivers(
        tmp_path,
        [
            {
                "vulnerability_ids": ["CVE-X"],
                "justification": "we accept",
                "owner": "x@example",
                "vex_justification": "totally_made_up_value",
            }
        ],
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(waivers)])
    assert proc.returncode == 0
    doc = json.loads(proc.stdout)
    v = doc["vulnerabilities"][0]
    # State still becomes not_affected (waiver is otherwise valid);
    # justification enum is omitted because the supplied value is invalid.
    assert v["analysis"]["state"] == "not_affected"
    assert "justification" not in v["analysis"]


def test_emit_vex_v02_validate_passes_on_well_formed_output(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": [{"id": "CVE-A"}]}}, "results": []}]})
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--validate"])
    assert proc.returncode == 0, f"stderr={proc.stderr}"


def test_emit_vex_v02_include_references_embeds_helpuri(tmp_path: Path) -> None:
    sarif = _write_sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "GHSA-zzzz", "helpUri": "https://osv.dev/vulnerability/GHSA-zzzz"},
                            ]
                        }
                    },
                    "results": [],
                }
            ]
        },
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--include-references"])
    assert proc.returncode == 0
    doc = json.loads(proc.stdout)
    v = doc["vulnerabilities"][0]
    assert v["advisories"] == [{"url": "https://osv.dev/vulnerability/GHSA-zzzz"}]


def test_emit_vex_v02_omits_advisories_when_flag_off(tmp_path: Path) -> None:
    sarif = _write_sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "GHSA-zzzz", "helpUri": "https://osv.dev/vulnerability/GHSA-zzzz"},
                            ]
                        }
                    },
                    "results": [],
                }
            ]
        },
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif)])
    assert proc.returncode == 0
    doc = json.loads(proc.stdout)
    assert "advisories" not in doc["vulnerabilities"][0]


def test_emit_vex_v02_expired_waiver_is_ignored(tmp_path: Path) -> None:
    sarif = _write_sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": [{"id": "CVE-OLD"}]}}, "results": []}]})
    waivers = _write_waivers(
        tmp_path,
        [
            {
                "vulnerability_ids": ["CVE-OLD"],
                "justification": "Was accepted",
                "owner": "x@example",
                "expires_at": "2020-01-01",
            }
        ],
    )
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(waivers)])
    assert proc.returncode == 0
    doc = json.loads(proc.stdout)
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_emit_vex_warns_when_waiver_id_does_not_match_sarif(tmp_path: Path) -> None:
    """If --waivers carries vulnerability_ids that don't appear in the SARIF,
    emit-vex must warn so the user spots typos or CVE/GHSA alias mismatches."""
    sarif = _write_sarif(
        tmp_path,
        {"runs": [{"tool": {"driver": {"rules": [{"id": "CVE-2024-REAL"}]}}, "results": []}]},
    )
    waivers = _write_waivers(
        tmp_path,
        [
            {
                "vulnerability_ids": ["CVE-2024-TYPO", "GHSA-aaaa-bbbb-cccc"],
                "justification": "stale waiver pointing at the wrong id",
                "owner": "appsec@example.org",
            }
        ],
    )
    out = tmp_path / "vex.json"
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(waivers), "--output", str(out)])
    assert proc.returncode == 0
    assert "did not match" in proc.stderr.lower()
    assert "CVE-2024-TYPO" in proc.stderr
    assert "GHSA-aaaa-bbbb-cccc" in proc.stderr
