"""v10.0.1 hotfix regressions for the correlate-findings surface (F2).

Each test pins one confirmed defect from the v10.0.1 raio-x so a future
refactor cannot silently reintroduce it. Functional coverage runs the CLI via
CliRunner and the pure normalizers/correlator directly; no network, no state.

Defects covered:
- X3-01  unreadable --waivers warning leaks the ABSOLUTE path -> basename only
- X3-02  non-list "waivers:" returns silently -> honest warning
- X7-02/X1-01  relative --output written to CWD instead of under --target
- X3-04  --enrichment-file resolves to CWD instead of --target
- X2-F5  non-dir --target error echoes the resolved abs path (leak)
- X2-F4  --target "" silently coerced to cwd -> clean exit-2
- X3-06  human view never shows a WAIVED marker
- X1-02  --enrichment-file help says "ranking rationale only" (understated)
- X3-05  out-of-range snapshot EPSS (999 / -1) warps ranking
- X2-F1  malformed results/findings CONTAINER still recorded status="ok"
- X4-02  build_findings_summary drops source-read accounting
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import Result
from typer.testing import CliRunner

from oss_policy_kit import __version__ as KIT_VERSION
from oss_policy_kit.application.finding_correlation import correlate
from oss_policy_kit.application.finding_normalization import normalize_kit_evidence
from oss_policy_kit.application.finding_sarif import normalize_sarif_sources
from oss_policy_kit.application.findings_report import build_findings_summary
from oss_policy_kit.application.vuln_waivers import load_vuln_waivers
from oss_policy_kit.cli.main import app, prepare_cli_args
from oss_policy_kit.domain.findings import (
    FindingLocation,
    FindingSource,
    NormalizedFinding,
    SeverityView,
)

runner = CliRunner()
_EVID = Path(".oss-policy-kit") / "evidence"
_SARIF = _EVID / "sast"


def _invoke(args: list[str]) -> Result:
    return runner.invoke(app, prepare_cli_args(args))


def _write(repo: Path, rel: str | Path, payload: object) -> None:
    p = repo / _EVID / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload), encoding="utf-8")


def _iac_evidence(findings: list[dict]) -> dict:
    return {
        "schema_version": "oss-policy-kit/evidence/iac-terraform/v1",
        "tool": "oss-policy-kit-iac-parser",
        "status": "ok",
        "target": "x",
        "scanned_at": "t",
        "attested_at": "t",
        "attested_by": "t",
        "findings_total": len(findings),
        "findings": findings,
    }


def _crit(rule: str = "IAC-TF-001") -> dict:
    return {
        "rule_id": rule,
        "severity": "CRITICAL",
        "message": "public bucket",
        "file": "main.tf",
        "resource_type": "aws_s3_bucket",
        "resource_name": "logs",
    }


def _osv_sarif(results: list[object]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "osv-scanner", "version": "2.0.0"}}, "results": results}],
    }


def _finding(cve: str, epss: float | None = None) -> NormalizedFinding:
    return NormalizedFinding(
        id="",
        sources=(FindingSource(tool="osv-scanner", source_path="s", rule=cve, severity_original="error", message="m"),),
        rule=cve,
        message="m",
        severity=SeverityView(normalized="high", by_source=(("osv-scanner", "error"),)),
        location=FindingLocation(),
        vulnerability_ids=(cve,),
        epss=epss,
    )


# --------------------------------------------------------------------------- #
# X3-01 + X3-02  waiver warnings: basename only, honest non-list warning
# --------------------------------------------------------------------------- #


def test_x3_01_unreadable_waivers_warning_has_no_abs_path(tmp_path: Path) -> None:
    # A file that exists but is not parseable YAML -> the read raises inside
    # load_vuln_waivers, producing the "Could not read waivers file ..." warning.
    secret_dir = tmp_path / "SECRET-USERNAME-dir"
    secret_dir.mkdir()
    bad = secret_dir / "waivers.yaml"
    bad.write_text("this: [is: not: valid: yaml", encoding="utf-8")

    _, warnings = load_vuln_waivers(bad)

    assert warnings, "an unreadable waivers file must warn"
    joined = " ".join(warnings)
    assert "waivers.yaml" in joined  # basename present
    assert "SECRET-USERNAME-dir" not in joined  # abs path / username NOT leaked
    assert str(secret_dir) not in joined


def test_x3_01_warning_reaches_artifact_without_abs_path(tmp_path: Path) -> None:
    # End-to-end: the warning lands in the shareable artifact extensions block.
    _write(tmp_path, "iac-terraform.json", _iac_evidence([_crit()]))
    secret_dir = tmp_path / "LEAKME"
    secret_dir.mkdir()
    bad = secret_dir / "waivers.yaml"
    bad.write_text(": : :\n\t- broken", encoding="utf-8")
    out = tmp_path / "findings.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--waivers", str(bad)])
    assert result.exit_code == 0, result.output
    artifact = json.loads(out.read_text(encoding="utf-8"))
    warns = artifact["extensions"]["waiver_warnings"]
    assert warns
    for w in warns:
        assert "LEAKME" not in w
        assert str(secret_dir) not in w


def test_x3_02_non_list_waivers_key_warns(tmp_path: Path) -> None:
    p = tmp_path / "waivers.yaml"
    p.write_text("waivers: not-a-list\n", encoding="utf-8")
    table, warnings = load_vuln_waivers(p)
    assert table == {}
    assert any("'waivers' is not a list" in w for w in warnings)


def test_x3_02_missing_waivers_key_stays_silent(tmp_path: Path) -> None:
    # A mapping with no "waivers:" key at all is not an error -> no warning.
    p = tmp_path / "waivers.yaml"
    p.write_text("other: value\n", encoding="utf-8")
    table, warnings = load_vuln_waivers(p)
    assert table == {}
    assert warnings == []


# --------------------------------------------------------------------------- #
# X7-02 / X1-01  relative --output anchors under --target, not CWD
# --------------------------------------------------------------------------- #


def test_x7_02_relative_output_written_under_target(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    _write(target, "iac-terraform.json", _iac_evidence([_crit()]))
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    result = _invoke(["correlate-findings", "--target", str(target)])
    assert result.exit_code == 0, result.output
    # Default relative --output lands under --target, NOT the current directory.
    assert (target / ".oss-policy-kit" / "findings.json").is_file()
    assert not (cwd / ".oss-policy-kit" / "findings.json").exists()


def test_x1_01_absolute_output_still_honored(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    out = tmp_path / "abs-out" / "findings.json"
    result = _invoke(["correlate-findings", "--target", str(target), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()


# --------------------------------------------------------------------------- #
# X3-04  --enrichment-file resolves under --target (parity with --waivers)
# --------------------------------------------------------------------------- #


def test_x3_04_relative_enrichment_resolves_under_target(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    snap = target / "enrich.json"
    snap.write_text(json.dumps({"as_of": "2026-06-01", "vulnerabilities": {}}), encoding="utf-8")
    out = tmp_path / "findings.json"
    # Run from a different cwd so a CWD-relative resolution would miss the file.
    other = tmp_path / "cwd"
    other.mkdir()
    monkeypatch.chdir(other)
    result = _invoke(
        ["correlate-findings", "--target", str(target), "--output", str(out), "--enrichment-file", "enrich.json"]
    )
    assert result.exit_code == 0, result.output
    artifact = json.loads(out.read_text(encoding="utf-8"))
    kinds = {s["kind"]: s["status"] for s in artifact["sources_read"]}
    assert kinds.get("enrichment-snapshot") == "ok"  # found under --target, read fine


def test_x3_04_relative_enrichment_missing_reports_clean_error(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    other = tmp_path / "cwd"
    other.mkdir()
    # Put the file only in CWD; because resolution is under --target it must NOT be found.
    (other / "enrich.json").write_text(json.dumps({"vulnerabilities": {}}), encoding="utf-8")
    monkeypatch.chdir(other)
    result = _invoke(
        [
            "correlate-findings",
            "--target",
            str(target),
            "--output",
            str(tmp_path / "f.json"),
            "--enrichment-file",
            "enrich.json",
        ]
    )
    assert result.exit_code == 2, result.output
    assert "--enrichment-file" in result.output
    assert "enrich.json" in result.output  # basename, not abs path
    assert str(other) not in result.output


# --------------------------------------------------------------------------- #
# X2-F5 / X2-F4  --target error hygiene
# --------------------------------------------------------------------------- #


def test_x2_f5_nondir_target_error_echoes_user_string_not_resolved_path(tmp_path: Path, monkeypatch) -> None:
    """A relative --target is echoed verbatim, never as its resolved absolute path (M-002).

    Echoing back the string the user typed is not a leak; resolving it is, because the
    resolved form exposes the cwd / home directory (and the OS username with it). The
    target must therefore be RELATIVE here: given an absolute --target the user's own
    string already is the absolute path, so there is nothing the error could withhold.
    """

    (tmp_path / "SECRET-HOME").mkdir()
    monkeypatch.chdir(tmp_path)
    result = _invoke(["correlate-findings", "--target", "SECRET-HOME/nope", "--output", str(tmp_path / "f.json")])
    assert result.exit_code == 2, result.output
    assert "is not a directory" in result.output
    assert "SECRET-HOME/nope" in result.output  # the user's own string, echoed verbatim
    # ...but never the resolved absolute form, which would carry the cwd / username.
    assert str((tmp_path / "SECRET-HOME" / "nope").resolve()) not in result.output
    assert str(tmp_path.resolve()) not in result.output
    assert "Traceback" not in result.output


def test_x2_f4_empty_target_rejected_cleanly(tmp_path: Path) -> None:
    result = _invoke(["correlate-findings", "--target", "", "--output", str(tmp_path / "f.json")])
    assert result.exit_code == 2, result.output
    assert "--target must not be empty" in result.output
    assert "Traceback" not in result.output


def test_x2_f4_whitespace_target_rejected_cleanly(tmp_path: Path) -> None:
    result = _invoke(["correlate-findings", "--target", "   ", "--output", str(tmp_path / "f.json")])
    assert result.exit_code == 2, result.output
    assert "--target must not be empty" in result.output


# --------------------------------------------------------------------------- #
# X3-06  WAIVED marker in the human view
# --------------------------------------------------------------------------- #


def test_x3_06_waived_finding_shows_marker(tmp_path: Path) -> None:
    _write(
        tmp_path,
        Path("sast") / "osv-scanner.sarif.json",
        _osv_sarif(
            [
                {
                    "ruleId": "CVE-2026-9999",
                    "level": "error",
                    "message": {"text": "vuln"},
                    "properties": {"kev": "true", "cve": "CVE-2026-9999"},
                }
            ]
        ),
    )
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        "waivers:\n"
        "  - vulnerability_ids: [CVE-2026-9999]\n"
        "    justification: accepted risk, not reachable\n"
        "    owner: appsec@example.com\n",
        encoding="utf-8",
    )
    out = tmp_path / "findings.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--waivers", str(waivers)])
    assert result.exit_code == 0, result.output  # KEV present but waived -> gate not tripped by default
    assert "WAIVED" in result.output
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["findings"][0]["waiver"]["waived"] is True


# --------------------------------------------------------------------------- #
# X1-02  enrichment help wording
# --------------------------------------------------------------------------- #


def test_x1_02_enrichment_help_states_it_reorders_rank() -> None:
    import inspect

    from oss_policy_kit.cli import correlate_findings as cf_module

    sig = inspect.signature(cf_module.correlate_findings_cmd)
    help_text = sig.parameters["enrichment_file"].default.help
    assert "ranking order/rationale only" in help_text
    assert "never changes finding fields, severities, gates, or control state" in help_text


# --------------------------------------------------------------------------- #
# X3-05  out-of-range snapshot EPSS ignored for ranking
# --------------------------------------------------------------------------- #


def _ranked_ids(findings: list[NormalizedFinding], enrichment: dict | None) -> list[str]:
    return [f.vulnerability_ids[0] for f in correlate(findings, enrichment).findings]


def test_x3_05_out_of_range_epss_does_not_change_ranking() -> None:
    a = _finding("CVE-2026-0001")
    b = _finding("CVE-2026-0002")
    baseline = _ranked_ids([a, b], None)

    for bogus in (999, -1, 42.0):
        enrichment = {"CVE-2026-0001": {"epss": bogus}}
        assert _ranked_ids([a, b], enrichment) == baseline, f"epss={bogus} must be ignored"


def test_x3_05_in_range_epss_still_ranks() -> None:
    a = _finding("CVE-2026-0001")
    b = _finding("CVE-2026-0002")
    # A valid EPSS on the second finding must lift it above the first.
    enrichment = {"CVE-2026-0002": {"epss": 0.9}}
    assert _ranked_ids([a, b], enrichment)[0] == "CVE-2026-0002"


# --------------------------------------------------------------------------- #
# X2-F1  malformed results/findings CONTAINER is not recorded as "ok"
# --------------------------------------------------------------------------- #


def test_x2_f1_malformed_sarif_results_container_not_ok(tmp_path: Path) -> None:
    p = tmp_path / _SARIF / "osv-scanner.sarif.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": "nope"}],
    }
    p.write_text(json.dumps(payload), encoding="utf-8")
    _findings, records = normalize_sarif_sources(tmp_path)
    osv = next(r for r in records if r.tool == "osv-scanner")
    assert osv.status != "ok"


def test_x2_f1_malformed_kit_findings_container_not_ok(tmp_path: Path) -> None:
    p = tmp_path / _EVID / "iac-terraform.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "oss-policy-kit/evidence/iac-terraform/v1",
        "tool": "oss-policy-kit-iac-parser",
        "status": "ok",
        "findings": 12345,  # container is a number, not a list
    }
    p.write_text(json.dumps(payload), encoding="utf-8")
    _findings, records = normalize_kit_evidence(tmp_path)
    tf = next(r for r in records if r.path.endswith("iac-terraform.json"))
    assert tf.status != "ok"


def test_x2_f1_genuinely_empty_containers_stay_ok(tmp_path: Path) -> None:
    # results:[] / findings:[] must NOT regress into "error".
    sp = tmp_path / _SARIF / "osv-scanner.sarif.json"
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps(_osv_sarif([])), encoding="utf-8")
    _, sarif_records = normalize_sarif_sources(tmp_path)
    assert next(r for r in sarif_records if r.tool == "osv-scanner").status == "ok"

    kp = tmp_path / _EVID / "iac-terraform.json"
    kp.write_text(json.dumps(_iac_evidence([])), encoding="utf-8")
    _, kit_records = normalize_kit_evidence(tmp_path)
    assert next(r for r in kit_records if r.path.endswith("iac-terraform.json")).status == "ok"


# --------------------------------------------------------------------------- #
# X4-02  build_findings_summary carries source-read accounting
# --------------------------------------------------------------------------- #


def test_x4_02_summary_has_source_read_accounting(tmp_path: Path) -> None:
    _write(tmp_path, "iac-terraform.json", _iac_evidence([_crit()]))
    summary = build_findings_summary(tmp_path, kit_version=KIT_VERSION)
    assert "sources_total" in summary
    assert "sources_ok" in summary
    assert summary["sources_total"] >= 1
    assert summary["sources_ok"] >= 1


def test_x4_02_all_corrupt_evidence_is_distinguishable_from_clean(tmp_path: Path) -> None:
    # Present-but-corrupt evidence: findings_total==0 but sources_ok < sources_total,
    # so a consumer can tell "unreadable" from a genuinely clean run.
    p = tmp_path / _EVID / "iac-terraform.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ not valid json", encoding="utf-8")
    summary = build_findings_summary(tmp_path, kit_version=KIT_VERSION)
    assert summary["findings_total"] == 0
    assert summary["sources_ok"] < summary["sources_total"]
