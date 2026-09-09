"""Unit tests for the Semgrep adapter (no real Semgrep binary required).

All subprocess / PATH interactions are monkeypatched so the suite exercises
every status branch (ok / not_available / error / timeout) and the JSON
normalization edge cases deterministically.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure.scanners import semgrep_adapter as sa


class _FakeProc:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _result_record(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "check_id": "python.lang.security.audit.dangerous-exec",
        "path": "src/app.py",
        "start": {"line": 10},
        "end": {"line": 12},
        "extra": {
            "severity": "error",
            "message": "  dangerous exec  ",
            "metadata": {"cwe": ["CWE-94"], "owasp": "A03:2021"},
        },
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# is_available / _semgrep_version / _now_iso_utc
# --------------------------------------------------------------------------- #


def test_is_available_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    assert sa.is_available() is True


def test_is_available_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: None)
    assert sa.is_available() is False


def test_semgrep_version_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: None)
    assert sa._semgrep_version() is None


def test_semgrep_version_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa.subprocess, "run", lambda *a, **k: _FakeProc(stdout="1.2.3\n"))
    assert sa._semgrep_version() == "1.2.3"


def test_semgrep_version_blank_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa.subprocess, "run", lambda *a, **k: _FakeProc(stdout="   "))
    assert sa._semgrep_version() is None


def test_semgrep_version_swallows_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")

    def _boom(*_a: Any, **_k: Any) -> None:
        raise OSError("nope")

    monkeypatch.setattr(sa.subprocess, "run", _boom)
    assert sa._semgrep_version() is None


def test_semgrep_version_swallows_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")

    def _to(*_a: Any, **_k: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=15)

    monkeypatch.setattr(sa.subprocess, "run", _to)
    assert sa._semgrep_version() is None


def test_now_iso_utc_shape() -> None:
    val = sa._now_iso_utc()
    assert val.endswith("Z")
    assert "T" in val


# --------------------------------------------------------------------------- #
# _normalize_finding
# --------------------------------------------------------------------------- #


def test_normalize_finding_full() -> None:
    f = sa._normalize_finding(_result_record())
    assert f is not None
    assert f.rule_id.endswith("dangerous-exec")
    assert f.severity == "ERROR"
    assert f.message == "dangerous exec"
    assert f.file == "src/app.py"
    assert f.line_start == 10
    assert f.line_end == 12
    assert f.cwe == ["CWE-94"]
    assert f.owasp == ["A03:2021"]


def test_normalize_finding_rule_id_alias() -> None:
    rec = _result_record()
    del rec["check_id"]
    rec["rule_id"] = "alt.rule"
    f = sa._normalize_finding(rec)
    assert f is not None
    assert f.rule_id == "alt.rule"


@pytest.mark.parametrize("missing", ["rule", "path"])
def test_normalize_finding_missing_required_returns_none(missing: str) -> None:
    rec = _result_record()
    if missing == "rule":
        del rec["check_id"]
    else:
        rec["path"] = 123  # wrong type
    assert sa._normalize_finding(rec) is None


def test_normalize_finding_defaults_when_extra_absent() -> None:
    rec = {"check_id": "r", "path": "p"}
    f = sa._normalize_finding(rec)
    assert f is not None
    assert f.severity == "INFO"
    assert f.message == ""
    assert f.cwe == []
    assert f.owasp == []
    assert f.line_start == 0
    assert f.line_end == 0


def test_normalize_finding_cwe_owasp_list_and_garbage() -> None:
    rec = _result_record()
    rec["extra"]["metadata"] = {"cwe": ["CWE-1", 5, "CWE-2"], "owasp": 99}
    f = sa._normalize_finding(rec)
    assert f is not None
    assert f.cwe == ["CWE-1", "CWE-2"]  # non-str dropped
    assert f.owasp == []  # non-list/str -> empty


def test_normalize_finding_cwe_string_and_owasp_garbage() -> None:
    rec = _result_record()
    rec["extra"]["metadata"] = {"cwe": "CWE-79", "owasp": ["A01"]}
    f = sa._normalize_finding(rec)
    assert f is not None
    assert f.cwe == ["CWE-79"]  # scalar str promoted to list
    assert f.owasp == ["A01"]


def test_normalize_finding_cwe_garbage_type() -> None:
    rec = _result_record()
    rec["extra"]["metadata"] = {"cwe": 42}
    f = sa._normalize_finding(rec)
    assert f is not None
    assert f.cwe == []


# --------------------------------------------------------------------------- #
# _parse_semgrep_findings
# --------------------------------------------------------------------------- #


def test_parse_findings_blank_returns_empty() -> None:
    assert sa._parse_semgrep_findings("   ") == []


def test_parse_findings_bad_json_returns_none() -> None:
    assert sa._parse_semgrep_findings("{not json") is None


def test_parse_findings_skips_non_dict_and_invalid() -> None:
    payload = {"results": [_result_record(), "junk", {"no": "fields"}]}
    out = sa._parse_semgrep_findings(json.dumps(payload))
    assert out is not None
    assert len(out) == 1


# --------------------------------------------------------------------------- #
# run_semgrep
# --------------------------------------------------------------------------- #


def test_run_semgrep_rejects_non_directory(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="not a directory"):
        sa.run_semgrep(f)


def test_run_semgrep_not_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: None)
    out = sa.run_semgrep(tmp_path)
    assert out.status == "not_available"
    assert out.version is None
    assert "not found" in out.raw_stderr


def test_run_semgrep_ok_with_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.0.0")
    payload = {"results": [_result_record()]}
    captured: dict[str, Any] = {}

    def _run(argv: list[str], **_k: Any) -> _FakeProc:
        captured["argv"] = argv
        return _FakeProc(stdout=json.dumps(payload), returncode=1)  # 1 = findings present

    monkeypatch.setattr(sa.subprocess, "run", _run)
    out = sa.run_semgrep(tmp_path, rulesets=("p/owasp-top-ten",))
    assert out.status == "ok"
    assert out.version == "1.0.0"
    assert len(out.findings) == 1
    # rulesets are forwarded as --config args
    assert "--config" in captured["argv"]
    assert "p/owasp-top-ten" in captured["argv"]


def test_run_semgrep_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.0.0")

    def _to(*_a: Any, **_k: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=1, stderr="partial")

    monkeypatch.setattr(sa.subprocess, "run", _to)
    out = sa.run_semgrep(tmp_path)
    assert out.status == "timeout"
    assert out.raw_stderr == "partial"


def test_run_semgrep_timeout_non_str_stderr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: None)

    def _to(*_a: Any, **_k: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=1, stderr=b"bytes")

    monkeypatch.setattr(sa.subprocess, "run", _to)
    out = sa.run_semgrep(tmp_path)
    assert out.status == "timeout"
    assert out.raw_stderr == ""


def test_run_semgrep_scanner_error_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.0.0")
    monkeypatch.setattr(sa.subprocess, "run", lambda *a, **k: _FakeProc(stderr="bad ruleset", returncode=2))
    out = sa.run_semgrep(tmp_path)
    assert out.status == "error"
    assert out.raw_stderr == "bad ruleset"


def test_run_semgrep_unparseable_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.0.0")
    monkeypatch.setattr(sa.subprocess, "run", lambda *a, **k: _FakeProc(stdout="{not json", returncode=0))
    out = sa.run_semgrep(tmp_path)
    assert out.status == "error"
    assert "could not be parsed" in out.raw_stderr


# --------------------------------------------------------------------------- #
# render_evidence_payload / write_evidence
# --------------------------------------------------------------------------- #


def test_render_evidence_payload_counts_by_severity(tmp_path: Path) -> None:
    outcome = sa.SemgrepRunOutcome(
        status="ok",
        version="1.0.0",
        rulesets=["auto"],
        findings=[
            sa.SemgrepFinding("r1", "ERROR", "m", "a.py", 1, 1),
            sa.SemgrepFinding("r2", "ERROR", "m", "b.py", 2, 2),
            sa.SemgrepFinding("r3", "WARNING", "m", "c.py", 3, 3),
        ],
        scanned_at="2026-01-01T00:00:00Z",
    )
    payload = sa.render_evidence_payload(outcome, target=tmp_path)
    assert payload["schema_version"] == sa.EVIDENCE_SCHEMA_VERSION
    assert payload["findings_total"] == 3
    assert payload["findings_by_severity"] == {"ERROR": 2, "WARNING": 1}
    assert payload["attested_at"] == "2026-01-01T00:00:00Z"
    assert payload["attested_by"] == "oss-policy-kit scan-sast"
    assert len(payload["findings"]) == 3


def test_write_evidence_creates_dir_and_file(tmp_path: Path) -> None:
    payload = {"schema_version": sa.EVIDENCE_SCHEMA_VERSION, "findings": []}
    out = sa.write_evidence(payload, repo_root=tmp_path)
    assert out.exists()
    assert out.name == sa.EVIDENCE_FILENAME
    assert out.parent == (tmp_path / ".oss-policy-kit" / "evidence").resolve()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == sa.EVIDENCE_SCHEMA_VERSION


# --------------------------------------------------------------------------- #
# A failed scan has to leave the operator something to read
# --------------------------------------------------------------------------- #


def test_a_failure_that_speaks_on_stdout_is_still_recorded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`scan-sast` answers a failed scan by sending the operator to the evidence file.

    On Windows a broken Semgrep exits 2 having written the literal ``<ERROR: missing output>``
    to **stdout**, with stderr empty. Measured against semgrep 1.163.0 on the documented
    `scan-sast --target .` quick start: exit 2, `raw_stderr_excerpt: ""`. The command pointed
    at a file whose only diagnostic field was blank, which is the same dead end the ruleset
    default in this module was chosen to remove.
    """

    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.163.0")
    monkeypatch.setattr(
        sa.subprocess,
        "run",
        lambda *_a, **_k: _FakeProc(stdout="<ERROR: missing output>\n", stderr="", returncode=2),
    )

    outcome = sa.run_semgrep(tmp_path)
    payload = sa.render_evidence_payload(outcome, target=tmp_path)

    assert outcome.status == "error"
    diagnostics = payload["diagnostics"]
    assert diagnostics["exit_code"] == 2
    assert "<ERROR: missing output>" in diagnostics["raw_stdout_excerpt"]
    assert any(str(value).strip() for value in diagnostics.values()), (
        "every diagnostic field is blank, so the evidence file the CLI points at says nothing"
    )


def test_a_failure_that_speaks_on_stderr_keeps_speaking_there(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ordinary failure path is unchanged: stderr is still where a normal error lands."""

    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.163.0")
    monkeypatch.setattr(
        sa.subprocess,
        "run",
        lambda *_a, **_k: _FakeProc(stdout="", stderr="invalid rule config\n", returncode=7),
    )

    payload = sa.render_evidence_payload(sa.run_semgrep(tmp_path), target=tmp_path)

    assert payload["diagnostics"]["raw_stderr_excerpt"] == "invalid rule config\n"
    assert payload["diagnostics"]["exit_code"] == 7


def test_unparseable_json_records_what_was_printed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "Semgrep JSON output could not be parsed" is a claim; the bytes that failed back it up."""

    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.163.0")
    monkeypatch.setattr(
        sa.subprocess,
        "run",
        lambda *_a, **_k: _FakeProc(stdout="not json at all", stderr="", returncode=0),
    )

    payload = sa.render_evidence_payload(sa.run_semgrep(tmp_path), target=tmp_path)

    assert payload["status"] == "error"
    assert payload["diagnostics"]["raw_stdout_excerpt"] == "not json at all"


def test_the_failure_line_names_the_scanner_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading the file is a second step; the code the scanner returned fits on the first."""

    from typer.testing import CliRunner

    from oss_policy_kit.cli.main import app

    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.163.0")
    monkeypatch.setattr(
        sa.subprocess,
        "run",
        lambda *_a, **_k: _FakeProc(stdout="<ERROR: missing output>\n", stderr="", returncode=2),
    )

    result = CliRunner().invoke(app, ["scan-sast", "--target", str(tmp_path)])

    assert result.exit_code == 2
    assert "semgrep exit 2" in result.output.replace("\n", " ")


def test_the_evidence_a_failed_scan_writes_still_matches_the_published_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """New diagnostic keys are only safe if the shipped schema still accepts the file."""

    import json as _json

    import jsonschema

    from oss_policy_kit.application.loader import bundled_kit_root

    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.163.0")
    monkeypatch.setattr(
        sa.subprocess,
        "run",
        lambda *_a, **_k: _FakeProc(stdout="<ERROR: missing output>\n", stderr="", returncode=2),
    )

    payload = sa.render_evidence_payload(sa.run_semgrep(tmp_path), target=tmp_path)
    schema = _json.loads(
        (bundled_kit_root() / "schema" / "evidence-sast-semgrep.schema.json").read_text(encoding="utf-8")
    )

    jsonschema.validate(payload, schema)
