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
    assert f is not None and f.rule_id == "alt.rule"


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
    assert f.cwe == [] and f.owasp == []
    assert f.line_start == 0 and f.line_end == 0


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
    assert f is not None and f.cwe == []  # non-list/str -> empty


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
    assert out is not None and len(out) == 1


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
    monkeypatch.setattr(
        sa.subprocess, "run", lambda *a, **k: _FakeProc(stderr="bad ruleset", returncode=2)
    )
    out = sa.run_semgrep(tmp_path)
    assert out.status == "error"
    assert out.raw_stderr == "bad ruleset"


def test_run_semgrep_unparseable_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sa.shutil, "which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(sa, "_semgrep_version", lambda: "1.0.0")
    monkeypatch.setattr(
        sa.subprocess, "run", lambda *a, **k: _FakeProc(stdout="{not json", returncode=0)
    )
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
