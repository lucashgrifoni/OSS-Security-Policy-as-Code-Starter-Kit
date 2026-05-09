"""Smoke tests for ``oss-policy-kit scan-iac``."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "scan-iac", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_scan_iac_human_writes_evidence(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" { acl = "public-read" }\n', encoding="utf-8")
    proc = _run("--target", str(tmp_path), cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "scan-iac:" in proc.stdout
    evidence = tmp_path / ".oss-policy-kit" / "evidence" / "iac-terraform.json"
    assert evidence.is_file()
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["status"] == "ok"
    assert payload["findings_total"] >= 1
    assert payload["schema_version"].startswith("oss-policy-kit/evidence/iac-terraform/")


def test_scan_iac_json_format_valid(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" { acl = "private" }\n', encoding="utf-8")
    proc = _run("--target", str(tmp_path), "--format", "json", cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    parsed = json.loads(proc.stdout)
    assert parsed["status"] == "ok"
    assert parsed["attested_by"] == "oss-policy-kit scan-iac"


def test_scan_iac_handles_no_tf_files(tmp_path: Path) -> None:
    proc = _run("--target", str(tmp_path), cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    evidence = tmp_path / ".oss-policy-kit" / "evidence" / "iac-terraform.json"
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["status"] == "ok"
    assert payload["findings_total"] == 0


def test_scan_iac_bad_format_rejected(tmp_path: Path) -> None:
    proc = _run("--target", str(tmp_path), "--format", "yaml", cwd=tmp_path)
    assert proc.returncode != 0
    assert "human" in proc.stderr or "json" in proc.stderr
