"""Smoke tests for ``oss-policy-kit scan-k8s``."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "scan-k8s", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


_VULNERABLE = (
    "apiVersion: apps/v1\n"
    "kind: Deployment\n"
    "metadata:\n"
    "  name: bad\n"
    "  namespace: default\n"
    "spec:\n"
    "  template:\n"
    "    spec:\n"
    "      hostNetwork: true\n"
    "      containers:\n"
    "        - name: app\n"
    "          image: nginx\n"
    "          securityContext:\n"
    "            privileged: true\n"
)


def test_scan_k8s_human_writes_evidence(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_VULNERABLE, encoding="utf-8")
    proc = _run("--target", str(tmp_path), cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "scan-k8s:" in proc.stdout
    evidence = tmp_path / ".oss-policy-kit" / "evidence" / "k8s-baseline.json"
    assert evidence.is_file()
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["status"] == "ok"
    assert payload["findings_total"] >= 2
    assert payload["schema_version"].startswith("oss-policy-kit/evidence/k8s-baseline/")
    assert payload["attested_by"] == "oss-policy-kit scan-k8s"


def test_scan_k8s_json_format_valid(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_VULNERABLE, encoding="utf-8")
    proc = _run("--target", str(tmp_path), "--format", "json", cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    parsed = json.loads(proc.stdout)
    assert parsed["status"] == "ok"
    assert parsed["findings_total"] >= 2


def test_scan_k8s_handles_no_yaml_files(tmp_path: Path) -> None:
    proc = _run("--target", str(tmp_path), cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    evidence = tmp_path / ".oss-policy-kit" / "evidence" / "k8s-baseline.json"
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["status"] == "ok"
    assert payload["findings_total"] == 0


def test_scan_k8s_bad_format_rejected(tmp_path: Path) -> None:
    proc = _run("--target", str(tmp_path), "--format", "yaml", cwd=tmp_path)
    assert proc.returncode != 0
    assert "human" in proc.stderr or "json" in proc.stderr
