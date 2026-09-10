"""v10.0.2 regression: emit-vex hardening (raio-x findings).

Covers five confirmed defects in ``oss_policy_kit.cli.emit_vex``:

- #1 / #2 / #13 — a non-UTF-8 ``--osv-sarif`` (UTF-16LE / UTF-16BE / raw binary)
  crashed to exit 3 (``UnicodeDecodeError`` escaping the ``OSError``-only guard
  in ``_extract_sarif_data``). It must instead exit 2 with a clean one-line
  validation message and no traceback — the same contract the UTF-8-BOM case
  already honours. Reachable via the tool's own doc hint
  (``osv-scanner ... > osv-scanner.sarif.json``) which on Windows PowerShell
  writes UTF-16. Applies to both ``--format cyclonedx`` and ``--format openvex``.
- #14 / #19 — the CycloneDX ``metadata.timestamp`` and the OpenVEX statement
  ``timestamp`` + document ``@id`` called ``datetime.now(UTC)``, ignoring
  ``SOURCE_DATE_EPOCH``. Under a pinned epoch two runs must be byte-identical
  (reproducible-build determinism fence) and must stamp the pinned date rather
  than leaking today's date.

Each test below fails against the pre-fix emit_vex.py and passes after it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from oss_policy_kit.cli.emit_vex import (
    _build_openvex_document,
    _build_vex_document,
    _extract_sarif_data,
)

# A distinct epoch from the suite-wide conftest pin (1781524800) so the assertion
# is unambiguous: any leak of "now" or the conftest value fails the test.
_PINNED_EPOCH = 1700000000
_PINNED_Z = datetime.fromtimestamp(_PINNED_EPOCH, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

_SARIF_DOC = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "osv-scanner",
                    "rules": [{"id": "CVE-2024-0001", "helpUri": "https://osv.dev/CVE-2024-0001"}],
                }
            },
            "results": [{"ruleId": "CVE-2024-0001"}],
        }
    ],
}


def _run_cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        env=env,
    )


def _write_utf8_sarif(tmp_path: Path) -> Path:
    p = tmp_path / "osv.sarif.json"
    p.write_text(json.dumps(_SARIF_DOC, indent=2), encoding="utf-8")
    return p


def _write_encoded_sarif(tmp_path: Path, name: str, encoding: str) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(_SARIF_DOC, indent=2), encoding=encoding)
    return p


# --------------------------------------------------------------------------- #
# #1 / #2 / #13 — non-UTF-8 SARIF must exit 2 cleanly, never exit 3.
# --------------------------------------------------------------------------- #


def test_extract_sarif_data_returns_error_not_raises_on_utf16(tmp_path: Path) -> None:
    """#1: the read helper returns an error string (no UnicodeDecodeError raised)."""

    sarif = _write_encoded_sarif(tmp_path, "osv.sarif.json", "utf-16")  # UTF-16LE + BOM
    ids, refs, err = _extract_sarif_data(sarif)
    assert ids == []
    assert refs == {}
    assert err is not None
    assert "UTF-8" in err


def test_emit_vex_utf16le_sarif_exits_2_not_3(tmp_path: Path) -> None:
    """#1: --format cyclonedx on a UTF-16LE SARIF exits 2 with a clean message."""

    sarif = _write_encoded_sarif(tmp_path, "osv-le.sarif.json", "utf-16")
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(tmp_path / "none.yaml")])
    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr
    assert "not valid UTF-8" in proc.stderr


def test_emit_vex_utf16be_sarif_exits_2_not_3(tmp_path: Path) -> None:
    """#2: a UTF-16BE (leading 0xfe/0xff) SARIF exits 2, not 3."""

    sarif = _write_encoded_sarif(tmp_path, "osv-be.sarif.json", "utf-16-be")
    # utf-16-be via write_text has no BOM; prepend one so the file is real UTF-16BE.
    sarif.write_bytes(b"\xfe\xff" + sarif.read_bytes())
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(tmp_path / "none.yaml")])
    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr


def test_emit_vex_binary_sarif_exits_2_not_3(tmp_path: Path) -> None:
    """#1: raw non-UTF-8 binary content exits 2 with no traceback."""

    sarif = tmp_path / "osv-bin.sarif.json"
    sarif.write_bytes(b"\xff\xfe\x00\x01\x02\x80\x81garbage")
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(tmp_path / "none.yaml")])
    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr


def test_emit_vex_utf16_sarif_openvex_exits_2_not_3(tmp_path: Path) -> None:
    """#13: the same crash under --format openvex also exits 2, not 3."""

    sarif = _write_encoded_sarif(tmp_path, "osv-ov.sarif.json", "utf-16")
    proc = _run_cli(
        [
            "emit-vex",
            "--osv-sarif",
            str(sarif),
            "--format",
            "openvex",
            "--product",
            "pkg:pypi/acme@1.2.3",
            "--waivers",
            str(tmp_path / "none.yaml"),
        ]
    )
    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr


def test_emit_vex_utf16_error_message_does_not_leak_absolute_path(tmp_path: Path) -> None:
    """M-002: the clean error must not echo the resolved absolute path/home/username."""

    sarif = _write_encoded_sarif(tmp_path, "osv.sarif.json", "utf-16")
    proc = _run_cli(["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(tmp_path / "none.yaml")])
    assert proc.returncode == 2, proc.stderr + proc.stdout
    assert str(sarif.resolve()) not in proc.stderr


# --------------------------------------------------------------------------- #
# #14 / #19 — VEX timestamps must honour SOURCE_DATE_EPOCH (determinism fence).
# --------------------------------------------------------------------------- #


def test_cyclonedx_metadata_timestamp_honors_source_date_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#19: CycloneDX metadata.timestamp is stamped from SOURCE_DATE_EPOCH, not now()."""

    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_PINNED_EPOCH))
    doc = _build_vex_document(["CVE-2024-0001"], tmp_path / "src.sarif.json")
    assert doc["metadata"]["timestamp"] == _PINNED_Z


def test_openvex_timestamp_and_id_honor_source_date_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#19: OpenVEX timestamp AND document @id are stamped from SOURCE_DATE_EPOCH."""

    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(_PINNED_EPOCH))
    doc = _build_openvex_document(["CVE-2024-0001"], tmp_path / "src.sarif.json", product="pkg:pypi/acme@1.2.3")
    assert doc["timestamp"] == _PINNED_Z
    assert doc["@id"].endswith(_PINNED_Z)


def test_cyclonedx_output_byte_identical_under_pinned_epoch(tmp_path: Path) -> None:
    """#14: two CycloneDX runs under a pinned epoch are byte-identical and stamp the epoch."""

    sarif = _write_utf8_sarif(tmp_path)
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(_PINNED_EPOCH), "NO_COLOR": "1"}
    args = ["emit-vex", "--osv-sarif", str(sarif), "--waivers", str(tmp_path / "none.yaml")]
    run1 = _run_cli(args, env=env)
    run2 = _run_cli(args, env=env)
    assert run1.returncode == 0, f"stderr={run1.stderr}"
    assert run2.returncode == 0, f"stderr={run2.stderr}"
    assert run1.stdout == run2.stdout
    assert _PINNED_Z in run1.stdout


def test_openvex_output_byte_identical_under_pinned_epoch(tmp_path: Path) -> None:
    """#14: two OpenVEX runs under a pinned epoch are byte-identical and stamp the epoch."""

    sarif = _write_utf8_sarif(tmp_path)
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(_PINNED_EPOCH), "NO_COLOR": "1"}
    args = [
        "emit-vex",
        "--osv-sarif",
        str(sarif),
        "--format",
        "openvex",
        "--product",
        "pkg:pypi/acme@1.2.3",
        "--waivers",
        str(tmp_path / "none.yaml"),
    ]
    run1 = _run_cli(args, env=env)
    run2 = _run_cli(args, env=env)
    assert run1.returncode == 0, f"stderr={run1.stderr}"
    assert run2.returncode == 0, f"stderr={run2.stderr}"
    assert run1.stdout == run2.stdout
    assert _PINNED_Z in run1.stdout
