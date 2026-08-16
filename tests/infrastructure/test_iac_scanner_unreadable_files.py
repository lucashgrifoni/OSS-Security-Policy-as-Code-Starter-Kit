"""A file the scanner cannot read is reported as unread, never silently dropped.

This is the difference between "we scanned five files and found nothing" and "we scanned
four files, could not open the fifth, and found nothing in the four". The first is a clean
result; the second is a partial one, and a policy gate that cannot tell them apart will
report a repository as compliant on the strength of a file it never opened.

Unreadable happens for ordinary reasons -- a permission bit, a broken symlink, a file held
open by another process on Windows, a path the walker resolved but the reader cannot. The
scanner has to keep going and record the file under ``files_failed``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep_scanner
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi_scanner


def _refuse_to_read(monkeypatch: pytest.MonkeyPatch, doomed_name: str) -> None:
    """Make the OS refuse one specific filename, whichever read the scanner uses.

    Both ``read_text`` and ``read_bytes`` are doubled on purpose. This used to patch only
    ``read_text``, and when the scanners moved to ``read_bytes`` -- so they could decode by BOM
    instead of mangling a UTF-16 file -- the doomed file became readable again and three tests
    started asserting nothing. The behaviour under test is "the OS would not give us this
    file", which is independent of which method asks.
    """

    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes

    def _read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == doomed_name:
            raise OSError(13, "Permission denied")
        return real_read_text(self, *args, **kwargs)

    def _read_bytes(self: Path) -> bytes:
        if self.name == doomed_name:
            raise OSError(13, "Permission denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_text", _read_text)
    monkeypatch.setattr(Path, "read_bytes", _read_bytes)


def test_bicep_scan_records_a_file_it_could_not_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "readable.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'sa'\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "locked.bicep").write_text("resource x 'Microsoft.Foo/bar@2023-01-01' = {}\n", encoding="utf-8")
    _refuse_to_read(monkeypatch, "locked.bicep")

    outcome = bicep_scanner.run_scan(tmp_path)

    failed = [pe["file"] for pe in outcome.parse_errors]
    assert any("locked.bicep" in f for f in failed), failed
    assert not any("locked.bicep" in str(f) for f in outcome.files_scanned)
    assert any("readable.bicep" in str(f) for f in outcome.files_scanned)


def test_pulumi_scan_records_a_file_it_could_not_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "readable.py").write_text("import pulumi_aws as aws\n", encoding="utf-8")
    (tmp_path / "locked.py").write_text("import pulumi_aws as aws\n", encoding="utf-8")
    _refuse_to_read(monkeypatch, "locked.py")

    outcome = pulumi_scanner.run_scan(tmp_path)

    failed = [pe["file"] for pe in outcome.parse_errors]
    assert any("locked.py" in f for f in failed), failed
    assert not any("locked.py" in str(f) for f in outcome.files_scanned)


def test_the_unreadable_file_reaches_the_evidence_as_files_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It is not enough to record it internally -- the consumer of the evidence has to see it."""

    (tmp_path / "locked.bicep").write_text("resource x 'Microsoft.Foo/bar@2023-01-01' = {}\n", encoding="utf-8")
    _refuse_to_read(monkeypatch, "locked.bicep")

    outcome = bicep_scanner.run_scan(tmp_path)
    evidence = bicep_scanner.render_evidence_payload(outcome, target=tmp_path)

    assert any("locked.bicep" in f for f in evidence["files_failed"]), evidence["files_failed"]
