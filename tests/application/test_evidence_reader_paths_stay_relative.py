"""A shared reader that cannot read its evidence must not say where it looked.

``str(OSError)`` appends the filename the call was handed, so interpolating the exception
into a ``reason`` publishes whatever the caller resolved -- the adopter's home directory,
their OS account name -- in a report they hand to an auditor (M-002). Fixing
``governance.py`` left the same leak alive in the two readers everything else goes through:

- ``_parse_branch_protection_evidence`` feeds ``PLAT-BRPROT-015`` and all four
  ``SLSA-SRC-*`` controls.
- ``validate_json_evidence`` returns its string verbatim as the reason of
  ``eval_org_mfa_001`` and its siblings.

The two SARIF readers beside them leaked identically.

Nothing the suite already fed these readers exposes it: ``JSONDecodeError`` and
``UnicodeDecodeError`` carry no filename, so it takes a real file and a real ``OSError``.
A directory standing where the evidence file belongs raises one deterministically on both
platforms -- ``PermissionError`` on Windows, ``IsADirectoryError`` on Linux -- and both
stringify with the path.

The input is RELATIVE and carries a directory component on purpose. Asserting that one
particular absolute string is absent passes for the wrong reason on Windows, where 8.3 short
names (``LUCASG~1``) spell the same directory differently; and a bare filename would leave
the pre-fix code nothing to leak. Asserting that no separator survives at all is the check
that cannot be satisfied by accident.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from oss_policy_kit.application import evaluators_common as ec
from oss_policy_kit.application.evaluators import _shared
from oss_policy_kit.domain.models import ControlStatus

_EVIDENCE_DIR = "evidence"
_SEPARATORS = ("/", "\\", os.sep)


def _unreadable_relative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> Path:
    """Return a RELATIVE path to *name* that raises a real ``OSError`` when read."""

    monkeypatch.chdir(tmp_path)
    (tmp_path / _EVIDENCE_DIR / name).mkdir(parents=True)
    relative = Path(_EVIDENCE_DIR) / name
    assert any(sep in str(relative) for sep in _SEPARATORS), (
        "the fixture must carry a separator, or the assertion under test passes for free"
    )
    return relative


def _assert_explains_without_locating(message: str) -> None:
    """The message says why the file was refused and names no filesystem location."""

    for sep in _SEPARATORS:
        assert sep not in message, f"path separator {sep!r} survived in: {message}"
    assert "could not be read" in message, f"the reason stopped explaining itself: {message}"


# --------------------------------------------------------------------------- #
# the two shared evidence readers
# --------------------------------------------------------------------------- #


def test_branch_protection_reader_refuses_without_naming_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-045 keeps the verdict at manual-review-required; M-002 keeps the host out of it."""

    evidence = _unreadable_relative(tmp_path, monkeypatch, "branch-protection.json")

    outcome = _shared._parse_branch_protection_evidence(evidence)

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    _assert_explains_without_locating(outcome.reason)


def test_json_evidence_validator_refuses_without_naming_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = _unreadable_relative(tmp_path, monkeypatch, "org-mfa-posture.json")

    data, error, placeholders = ec.validate_json_evidence(
        evidence,
        schema_loader=lambda: {"type": "object"},
        evidence_name="Organization MFA",
    )

    assert data is None
    assert placeholders == []
    assert error is not None
    _assert_explains_without_locating(error)


# --------------------------------------------------------------------------- #
# the SARIF readers the same sweep covered
# --------------------------------------------------------------------------- #


def test_sarif_reader_refuses_without_naming_the_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sarif = _unreadable_relative(tmp_path, monkeypatch, "semgrep.sarif.json")

    runs, error = _shared._load_sarif_runs(sarif)

    assert runs is None
    assert error is not None
    _assert_explains_without_locating(error)


def test_zizmor_severity_reader_refuses_without_naming_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sarif = _unreadable_relative(tmp_path, monkeypatch, "zizmor.sarif.json")

    counts, error = _shared._parse_zizmor_severity_properties(sarif)

    assert counts is None
    assert error is not None
    _assert_explains_without_locating(error)
