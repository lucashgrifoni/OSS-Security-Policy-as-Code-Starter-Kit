"""`correlate-findings` must say when its inputs were incomplete.

The correlated artifact is honest about the files it read -- `sources_read` records the evidence
file as `ok`, and it was. What it never said is that the *scanner* had skipped a source it could
not decode, so `findings_total` counted less than the repository held while looking like a
total. `--fail-on-severity` gates pipelines on that number, so a UTF-16 file could keep a build
green by being unreadable.

`sources_read[].status` is a closed enum under `additionalProperties: false`, so the record
cannot carry this. `extensions` is the contract's free-form block and already carries
`waiver_warnings` this way, so the artifact stays valid against a published schema -- which
these tests check rather than assume.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit import __version__
from oss_policy_kit.application.finding_normalization import KIT_EVIDENCE_SOURCES
from oss_policy_kit.application.findings_report import build_findings_report

_EVIDENCE = Path(".oss-policy-kit") / "evidence"


def _write(root: Path, filename: str, payload: dict[str, Any]) -> None:
    directory = root / _EVIDENCE
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(json.dumps(payload), encoding="utf-8")


def _evidence(*, parse_errors: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schema_version": "oss-policy-kit/evidence/iac-terraform/v1",
        "status": "ok",
        "files_scanned": ["readable.tf"],
        "findings": [],
        "findings_by_rule": {},
        "diagnostics": {"parse_errors": parse_errors, "raw_message": ""},
    }


def _report(root: Path) -> dict[str, Any]:
    return build_findings_report(root, kit_version=__version__)


def test_a_skipped_source_is_named_in_the_artifact(tmp_path: Path) -> None:
    _write(tmp_path, "iac-terraform.json", _evidence(parse_errors=[{"file": "utf16.tf", "error": "bad codec"}]))

    warnings = _report(tmp_path)["extensions"]["partial_scan_warnings"]

    assert len(warnings) == 1
    assert "utf16.tf" in warnings[0], f"the warning does not name the file: {warnings[0]}"
    assert "iac-terraform.json" in warnings[0], f"the warning does not name the source: {warnings[0]}"


def test_a_complete_scan_adds_no_warning(tmp_path: Path) -> None:
    """The counterpart that keeps the check from being satisfied by always warning."""

    _write(tmp_path, "iac-terraform.json", _evidence(parse_errors=[]))

    assert "partial_scan_warnings" not in _report(tmp_path)["extensions"]


def test_the_warned_artifact_still_validates_against_the_published_schema(tmp_path: Path) -> None:
    """`extensions` is free-form, but "free-form" is a claim worth checking once."""

    jsonschema = pytest.importorskip("jsonschema")
    from oss_policy_kit.application.loader import bundled_kit_root  # noqa: PLC0415

    _write(tmp_path, "iac-terraform.json", _evidence(parse_errors=[{"file": "utf16.tf", "error": "bad codec"}]))
    schema = json.loads((bundled_kit_root() / "schema" / "findings" / "1.0.json").read_text(encoding="utf-8"))

    jsonschema.validate(_report(tmp_path), schema)


@pytest.mark.parametrize("filename", [s[0] for s in KIT_EVIDENCE_SOURCES])
def test_every_kit_evidence_source_is_checked_for_skipped_files(tmp_path: Path, filename: str) -> None:
    """Derived from the source registry: a seventh scanner is covered by being registered.

    The check is that the CORRELATOR reads `diagnostics.parse_errors` from every registered
    source, not that every scanner emits it -- `sast-semgrep.json` is written by Semgrep and
    carries no such key, so asserting it "can record parse_errors" would state something about
    a tool this repository does not control. What matters is that if one ever appears there,
    the correlator does not swallow it.
    """

    _write(tmp_path, filename, _evidence(parse_errors=[{"file": "unreadable-source", "error": "bad codec"}]))

    warnings = _report(tmp_path)["extensions"].get("partial_scan_warnings", [])

    assert any(filename in w for w in warnings), (
        f"the correlator ignores diagnostics.parse_errors in {filename}, so an artifact built "
        "from it would under-report in silence."
    )
