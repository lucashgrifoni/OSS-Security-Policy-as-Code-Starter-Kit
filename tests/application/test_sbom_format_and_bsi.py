"""SBOM format/version detection + BSI TR-03183-2 v2.1.0 validation.

Covers PR-4 (Onda 1) extensions to ``BUILD-SBOM-QUAL-003``:

- **O-12** — SPDX 3.0.1 (and SPDX 2.x) detection with version surfacing,
  CycloneDX version surfacing.
- **V6-09** — BSI TR-03183-2 v2.1.0 required-field validation: identifiers
  (PURL/CPE), cryptographic hashes, license declaration, supplier identity,
  and explicit separation of vulnerability data into a VEX document.

The validator is intentionally heuristic (regex over the text blob) — strict
BSI conformance requires a dedicated tool. The kit's role is to surface the
most common clone-side gaps.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import (
    EvalContext,
    _detect_sbom_format_and_version,
    _validate_bsi_tr_03183_v2_1,
    eval_build_sbom_qual_003,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="osps-baseline-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


# ---- Fixtures: minimal SBOM blobs by format/version -----------------------


def _cyclonedx_16_compliant() -> str:
    """CycloneDX 1.6 with all BSI v2.1.0 required fields present, no vulnerabilities embedded."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-05-18T12:00:00Z",
            "supplier": {"name": "Example Corp"},
        },
        "components": [
            {
                "type": "library",
                "name": "example-lib",
                "version": "1.2.3",
                "purl": "pkg:pypi/example-lib@1.2.3",
                "cpe": "cpe:2.3:a:example:example-lib:1.2.3:*:*:*:*:*:*:*",
                "hashes": [{"alg": "SHA-256", "content": "abc123"}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "supplier": {"name": "Example Corp"},
            }
        ],
    }
    return json.dumps(doc)


def _cyclonedx_16_missing_hashes() -> str:
    """CycloneDX 1.6 missing hashes (BSI v2.1.0 fail dimension)."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-05-18T12:00:00Z", "supplier": {"name": "X"}},
        "components": [
            {
                "type": "library",
                "name": "n",
                "version": "1",
                "purl": "pkg:pypi/n@1",
                "licenses": [{"license": {"id": "MIT"}}],
                "supplier": {"name": "X"},
            }
        ],
    }
    return json.dumps(doc)


def _cyclonedx_16_with_vex_inside() -> str:
    """CycloneDX 1.6 that embeds a ``vulnerabilities[]`` array — BSI v2.1.0 rejects this."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-05-18T12:00:00Z", "supplier": {"name": "X"}},
        "components": [
            {
                "type": "library",
                "name": "n",
                "version": "1",
                "purl": "pkg:pypi/n@1",
                "hashes": [{"alg": "SHA-256", "content": "a"}],
                "licenses": [{"license": {"id": "MIT"}}],
                "supplier": {"name": "X"},
            }
        ],
        "vulnerabilities": [{"id": "CVE-2024-12345", "source": {"name": "NVD"}, "ratings": []}],
    }
    return json.dumps(doc)


def _cyclonedx_15_legacy() -> str:
    """CycloneDX 1.5 — older than BSI v2.1.0 target; should return None from validator."""
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []}
    return json.dumps(doc)


def _spdx_22_json() -> str:
    """SPDX 2.2 JSON — older than BSI v2.1.0 target."""
    doc = {"spdxVersion": "SPDX-2.2", "name": "doc", "packages": []}
    return json.dumps(doc)


def _spdx_3_compliant() -> str:
    """SPDX 3.0.1 JSON-LD — recognised by the v3 detector."""
    doc = {
        "@context": "https://spdx.dev/spec/3.0.1/schema/spdx-context.jsonld",
        "@graph": [
            {
                "type": "CreationInfo",
                "specVersion": "3.0.1",
                "created": "2026-05-18T00:00:00Z",
                "createdBy": ["spdxid://supplier"],
            },
            {
                "type": "software_Package",
                "spdxId": "spdxid://pkg",
                "packageURL": "pkg:pypi/x@1.0.0",
                "verifiedUsing": [{"algorithm": "sha256", "hashValue": "deadbeef"}],
                "licenseConcluded": "Apache-2.0",
                "supplier": "Example Corp",
            },
        ],
    }
    return json.dumps(doc)


# ---- _detect_sbom_format_and_version --------------------------------------


def test_detect_cyclonedx_16() -> None:
    fmt, ver = _detect_sbom_format_and_version(_cyclonedx_16_compliant())
    assert fmt == "cyclonedx" and ver == "1.6"


def test_detect_cyclonedx_15() -> None:
    fmt, ver = _detect_sbom_format_and_version(_cyclonedx_15_legacy())
    assert fmt == "cyclonedx" and ver == "1.5"


def test_detect_spdx_3_0_1() -> None:
    fmt, ver = _detect_sbom_format_and_version(_spdx_compliant := _spdx_3_compliant())
    assert fmt == "spdx"
    assert ver is not None and ver.startswith("3.0")


def test_detect_spdx_22_json() -> None:
    fmt, ver = _detect_sbom_format_and_version(_spdx_22_json())
    assert fmt == "spdx" and ver == "2.2"


def test_detect_spdx_22_tag_value() -> None:
    blob = "SPDXVersion: SPDX-2.2\nDataLicense: CC0-1.0\nPackageName: foo\n"
    fmt, ver = _detect_sbom_format_and_version(blob)
    assert fmt == "spdx" and ver == "2.2"


def test_detect_unknown_returns_none() -> None:
    fmt, ver = _detect_sbom_format_and_version('{"unrelated": true}')
    assert fmt is None and ver is None


# ---- _validate_bsi_tr_03183_v2_1 ------------------------------------------


def test_bsi_validator_returns_none_for_legacy_cyclonedx() -> None:
    """CycloneDX < 1.6 is out of BSI v2.1.0 scope."""
    assert _validate_bsi_tr_03183_v2_1(_cyclonedx_15_legacy(), "cyclonedx", "1.5") is None


def test_bsi_validator_returns_none_for_spdx_2x() -> None:
    """SPDX 2.x is out of BSI v2.1.0 scope (BSI v2.1.0 targets SPDX 3.x)."""
    assert _validate_bsi_tr_03183_v2_1(_spdx_22_json(), "spdx", "2.2") is None


def test_bsi_validator_cyclonedx_16_all_required_present() -> None:
    """Fully populated CycloneDX 1.6 passes every BSI v2.1.0 dimension."""
    result = _validate_bsi_tr_03183_v2_1(_cyclonedx_16_compliant(), "cyclonedx", "1.6")
    assert result == {
        "identifiers_present": True,
        "hashes_present": True,
        "licenses_present": True,
        "supplier_present": True,
        "vulnerability_data_separated": True,
    }


def test_bsi_validator_flags_missing_hashes() -> None:
    result = _validate_bsi_tr_03183_v2_1(_cyclonedx_16_missing_hashes(), "cyclonedx", "1.6")
    assert result is not None
    assert result["hashes_present"] is False
    # The other dimensions remain present.
    assert result["identifiers_present"] is True
    assert result["licenses_present"] is True
    assert result["supplier_present"] is True


def test_bsi_validator_rejects_sbom_with_embedded_vulnerabilities() -> None:
    """BSI v2.1.0 requires VEX separation — embedded ``vulnerabilities[]`` fails."""
    result = _validate_bsi_tr_03183_v2_1(_cyclonedx_16_with_vex_inside(), "cyclonedx", "1.6")
    assert result is not None
    assert result["vulnerability_data_separated"] is False
    # Other required fields still present in the fixture.
    assert result["identifiers_present"] is True
    assert result["hashes_present"] is True


def test_bsi_validator_spdx_3_recognised() -> None:
    """SPDX 3.x reaches the BSI validator and returns a verdict."""
    result = _validate_bsi_tr_03183_v2_1(_spdx_3_compliant(), "spdx", "3.0.1")
    assert result is not None
    # The minimal SPDX 3 fixture has identifiers (packageURL), hashes (verifiedUsing
    # with hashValue), license (licenseConcluded), supplier (supplier field), and no
    # vulnerabilities embedded.
    assert result["identifiers_present"] is True
    assert result["hashes_present"] is True
    assert result["licenses_present"] is True
    assert result["supplier_present"] is True
    assert result["vulnerability_data_separated"] is True


# ---- eval_build_sbom_qual_003 surfaces BSI notes in reason ----------------


def test_eval_sbom_qual_surfaces_bsi_notes_when_applicable(tmp_path: Path) -> None:
    """A CycloneDX 1.6 SBOM in the repo triggers BSI v2.1.0 notes in the reason."""
    (tmp_path / "sbom.json").write_text(_cyclonedx_16_compliant(), encoding="utf-8")
    out = eval_build_sbom_qual_003(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "BSI TR-03183-2 v2.1.0" in out.reason
    assert "all required fields present" in out.reason


def test_eval_sbom_qual_flags_bsi_missing_fields(tmp_path: Path) -> None:
    """SBOM with missing hashes surfaces the gap in the reason."""
    (tmp_path / "sbom.json").write_text(_cyclonedx_16_missing_hashes(), encoding="utf-8")
    out = eval_build_sbom_qual_003(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS  # still PASS — SBOM is valid; BSI is supplementary
    assert "BSI TR-03183-2 v2.1.0" in out.reason
    assert "missing" in out.reason
    assert "hashes" in out.reason


def test_eval_sbom_qual_no_bsi_notes_for_legacy_cyclonedx(tmp_path: Path) -> None:
    """CycloneDX 1.5 is out of BSI v2.1.0 scope; no BSI text appears."""
    (tmp_path / "sbom.json").write_text(_cyclonedx_15_legacy(), encoding="utf-8")
    out = eval_build_sbom_qual_003(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "BSI TR-03183-2" not in out.reason


@pytest.mark.parametrize(
    "blob,expected_fmt,expected_version_prefix",
    [
        (_cyclonedx_16_compliant(), "cyclonedx", "1.6"),
        (_cyclonedx_15_legacy(), "cyclonedx", "1.5"),
        (_spdx_3_compliant(), "spdx", "3.0"),
        (_spdx_22_json(), "spdx", "2.2"),
    ],
)
def test_eval_sbom_qual_reports_format_and_version(
    tmp_path: Path, blob: str, expected_fmt: str, expected_version_prefix: str
) -> None:
    """The evaluator reason includes the detected format + version."""
    (tmp_path / "sbom.json").write_text(blob, encoding="utf-8")
    out = eval_build_sbom_qual_003(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert expected_fmt in out.reason
    assert expected_version_prefix in out.reason
