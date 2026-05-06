"""SARIF 2.1.0 output for evaluation reports.

Maps failing and manual-review-required control results to SARIF results so
GitHub code scanning, IDEs, and SARIF viewers can ingest them directly.

Design rules:

- Only ``fail`` and ``manual-review-required`` results become SARIF results.
- ``manual-review-required`` is mapped to ``level: warning`` (not error) so it
  surfaces in code scanning without acting like a hard failure.
- Repository-level findings emit a SARIF artifactLocation pointing at the
  repository root and **omit the region object**, so consumers do not render a
  fake line range.
- File-backed findings (when ``evidence_sources`` carries a real relative path)
  emit a file-level artifactLocation; still no region unless explicit line data
  is available — repository governance findings rarely have that.
- Tool driver metadata identifies this kit and pins the rule catalog on each
  emission. No PII, no host paths, no tokens.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oss_policy_kit.application.evidence_projection import normalize_confidence, project_evidence
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"

_TOOL_NAME = "oss-policy-kit"
_TOOL_INFORMATION_URI = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit"

_REPORTABLE_STATUSES = frozenset({ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED})


def _level_for_status(status: ControlStatus) -> str:
    if status == ControlStatus.FAIL:
        return "error"
    if status == ControlStatus.MANUAL_REVIEW_REQUIRED:
        return "warning"
    return "note"


def _security_severity_for(weight: int, status: ControlStatus) -> str:
    """Map weight (1..3) to a SARIF security-severity score in [0.0, 10.0].

    Hard failures get a higher floor than manual-review-required.
    Numbers are conservative; the kit is not a CVSS source.
    """

    base_per_weight = {1: 4.0, 2: 6.5, 3: 8.5}
    base = base_per_weight.get(weight, 5.0)
    if status == ControlStatus.MANUAL_REVIEW_REQUIRED:
        base = max(0.0, base - 2.0)
    return f"{base:.1f}"


def _is_safe_relative_path(value: str) -> bool:
    """Reject empty, absolute, or escape-style paths."""

    if not value:
        return False
    v = value.replace("\\", "/").strip()
    if v.startswith(("/", "http://", "https://")):
        return False
    if len(v) >= 2 and v[1] == ":":
        return False
    return ".." not in v.split("/")


def _file_locations_from_result(result: ControlResult) -> list[dict[str, Any]]:
    """Return SARIF location entries for any clone-relative file evidence.

    Only includes path-style references that pass ``_is_safe_relative_path``.
    Returns an empty list when the result is repository-scoped.
    """

    out: list[dict[str, Any]] = []
    for src in result.evidence_sources:
        if not _is_safe_relative_path(src):
            continue
        normalized = src.replace("\\", "/")
        out.append(
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": normalized,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        )
    return out


def _repo_location() -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": ".",
                "uriBaseId": "%SRCROOT%",
            }
        }
    }


def _result_message(result: ControlResult) -> dict[str, str]:
    parts = [result.reason.strip()]
    evidence = project_evidence(result)
    limitations = evidence.get("limitations") or []
    if limitations:
        parts.append("Limitations: " + " ".join(limitations))
    return {"text": " | ".join(p for p in parts if p)}


def _rule_for_result(result: ControlResult) -> dict[str, Any]:
    """Build a SARIF ``reportingDescriptor`` (rule) entry for a control."""

    return {
        "id": result.control_id,
        "name": result.control_id.replace("-", "_"),
        "shortDescription": {"text": result.title},
        "fullDescription": {
            "text": (
                f"{result.title}. Category: {result.category}. "
                f"Lifecycle: {result.lifecycle}. Assurance: {result.assurance}."
            )
        },
        "helpUri": _TOOL_INFORMATION_URI,
        "help": {
            "text": result.remediation,
            "markdown": f"**Remediation:** {result.remediation}",
        },
        "properties": {
            "category": result.category,
            "lifecycle": result.lifecycle,
            "assurance": result.assurance,
            "weight": result.weight,
        },
        "defaultConfiguration": {
            "level": _level_for_status(result.status),
        },
    }


def _result_to_sarif(result: ControlResult) -> dict[str, Any]:
    locations = _file_locations_from_result(result)
    if not locations:
        locations = [_repo_location()]

    sarif_result: dict[str, Any] = {
        "ruleId": result.control_id,
        "level": _level_for_status(result.status),
        "message": _result_message(result),
        "locations": locations,
        "properties": {
            "kit_status": result.status.value,
            "confidence": normalize_confidence(result.confidence),
            "assurance": result.assurance,
            "lifecycle": result.lifecycle,
            "profile": result.profile,
            "weight": result.weight,
            "security-severity": _security_severity_for(result.weight, result.status),
        },
        "partialFingerprints": {
            "controlAndProfile/v1": f"{result.control_id}@{result.profile}",
        },
    }
    return sarif_result


def build_sarif(report: ExecutionReport) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log object for the evaluation report."""

    reportable = [r for r in report.results if r.status in _REPORTABLE_STATUSES]
    rules_by_id: dict[str, dict[str, Any]] = {}
    for r in reportable:
        rules_by_id.setdefault(r.control_id, _rule_for_result(r))

    sarif_results = [_result_to_sarif(r) for r in reportable]

    run_block: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": _TOOL_NAME,
                "informationUri": _TOOL_INFORMATION_URI,
                "version": report.kit_version,
                "rules": list(rules_by_id.values()),
            }
        },
        "originalUriBaseIds": {
            "%SRCROOT%": {"uri": "file:///"},
        },
        "results": sarif_results,
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": report.generated_at,
            }
        ],
        "properties": {
            "profile_id": report.profile_id,
            "profile_title": report.profile_title,
            "kit_version": report.kit_version,
        },
    }

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run_block],
    }


def write_sarif_report(report: ExecutionReport, path: Path) -> None:
    """Write a SARIF 2.1.0 log file for the evaluation report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_sarif(report)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
