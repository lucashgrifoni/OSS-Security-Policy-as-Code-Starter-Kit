"""Assemble the findings/1.0 artifact dict (ADR-030 A-S5).

Orchestrates the read-only pipeline — kit-evidence normalizers (A-S2) +
external-SARIF normalizers (A-S3) -> correlation engine (A-S4) -> the
``oss-policy-kit/findings/1.0`` artifact. Paths are privacy-sanitized by
default (basename-only ``target_path``, like reports/2.0), reusing the
reporting-layer sanitizer so the two artifacts behave identically.

Pure and single-run: reads only under ``repo_root`` + the fixed evidence
paths, no network, no persistence, no cross-run state.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from oss_policy_kit.application.clock import report_generated_at
from oss_policy_kit.application.finding_correlation import correlate
from oss_policy_kit.application.finding_normalization import (
    NORMALIZED_SEVERITIES,
    kit_evidence_partial_scan_warnings,
    normalize_kit_evidence,
)
from oss_policy_kit.application.finding_sarif import normalize_sarif_sources
from oss_policy_kit.application.input_limits import BAD_INPUT_ERRORS, MAX_EVIDENCE_BYTES, oversize_reason
from oss_policy_kit.application.reporting import _sanitize_target_path_for_payload
from oss_policy_kit.application.vuln_waivers import VulnWaiver, load_vuln_waivers
from oss_policy_kit.domain.findings import NormalizedFinding, SourceRecord, WaiverLink

FINDINGS_SCHEMA_VERSION = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/findings/1.0"
FINDINGS_CONTRACT_VERSION = "findings/1.0"


def _source_record_to_dict(record: SourceRecord) -> dict[str, Any]:
    return {
        "path": record.path,
        "kind": record.kind,
        "tool": record.tool,
        "tool_version": record.tool_version,
        "schema_version": record.schema_version,
        "status": record.status,
    }


def _finding_to_dict(finding: NormalizedFinding) -> dict[str, Any]:
    loc = finding.location
    lg = loc.logical
    return {
        "id": finding.id,
        "sources": [
            {
                "tool": s.tool,
                "source_path": s.source_path,
                "rule": s.rule,
                "severity_original": s.severity_original,
                "message": s.message,
                "native_id": s.native_id,
            }
            for s in finding.sources
        ],
        "rule": finding.rule,
        "message": finding.message,
        "cwe": list(finding.cwe),
        "owasp": list(finding.owasp),
        "severity": {
            "normalized": finding.severity.normalized,
            "by_source": [{"tool": t, "original": o} for t, o in finding.severity.by_source],
        },
        "location": {
            "file": loc.file,
            "line_start": loc.line_start,
            "line_end": loc.line_end,
            "logical": {
                "type": lg.type,
                "resource_type": lg.resource_type,
                "resource_name": lg.resource_name,
                "kind": lg.kind,
                "namespace": lg.namespace,
                "name": lg.name,
            },
        },
        "component": finding.component,
        "vulnerability_ids": list(finding.vulnerability_ids),
        "epss": finding.epss,
        "kev": finding.kev,
        "cvss": finding.cvss,
        "reachability": finding.reachability,
        "waiver": {
            "waived": finding.waiver.waived,
            "matched_by": finding.waiver.matched_by,
            "waiver_owner": finding.waiver.waiver_owner,
            "expires_at": finding.waiver.expires_at,
        },
        "priority": {
            "rank": finding.priority.rank if finding.priority else 0,
            "rationale": finding.priority.rationale if finding.priority else "",
        },
        "correlation": {
            "key": finding.correlation.key if finding.correlation else "",
            "merged_from": finding.correlation.merged_from if finding.correlation else 1,
            "confidence": finding.correlation.confidence if finding.correlation else "exact",
        },
    }


def collect_normalized_findings(
    repo_root: Path,
) -> tuple[list[NormalizedFinding], list[SourceRecord]]:
    """Read + normalize all kit-evidence and external-SARIF sources under *repo_root*."""

    kit_findings, kit_records = normalize_kit_evidence(repo_root)
    sarif_findings, sarif_records = normalize_sarif_sources(repo_root)
    return kit_findings + sarif_findings, kit_records + sarif_records


def _apply_vuln_waivers(
    findings: tuple[NormalizedFinding, ...], waivers: dict[str, VulnWaiver]
) -> tuple[NormalizedFinding, ...]:
    """Attach waiver links to findings whose vulnerability ids match (FT-3 fence).

    The link is annotation only: rank, severity, and every other field stay
    untouched, and nothing here can reach the evaluation engine. Waived
    findings stay fully visible in the artifact.
    """

    if not waivers:
        return findings
    out: list[NormalizedFinding] = []
    for f in findings:
        record = next((waivers[v] for v in f.vulnerability_ids if v in waivers), None)
        if record is None:
            out.append(f)
            continue
        link = WaiverLink(
            waived=True,
            matched_by="vulnerability_id",
            waiver_owner=record.owner,
            expires_at=record.expires_at.isoformat() if record.expires_at else None,
        )
        out.append(replace(f, waiver=link))
    return tuple(out)


def _load_enrichment(path: Path) -> tuple[dict[str, dict[str, Any]], SourceRecord]:
    """Load an offline EPSS/KEV enrichment snapshot with an honest provenance record.

    Shape: ``{"as_of": "YYYY-MM-DD", "vulnerabilities": {"CVE-X": {"epss": .., "kev": ..}}}``.
    The record carries the inferred-trust label and the snapshot's as-of date;
    the data feeds ranking only (see finding_correlation._effective_signals).
    """

    tool = "user-supplied-enrichment (inferred trust)"
    rel = path.name  # basename only: never leak the auditor's absolute path
    if not path.is_file():
        return {}, SourceRecord(path=rel, kind="enrichment-snapshot", tool=tool, status="missing")
    if oversize_reason(path, MAX_EVIDENCE_BYTES, label="enrichment snapshot") is not None:
        return {}, SourceRecord(path=rel, kind="enrichment-snapshot", tool=tool, status="oversize")
    try:
        # BAD_INPUT_ERRORS is the shared taxonomy of what an unreadable file can
        # throw: json.loads raises RecursionError (not JSONDecodeError) past the
        # nesting limit and a bare ValueError past CPython's 4300-digit integer
        # conversion limit. Both must degrade to an honest "unreadable" record —
        # correlate-findings documents that an unreadable source is never raised.
        raw = json.loads(path.read_text(encoding="utf-8"))
    except BAD_INPUT_ERRORS:
        return {}, SourceRecord(path=rel, kind="enrichment-snapshot", tool=tool, status="unreadable")
    if not isinstance(raw, dict):
        return {}, SourceRecord(path=rel, kind="enrichment-snapshot", tool=tool, status="unreadable")
    vulns = raw.get("vulnerabilities")
    table = {str(k): v for k, v in vulns.items() if isinstance(v, dict)} if isinstance(vulns, dict) else {}
    as_of = str(raw.get("as_of") or "").strip() or None
    record = SourceRecord(path=rel, kind="enrichment-snapshot", tool=tool, status="ok", tool_version=as_of)
    return table, record


def build_findings_report(
    repo_root: Path,
    *,
    kit_version: str,
    include_absolute_path: bool = False,
    generated_at: str | None = None,
    waivers_path: Path | None = None,
    enrichment_path: Path | None = None,
) -> dict[str, Any]:
    """Build the complete findings/1.0 artifact dict for *repo_root*.

    Deterministic given the same inputs (``generated_at`` defaults to the
    SOURCE_DATE_EPOCH-honoring report clock). Missing/unreadable sources are
    recorded in ``sources_read`` and never raise.
    """

    findings, records = collect_normalized_findings(repo_root)
    enrichment: dict[str, dict[str, Any]] | None = None
    if enrichment_path is not None:
        enrichment, enrichment_record = _load_enrichment(enrichment_path)
        records.append(enrichment_record)
    result = correlate(findings, enrichment)

    correlated = result.findings
    waiver_warnings: list[str] = []
    if waivers_path is not None:
        vuln_waivers, waiver_warnings = load_vuln_waivers(waivers_path)
        correlated = _apply_vuln_waivers(correlated, vuln_waivers)

    by_severity = dict.fromkeys(NORMALIZED_SEVERITIES, 0)
    for f in correlated:
        by_severity[f.severity.normalized] = by_severity.get(f.severity.normalized, 0) + 1

    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "contract_version": FINDINGS_CONTRACT_VERSION,
        "generated_at": generated_at if generated_at is not None else report_generated_at(),
        "kit_version": kit_version,
        "target_path": _sanitize_target_path_for_payload(str(repo_root), include_absolute=include_absolute_path),
        "sources_read": [_source_record_to_dict(r) for r in records],
        "findings_total": len(correlated),
        "findings_by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in correlated],
        "correlation": result.to_dict(),
        "extensions": _extensions(waiver_warnings, kit_evidence_partial_scan_warnings(repo_root)),
    }


def _extensions(waiver_warnings: list[str], partial_scan_warnings: list[str]) -> dict[str, Any]:
    """Keep `extensions` absent-when-empty, which is how consumers already read it."""

    out: dict[str, Any] = {}
    if waiver_warnings:
        out["waiver_warnings"] = waiver_warnings
    if partial_scan_warnings:
        out["partial_scan_warnings"] = partial_scan_warnings
    return out


def build_findings_summary(repo_root: Path, *, kit_version: str) -> dict[str, Any]:
    """Compute the flag-gated ``extensions.findings_summary`` block IN-PROCESS (A-S8).

    Recomputed from the same clone-local inputs during the same ``evaluate``
    invocation — it NEVER reads a pre-existing ``findings.json`` (fence FT-1)
    and implies no linkage to the per-control ``finding_id``. ``kev_count`` and
    ``high_epss_count`` (EPSS >= 0.5) are source-derived signals, never
    compliance claims. ``findings_digest`` is the sha256 (16 hex) of the
    canonical findings array so consumers can pair the summary with a
    separately produced findings/1.0 artifact.
    """

    report = build_findings_report(repo_root, kit_version=kit_version)
    canonical = json.dumps(report["findings"], sort_keys=True).encode("utf-8")
    sources = report["sources_read"]
    sources_ok = sum(1 for s in sources if s["status"] == "ok")
    return {
        "findings_total": report["findings_total"],
        "correlated_groups": report["correlation"]["merged_groups"],
        "by_severity": report["findings_by_severity"],
        "kev_count": sum(1 for f in report["findings"] if f["kev"]),
        "high_epss_count": sum(1 for f in report["findings"] if (f["epss"] or 0) >= 0.5),
        # Source-read accounting so a consumer can tell a genuinely-clean zero
        # from an all-unreadable one: findings_total==0 with sources_ok < sources_total
        # means evidence was present but could not be read, not "no problems".
        "sources_total": len(sources),
        "sources_ok": sources_ok,
        "artifact": "findings.json",
        "findings_digest": hashlib.sha256(canonical).hexdigest()[:16],
    }
