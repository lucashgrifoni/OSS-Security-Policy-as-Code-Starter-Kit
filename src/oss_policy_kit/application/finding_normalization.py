"""Normalize kit scanner evidence into the ADR-030 finding model (A-S2).

Reads the six kit-emitted evidence JSONs under ``.oss-policy-kit/evidence/``
(sast-semgrep, iac-terraform, iac-cfn, iac-pulumi, iac-bicep, k8s-baseline)
and projects each raw finding into a :class:`NormalizedFinding` with a single
source. Cross-source correlation, ids, and ranking happen later in the
correlation engine — this module is a pure, read-only projection.

Honesty rules (ADR-030 Amendment):

- A missing/unreadable/oversize source NEVER fails the run; it is recorded in
  the returned :class:`SourceRecord` list with an honest status.
- Original severities are preserved verbatim in ``severity.by_source``; the
  normalized value comes from the versioned x-severity-map below, which never
  rewrites what a source tool said.
- Every read is size-capped (``MAX_EVIDENCE_BYTES``) and tolerant of bad
  encodings (``UnicodeDecodeError`` degrades to ``unreadable``, never a crash).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from oss_policy_kit.application._evidence_rules import _phrase, unread_sources
from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES, oversize_reason
from oss_policy_kit.domain.findings import (
    FindingLocation,
    FindingSource,
    LogicalLocation,
    NormalizedFinding,
    SeverityView,
    SourceRecord,
)

#: Version tag for the severity normalization table. Bump only with a contract note;
#: the table is part of the findings/1.0 documentation surface.
SEVERITY_MAP_VERSION = "x-severity-map/v1"

#: The fixed normalized-severity vocabulary of findings/1.0 (ordered high → low signal).
NORMALIZED_SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "unknown")

# IaC scanners emit the schema-locked LOW..CRITICAL vocabulary; the k8s scanner's
# free-form severity maps through the same table when it matches (uppercased).
_IAC_SEVERITY_PAIRS: tuple[tuple[str, str], ...] = (
    ("CRITICAL", "critical"),
    ("HIGH", "high"),
    ("MEDIUM", "medium"),
    ("LOW", "low"),
)
_IAC_SEVERITY: dict[str, str] = dict(_IAC_SEVERITY_PAIRS)

# Semgrep passes through its own INFO/WARNING/ERROR vocabulary.
_SEMGREP_SEVERITY_PAIRS: tuple[tuple[str, str], ...] = (
    ("ERROR", "high"),
    ("WARNING", "medium"),
    ("INFO", "info"),
)
_SEMGREP_SEVERITY: dict[str, str] = dict(_SEMGREP_SEVERITY_PAIRS)


def normalize_iac_severity(value: str) -> str:
    """Map an IaC/K8s severity string to the normalized vocabulary (else ``unknown``)."""

    return _IAC_SEVERITY.get(value.strip().upper(), "unknown")


def normalize_semgrep_severity(value: str) -> str:
    """Map a Semgrep severity string to the normalized vocabulary (else ``unknown``)."""

    return _SEMGREP_SEVERITY.get(value.strip().upper(), "unknown")


_EVIDENCE_DIR = Path(".oss-policy-kit") / "evidence"


def _source(tool: str, rel_path: str, raw: dict[str, Any]) -> FindingSource:
    return FindingSource(
        tool=tool,
        source_path=rel_path,
        rule=str(raw.get("rule_id") or ""),
        severity_original=str(raw.get("severity") or ""),
        message=str(raw.get("message") or ""),
    )


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(v) for v in value if isinstance(v, str) and v.strip())


def _opt_int(value: Any) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def _normalize_semgrep(tool: str, rel_path: str, raw: dict[str, Any]) -> NormalizedFinding:
    severity_original = str(raw.get("severity") or "")
    return NormalizedFinding(
        id="",
        sources=(_source(tool, rel_path, raw),),
        rule=str(raw.get("rule_id") or ""),
        message=str(raw.get("message") or ""),
        severity=SeverityView(
            normalized=normalize_semgrep_severity(severity_original),
            by_source=((tool, severity_original),),
        ),
        location=FindingLocation(
            file=str(raw.get("file")) if raw.get("file") else None,
            line_start=_opt_int(raw.get("line_start")),
            line_end=_opt_int(raw.get("line_end")),
        ),
        cwe=_str_tuple(raw.get("cwe")),
        owasp=_str_tuple(raw.get("owasp")),
    )


def _normalize_iac(tool: str, rel_path: str, raw: dict[str, Any]) -> NormalizedFinding:
    severity_original = str(raw.get("severity") or "")
    return NormalizedFinding(
        id="",
        sources=(_source(tool, rel_path, raw),),
        rule=str(raw.get("rule_id") or ""),
        message=str(raw.get("message") or ""),
        severity=SeverityView(
            normalized=normalize_iac_severity(severity_original),
            by_source=((tool, severity_original),),
        ),
        location=FindingLocation(
            file=str(raw.get("file")) if raw.get("file") else None,
            line_start=_opt_int(raw.get("line_start")),
            logical=LogicalLocation(
                type="resource",
                resource_type=str(raw.get("resource_type")) if raw.get("resource_type") else None,
                resource_name=str(raw.get("resource_name")) if raw.get("resource_name") else None,
            ),
        ),
    )


def _normalize_k8s(tool: str, rel_path: str, raw: dict[str, Any]) -> NormalizedFinding:
    severity_original = str(raw.get("severity") or "")
    return NormalizedFinding(
        id="",
        sources=(_source(tool, rel_path, raw),),
        rule=str(raw.get("rule_id") or ""),
        message=str(raw.get("message") or ""),
        severity=SeverityView(
            normalized=normalize_iac_severity(severity_original),
            by_source=((tool, severity_original),),
        ),
        location=FindingLocation(
            file=str(raw.get("file")) if raw.get("file") else None,
            logical=LogicalLocation(
                type="k8s-object",
                kind=str(raw.get("kind")) if raw.get("kind") else None,
                namespace=str(raw.get("namespace")) if raw.get("namespace") else None,
                name=str(raw.get("name")) if raw.get("name") else None,
            ),
        ),
    )


#: Registry of the six kit evidence sources: (filename, default tool label, normalizer).
#: Adding a source is a data-registration change here, never a schema change.
KIT_EVIDENCE_SOURCES: tuple[tuple[str, str, Callable[[str, str, dict[str, Any]], NormalizedFinding]], ...] = (
    ("sast-semgrep.json", "semgrep", _normalize_semgrep),
    ("iac-terraform.json", "oss-policy-kit-iac-parser", _normalize_iac),
    ("iac-cfn.json", "oss-policy-kit-cfn-parser", _normalize_iac),
    ("iac-pulumi.json", "oss-policy-kit-pulumi-parser", _normalize_iac),
    ("iac-bicep.json", "oss-policy-kit-bicep-parser", _normalize_iac),
    ("k8s-baseline.json", "oss-policy-kit-k8s-parser", _normalize_k8s),
)

_KNOWN_SCANNER_STATUSES = frozenset({"ok", "not_available", "error", "timeout"})


def _read_source(repo_root: Path, filename: str, default_tool: str) -> tuple[dict[str, Any] | None, SourceRecord]:
    """Read one evidence file, returning (payload-or-None, honest SourceRecord)."""

    rel = (_EVIDENCE_DIR / filename).as_posix()
    path = repo_root / _EVIDENCE_DIR / filename
    if not path.is_file():
        return None, SourceRecord(path=rel, kind="kit-evidence", tool=default_tool, status="missing")
    if oversize_reason(path, MAX_EVIDENCE_BYTES, label=filename) is not None:
        return None, SourceRecord(path=rel, kind="kit-evidence", tool=default_tool, status="oversize")
    try:
        # RecursionError guards deeply-nested input: json.loads raises it (not
        # JSONDecodeError) past the recursion limit, and it must degrade to an
        # honest "unreadable" record, never crash correlate-findings with exit 3.
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None, SourceRecord(path=rel, kind="kit-evidence", tool=default_tool, status="unreadable")
    if not isinstance(payload, dict):
        return None, SourceRecord(path=rel, kind="kit-evidence", tool=default_tool, status="unreadable")

    tool = str(payload.get("tool") or default_tool)
    raw_status = str(payload.get("status") or "ok")
    status = raw_status if raw_status in _KNOWN_SCANNER_STATUSES else "error"
    record = SourceRecord(
        path=rel,
        kind="kit-evidence",
        tool=tool,
        status=status,
        tool_version=str(payload["tool_version"]) if payload.get("tool_version") else None,
        schema_version=str(payload["schema_version"]) if payload.get("schema_version") else None,
    )
    return payload, record


def kit_evidence_partial_scan_warnings(repo_root: Path) -> list[str]:
    """Name the source files the scanners could not parse, per evidence file.

    A scanner that cannot decode a file records it in `diagnostics.parse_errors` and scans on.
    The correlated artifact is then honestly labelled -- `sources_read` says the evidence file
    was read `ok`, and it was -- while `findings_total` counts only what the scanners managed
    to look at. Nothing in the artifact said a file had been skipped, and `--fail-on-severity`
    gates pipelines on that number.

    `sources_read[].status` is a closed enum with `additionalProperties: false`, so the record
    itself cannot carry this. `extensions` is the contract's sanctioned free-form block and
    already carries `waiver_warnings` the same way.

    Shares `unread_source_files` with the control evaluators so "the scanner could not read
    this" has one definition rather than two that drift.
    """

    warnings: list[str] = []
    for filename, default_tool, _normalizer in KIT_EVIDENCE_SOURCES:
        payload, _record = _read_source(repo_root, filename, default_tool)
        if payload is None:
            continue
        shown, total = unread_sources(payload)
        if shown:
            warnings.append(
                f"{filename}: the scanner could not parse {_phrase(shown, total)}, so findings from "
                "those file(s) are absent from this artifact."
            )
    return warnings


def normalize_kit_evidence(repo_root: Path) -> tuple[list[NormalizedFinding], list[SourceRecord]]:
    """Project every kit evidence file under *repo_root* into normalized findings.

    Deterministic: sources are visited in registry order and findings keep
    their in-file order. Sources that are missing, oversize, unreadable, or
    reported non-ok by their scanner contribute an honest record and no
    findings (a non-ok scanner run may still carry a findings list; it is
    normalized so nothing observed is dropped).
    """

    findings: list[NormalizedFinding] = []
    records: list[SourceRecord] = []
    for filename, default_tool, normalizer in KIT_EVIDENCE_SOURCES:
        payload, record = _read_source(repo_root, filename, default_tool)
        if payload is None:
            records.append(record)
            continue
        raw_findings = payload.get("findings")
        if not isinstance(raw_findings, list):
            # The findings CONTAINER itself is malformed (present but wrong type):
            # demote to "error" so a consumer can tell it from a genuine empty
            # list. A payload with no "findings" key stays at its reported status.
            if "findings" in payload:
                record = replace(record, status="error")
            records.append(record)
            continue
        records.append(record)
        rel = (_EVIDENCE_DIR / filename).as_posix()
        for raw in raw_findings:
            if isinstance(raw, dict):
                findings.append(normalizer(record.tool, rel, raw))
    return findings, records
