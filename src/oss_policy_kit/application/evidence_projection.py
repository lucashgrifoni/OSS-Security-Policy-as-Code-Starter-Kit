"""Evidence Model v2 projection for the reports/1.0 contract.

Maps a v4-era ``ControlResult`` (with flat ``evidence_sources``, free-form
``confidence``, scalar ``evidence_collection_method``) into the structured
``evidence`` object required by ``reports/1.0``.

Design rules (do not silently inflate trust):

- ``assurance: signal`` controls cannot be projected with ``trust_level: verified``.
  They become ``trust_level: inferred`` at best, even when ``status == pass``.
- ``api_collected`` evidence with a recent ``collected_at`` (default freshness
  window: 90 days) projects to ``trust_level: verified``; older than the window
  becomes ``stale`` and ``trust_level: declared``.
- ``user_supplied`` evidence with no ``attested_by`` metadata projects to
  ``self_attested`` and ``trust_level: declared``.
- ``not-observable`` and ``not-applicable`` statuses route to ``not_observable`` /
  ``not_applicable`` with ``trust_level: unobserved``.

This module is read-only with respect to evaluators: it only re-shapes the
already-computed ``ControlResult`` for the ``reports/1.0`` projection. Existing
``reports/0.x`` emission paths are unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from oss_policy_kit.domain.models import ControlResult, ControlStatus

EVIDENCE_PROVENANCE_VERSION = "evidence/2.0"

# Conservative default freshness window for API-collected platform evidence.
# Stale evidence on a hard-gate profile cannot back a `verified` trust level.
DEFAULT_FRESHNESS_WINDOW_DAYS = 90

_CONFIDENCE_NORMALIZATION: dict[str, str] = {
    "high": "high",
    "strong": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "weak": "low",
    "none": "none",
    "n/a": "none",
    "not-applicable": "none",
    "not_applicable": "none",
}


def normalize_confidence(raw: str | None) -> str:
    """Map free-form ``confidence`` strings into the v1 enum."""

    if not raw:
        return "none"
    key = raw.strip().lower()
    return _CONFIDENCE_NORMALIZATION.get(key, "low")


def _is_placeholder_path(value: str) -> bool:
    v = value.strip().lower()
    if not v:
        return True
    return v in {"<placeholder>", "tbd", "todo", "n/a"}


def _redact_path(path: str) -> tuple[str, bool]:
    """Best-effort: return (redacted_value, was_redacted).

    The kit already operates on relative repo paths in most evidence sources,
    but defensive normalization here strips a leading drive letter or absolute
    POSIX root so reports/1.0 never leaks workstation paths.
    """

    p = path.strip()
    if not p:
        return p, False
    if len(p) >= 2 and p[1] == ":":
        # Windows user-profile absolute path: drop drive and home segments.
        rest = p[2:].lstrip("\\/")
        return (
            f"<redacted-absolute>/{rest.split(chr(92), 4)[-1]}" if "\\" in rest else f"<redacted-absolute>/{rest}",
            True,
        )
    if p.startswith("/"):
        # POSIX absolute path
        return f"<redacted-absolute>{p.rsplit('/', 1)[-1]}", True
    return p, False


def _classify_reference(value: str) -> dict[str, Any]:
    if value.lower().startswith(("http://", "https://")):
        return {"kind": "url", "value": value, "redacted": False}
    redacted_value, was_redacted = _redact_path(value)
    return {"kind": "path", "value": redacted_value, "redacted": was_redacted}


@dataclass(frozen=True, slots=True)
class FreshnessContext:
    """Optional freshness window override (mostly for tests and CLI flags)."""

    window_days: int = DEFAULT_FRESHNESS_WINDOW_DAYS


def _parse_collected_at(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        # Accept naive ISO8601 and assume UTC if missing tz.
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _freshness_status(
    *,
    method: str,
    collected_at: datetime | None,
    has_evidence: bool,
    ctx: FreshnessContext,
) -> str:
    if not has_evidence:
        return "not_applicable"
    if method == "static":
        # Clone-visible facts do not have a meaningful freshness window.
        return "not_applicable"
    if collected_at is None:
        return "unknown"
    now = datetime.now(UTC)
    if now - collected_at > timedelta(days=ctx.window_days):
        return "stale"
    return "fresh"


def _source_type_from_result(result: ControlResult) -> str:
    """Classify the source type from existing ControlResult fields."""

    if result.status == ControlStatus.NOT_OBSERVABLE:
        return "not_observable"
    if result.status == ControlStatus.NOT_APPLICABLE:
        return "not_observable"
    if result.status == ControlStatus.MANUAL_REVIEW_REQUIRED:
        return "manual_review"

    method = (result.evidence_collection_method or "static").lower()
    if method == "live":
        return "api_collected"
    if method == "manual":
        return "user_supplied"

    # method == "static" (clone-visible)
    if result.assurance == "signal":
        return "heuristic_signal"
    if result.assurance == "evidence-backed":
        # Static evidence-backed paths exist (placeholder JSON in repo, etc.)
        return "user_supplied"
    return "static_clone"


def _attestation_status_from_result(result: ControlResult, source_type: str) -> str:
    if source_type in {"not_observable", "manual_review"}:
        return "not_applicable"
    extra_attested = bool(result.extra.get("attested_by")) if isinstance(result.extra, dict) else False
    if source_type == "api_collected" and extra_attested:
        return "signed"
    if source_type in {"user_supplied", "api_collected"}:
        return "self_attested"
    return "none"


def _trust_level(
    *,
    result: ControlResult,
    source_type: str,
    freshness: str,
    attestation: str,
) -> str:
    """Project trust_level under the no-silent-inflation rules."""

    if result.status == ControlStatus.NOT_OBSERVABLE:
        return "unobserved"
    if result.status in (ControlStatus.NOT_APPLICABLE, ControlStatus.NOT_EVALUATED):
        return "unobserved"
    if result.status == ControlStatus.MANUAL_REVIEW_REQUIRED:
        return "inferred"

    if source_type == "heuristic_signal":
        return "inferred"
    if source_type == "static_clone":
        return "declared"
    if source_type == "user_supplied":
        return "declared"
    if source_type == "api_collected":
        if freshness == "fresh" and attestation in {"signed", "self_attested"}:
            return "verified"
        if freshness == "stale":
            return "declared"
        return "declared"
    if source_type == "derived":
        return "inferred"
    return "unobserved"


def _gate_role(status: ControlStatus) -> str:
    return {
        ControlStatus.PASS: "passed_observation",
        ControlStatus.FAIL: "ci_blocking_fail",
        ControlStatus.MANUAL_REVIEW_REQUIRED: "human_review_gate",
        ControlStatus.SELF_ATTESTED: "self_attested_declarative",
        ControlStatus.NOT_EVALUATED: "not_evaluated_limit",
        ControlStatus.WAIVED: "waived",
        ControlStatus.NOT_APPLICABLE: "not_applicable",
        ControlStatus.NOT_OBSERVABLE: "not_observable",
    }[status]


def _limitations(*, source_type: str, freshness: str, attestation: str, assurance: str) -> list[str]:
    out: list[str] = []
    if source_type == "heuristic_signal":
        out.append("Result is backed by keyword/heuristic matches; absence of match is not absence of control.")
    if source_type == "user_supplied" and attestation in {"self_attested", "none"}:
        out.append("Evidence is self-attested by the maintainer, not platform-verified.")
    if freshness == "stale":
        out.append("Evidence freshness window exceeded; re-collect before relying on this result for a release gate.")
    if freshness == "unknown":
        out.append("Evidence has no collection timestamp; freshness cannot be asserted.")
    if assurance == "signal":
        out.append("Catalog assurance is 'signal'; trust_level cannot exceed 'inferred' for this control.")
    return out


def project_evidence(result: ControlResult, *, ctx: FreshnessContext | None = None) -> dict[str, Any]:
    """Project a ControlResult into the v1 ``evidence`` object."""

    ctx = ctx or FreshnessContext()
    source_type = _source_type_from_result(result)
    method = (result.evidence_collection_method or "static").lower()
    if method not in {"live", "manual", "static"}:
        method = "static"

    collected_at_raw: str | None = None
    if isinstance(result.extra, dict):
        collected_at_raw = result.extra.get("collected_at") or result.extra.get("collection_collected_at")

    collected_at_dt = _parse_collected_at(collected_at_raw)
    has_evidence = bool(result.evidence_sources) or source_type in {"api_collected", "user_supplied"}
    freshness = _freshness_status(
        method=method,
        collected_at=collected_at_dt,
        has_evidence=has_evidence,
        ctx=ctx,
    )
    attestation = _attestation_status_from_result(result, source_type)
    trust = _trust_level(
        result=result,
        source_type=source_type,
        freshness=freshness,
        attestation=attestation,
    )

    references = [_classify_reference(s) for s in result.evidence_sources if not _is_placeholder_path(s)]

    source_platform: str | None = None
    if isinstance(result.extra, dict):
        plat = result.extra.get("source_platform") or result.extra.get("platform")
        if isinstance(plat, str) and plat.strip():
            source_platform = plat.strip()
    if source_platform is None:
        # Heuristic: derive platform from control_id prefix.
        cid = result.control_id
        if cid.startswith("AZ-"):
            source_platform = "azure"
        elif cid.startswith("AWS-"):
            source_platform = "aws"
        elif cid.startswith(("GH-", "PLAT-", "CI-", "GOV-", "REL-", "SEC-")):
            source_platform = "github" if cid.startswith(("GH-", "PLAT-")) else "local"

    limitations = _limitations(
        source_type=source_type,
        freshness=freshness,
        attestation=attestation,
        assurance=result.assurance,
    )

    digest: str | None = None
    schema_id: str | None = None
    if isinstance(result.extra, dict):
        d = result.extra.get("digest")
        if isinstance(d, str) and d.startswith("sha256:"):
            digest = d
        sid = result.extra.get("evidence_schema_id")
        if isinstance(sid, str) and sid.strip():
            schema_id = sid.strip()

    return {
        "source_type": source_type,
        "trust_level": trust,
        "collection_method": method,
        "collected_at": collected_at_raw,
        "source_platform": source_platform,
        "freshness_status": freshness,
        "attestation_status": attestation,
        "references": references,
        "limitations": limitations,
        "digest": digest,
        "evidence_schema_id": schema_id,
    }


def gate_role_for(status: ControlStatus) -> str:
    """Public helper exposing the status -> gate_role mapping."""

    return _gate_role(status)
