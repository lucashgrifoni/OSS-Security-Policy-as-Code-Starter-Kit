"""Core domain types for evaluation results."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any


class ControlStatus(StrEnum):
    """Normalized outcome for a single control."""

    PASS = "pass"
    FAIL = "fail"
    MANUAL_REVIEW_REQUIRED = "manual-review-required"
    SELF_ATTESTED = "self-attested"
    # ATTESTED (ADR-028, v8.x): a passing verdict anchored on a *verified* attestation
    # (in-toto + cosign keyless), distinct from SELF_ATTESTED (maintainer self-claim) and
    # from a deterministic PASS. Emitted by PROV-VERIFY-061 and GH-IMMUTREL-070, and
    # `evaluate --enable-attested` defaults to on since v8.0.0 (ADR-041), so a stock run
    # reaches it whenever the verification record is complete and fresh.
    ATTESTED = "attested"
    NOT_EVALUATED = "not-evaluated"
    NOT_OBSERVABLE = "not-observable"
    NOT_APPLICABLE = "not-applicable"
    WAIVED = "waived"


class EvidenceCollectionMethod(StrEnum):
    """How evidence backing a control outcome was obtained."""

    LIVE = "live"
    MANUAL = "manual"
    STATIC = "static"


@dataclass(frozen=True, slots=True)
class LiveCollectionMetadata:
    """Metadata when live platform evidence collection was performed for a run."""

    performed: bool
    platform: str | None = None
    collected_at: str | None = None
    api_evidence_sources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EvalOutcome:
    """Raw outcome before catalog merge and waivers."""

    status: ControlStatus
    reason: str
    remediation: str
    evidence_sources: list[str]
    confidence: str
    evidence_collection_method: EvidenceCollectionMethod = EvidenceCollectionMethod.STATIC
    operational_warnings: tuple[str, ...] = ()
    #: Optional per-control metadata projected onto ``ControlResult.extra`` (e.g.
    #: ``{"provenance": "self-reported"}`` for ADR-033 Insights-derived verdicts).
    #: Default empty so existing evaluators are unaffected.
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class WaiverRecord:
    """Versioned waiver applied during evaluation."""

    control_id: str
    justification: str
    owner: str
    status: str
    expires_at: date | None
    applies_to: list[str] | None


@dataclass(frozen=True, slots=True)
class ControlResult:
    """Single control evaluation row."""

    control_id: str
    title: str
    category: str
    status: ControlStatus
    profile: str
    evidence_sources: list[str]
    confidence: str
    reason: str
    remediation: str
    lifecycle: str = "stable"
    assurance: str = "signal"
    owner: str | None = None
    waiver: WaiverRecord | None = None
    expires_at: date | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    evidence_collection_method: str = "static"
    deprecation_note: str | None = None
    weight: int = 1


@dataclass(frozen=True, slots=True)
class WeightedScore:
    """Risk-adjusted posture score derived from control weights."""

    earned: int
    possible: int
    percent: float


@dataclass(frozen=True, slots=True)
class ExecutionReport:
    """Full evaluation run."""

    schema_version: str
    generated_at: str
    kit_version: str
    target_path: str
    profile_id: str
    profile_title: str
    summary_by_status: dict[str, int]
    results: list[ControlResult]
    operational_warnings: list[str]
    scorecard_path: str | None = None
    scorecard_supplemental: dict[str, Any] | None = None
    #: Absolute path to a waiver file passed via `--waivers` (not versioned in-repo policy).
    external_waiver_path: str | None = None
    live_collection: LiveCollectionMetadata | None = None
    weighted_score: WeightedScore | None = None


def utc_now() -> datetime:
    """Current UTC datetime, honouring ``SOURCE_DATE_EPOCH`` (reproducible builds).

    Every clock read that can change an evaluation OUTCOME (evidence freshness,
    waiver expiry, attestation-freshness windows) flows through this helper so a
    reproducible-build environment — or the test suite — can pin the evaluation
    date via the standard ``SOURCE_DATE_EPOCH`` environment variable. With the
    variable unset, behaviour is unchanged (``datetime.now(UTC)``).
    """

    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw:
        try:
            epoch = int(raw.strip())
        except ValueError:
            epoch = -1
        if epoch >= 0:
            return datetime.fromtimestamp(epoch, tz=UTC)
    return datetime.now(UTC)


def utc_today() -> date:
    """Current UTC date for waiver expiry checks (honours ``SOURCE_DATE_EPOCH``)."""

    return utc_now().date()
