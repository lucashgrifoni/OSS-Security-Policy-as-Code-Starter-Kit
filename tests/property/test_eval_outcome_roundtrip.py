"""Property-based tests for EvalOutcome JSON roundtrip."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from oss_policy_kit.domain.models import ControlStatus, EvalOutcome, EvidenceCollectionMethod

status_strategy = st.sampled_from(list(ControlStatus))
method_strategy = st.sampled_from(list(EvidenceCollectionMethod))
safe_text = st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:;_-/", max_size=200)


@given(
    status=status_strategy,
    reason=safe_text,
    remediation=safe_text,
    evidence_sources=st.lists(safe_text, max_size=8),
    confidence=st.sampled_from(["low", "medium", "high"]),
    method=method_strategy,
    warnings=st.lists(safe_text, max_size=5),
)
@settings(max_examples=50, deadline=None)
def test_eval_outcome_asdict_json_roundtrip(
    status: ControlStatus,
    reason: str,
    remediation: str,
    evidence_sources: list[str],
    confidence: str,
    method: EvidenceCollectionMethod,
    warnings: list[str],
) -> None:
    outcome = EvalOutcome(
        status=status,
        reason=reason,
        remediation=remediation,
        evidence_sources=evidence_sources,
        confidence=confidence,
        evidence_collection_method=method,
        operational_warnings=tuple(warnings),
    )

    encoded = json.dumps(asdict(outcome))
    decoded = json.loads(encoded)

    assert decoded["status"] == status.value
    assert decoded["evidence_collection_method"] == method.value
    assert decoded["evidence_sources"] == evidence_sources
    assert decoded["operational_warnings"] == warnings


@given(status=status_strategy, reason=safe_text, remediation=safe_text)
@settings(max_examples=30, deadline=None)
def test_eval_outcome_can_be_reconstructed_from_json(status: ControlStatus, reason: str, remediation: str) -> None:
    payload = {
        "status": status.value,
        "reason": reason,
        "remediation": remediation,
        "evidence_sources": ["README.md"],
        "confidence": "medium",
        "evidence_collection_method": EvidenceCollectionMethod.STATIC.value,
        "operational_warnings": [],
    }
    typed_payload: dict[str, Any] = payload

    reconstructed = EvalOutcome(
        status=ControlStatus(typed_payload["status"]),
        reason=typed_payload["reason"],
        remediation=typed_payload["remediation"],
        evidence_sources=list(typed_payload["evidence_sources"]),
        confidence=typed_payload["confidence"],
        evidence_collection_method=EvidenceCollectionMethod(typed_payload["evidence_collection_method"]),
        operational_warnings=tuple(typed_payload["operational_warnings"]),
    )

    assert reconstructed.status is status
    assert reconstructed.reason == reason
    assert reconstructed.remediation == remediation
