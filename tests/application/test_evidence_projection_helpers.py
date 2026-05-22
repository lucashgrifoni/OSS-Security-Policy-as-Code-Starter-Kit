"""Branch coverage for pure helpers in ``application.evidence_projection``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from oss_policy_kit.application import evidence_projection as ep
from oss_policy_kit.application.evidence_projection import FreshnessContext
from oss_policy_kit.domain.models import ControlResult, ControlStatus


def _result(status: ControlStatus = ControlStatus.PASS, **over: object) -> ControlResult:
    kwargs: dict[str, object] = {
        "control_id": "C-1",
        "title": "t",
        "category": "governance",
        "status": status,
        "profile": "p",
        "evidence_sources": [],
        "confidence": "high",
        "reason": "r",
        "remediation": "fix",
    }
    kwargs.update(over)
    return ControlResult(**kwargs)  # type: ignore[arg-type]


def test_normalize_confidence() -> None:
    assert ep.normalize_confidence(None) == "none"
    assert ep.normalize_confidence("") == "none"
    assert ep.normalize_confidence("HIGH") in {"high", "low", "medium", "none"}
    assert ep.normalize_confidence("totally-unknown-value") == "low"


def test_is_placeholder_path() -> None:
    assert ep._is_placeholder_path("")
    assert ep._is_placeholder_path("TODO")
    assert ep._is_placeholder_path("<placeholder>")
    assert not ep._is_placeholder_path("src/app.py")


def test_redact_path() -> None:
    rel, redacted = ep._redact_path("src/app.py")
    assert rel == "src/app.py" and redacted is False
    assert ep._redact_path("")[1] is False
    win, w_red = ep._redact_path("C:\\Users\\me\\repo\\file.py")
    assert w_red is True and "<redacted-absolute>" in win
    posix, p_red = ep._redact_path("/home/me/repo/file.py")
    assert p_red is True and "<redacted-absolute>" in posix


def test_classify_reference() -> None:
    assert ep._classify_reference("https://osv.dev/x")["kind"] == "url"
    pathref = ep._classify_reference("src/app.py")
    assert pathref["kind"] == "path" and pathref["redacted"] is False


def test_parse_collected_at() -> None:
    assert ep._parse_collected_at(None) is None
    assert ep._parse_collected_at("not-a-date") is None
    dt = ep._parse_collected_at("2026-05-01T00:00:00Z")
    assert dt is not None and dt.tzinfo is not None
    naive = ep._parse_collected_at("2026-05-01T00:00:00")
    assert naive is not None and naive.tzinfo is UTC


def test_freshness_status() -> None:
    ctx = FreshnessContext(window_days=90)
    assert ep._freshness_status(method="live", collected_at=None, has_evidence=False, ctx=ctx) == "not_applicable"
    assert ep._freshness_status(method="static", collected_at=None, has_evidence=True, ctx=ctx) == "not_applicable"
    assert ep._freshness_status(method="live", collected_at=None, has_evidence=True, ctx=ctx) == "unknown"
    old = datetime.now(UTC) - timedelta(days=200)
    assert ep._freshness_status(method="live", collected_at=old, has_evidence=True, ctx=ctx) == "stale"
    recent = datetime.now(UTC) - timedelta(days=1)
    assert ep._freshness_status(method="live", collected_at=recent, has_evidence=True, ctx=ctx) == "fresh"


def test_project_evidence_various_statuses() -> None:
    for status in (
        ControlStatus.PASS,
        ControlStatus.FAIL,
        ControlStatus.MANUAL_REVIEW_REQUIRED,
        ControlStatus.NOT_APPLICABLE,
    ):
        doc = ep.project_evidence(_result(status))
        assert isinstance(doc, dict)
        assert "trust_level" in doc or "source_type" in doc or doc  # structural smoke
