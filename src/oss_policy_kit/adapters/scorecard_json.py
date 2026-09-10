"""Optional ingestion of OpenSSF Scorecard JSON exports."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oss_policy_kit.application.input_limits import (
    BAD_INPUT_ERRORS,
    MAX_EVIDENCE_BYTES,
    bad_input_reason,
    oversize_reason,
    too_deep_reason,
)
from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file


@dataclass(slots=True)
class ScorecardCheck:
    """Normalized check entry."""

    name: str
    score: int | None
    reason: str | None = None


@dataclass(slots=True)
class ScorecardBundle:
    """Parsed Scorecard payload.

    ``aggregate_score`` is the official root ``score`` field (0-10) reported
    by the OpenSSF Scorecard CLI when present. Evaluators should prefer it
    over the arithmetic mean of check scores, which is not the same formula
    Scorecard uses internally.
    """

    checks: list[ScorecardCheck] = field(default_factory=list)
    raw_path: str | None = None
    aggregate_score: float | None = None
    #: The Scorecard run's ``date`` field (ISO-8601 string) when present, used for
    #: evidence-freshness/staleness checks by consumers. ``None`` when undated.
    result_date: str | None = None


def _coerce_checks(blob: Any) -> list[ScorecardCheck]:
    if blob is None:
        return []
    if isinstance(blob, dict) and "checks" in blob:
        blob = blob["checks"]
    if not isinstance(blob, list):
        return []
    out: list[ScorecardCheck] = []
    for item in blob:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        score = item.get("score")
        score_i = int(score) if isinstance(score, int) and not isinstance(score, bool) else None
        reason = item.get("reason") or item.get("details")
        reason_s = str(reason) if reason is not None else None
        out.append(ScorecardCheck(name=name, score=score_i, reason=reason_s))
    return out


def _coerce_aggregate_score(value: Any) -> float | None:
    """Return a well-formed Scorecard aggregate score in the 0-10 range."""

    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        score = float(value)
    else:
        return None
    if math.isnan(score):
        return None
    if score < 0.0 or score > 10.0:
        return None
    return score


def _coerce_date(value: Any) -> str | None:
    """Return a non-empty ISO-8601-ish date string, else ``None``."""

    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def load_scorecard_json(path: Path) -> ScorecardBundle:
    """Load Scorecard JSON (common CLI export shapes)."""

    try:
        text = path.read_text(encoding="utf-8")
        # Depth is checked before parsing, not left to RecursionError: the C JSON scanner
        # blows its stack on Windows and parses the same document on Linux, so the
        # exception-only guard silently did nothing on the platform CI and most adopters
        # run. See input_limits.MAX_JSON_DEPTH.
        too_deep = too_deep_reason(text, label=f"Scorecard JSON {path.name}")
        if too_deep is not None:
            raise LoadError(too_deep)
        data = json.loads(text)
    except UnicodeDecodeError as exc:
        # UTF-16/non-UTF-8 input: surface a clean LoadError (-> exit 2) instead of an exit-3
        # crash.
        raise LoadError(f"Scorecard JSON {path.name} could not be decoded as UTF-8: {exc}") from exc
    except json.JSONDecodeError:
        # Ordinary malformed JSON keeps propagating to the evaluate-path handler
        # (cli/common.py), which renders the friendly "could not be parsed
        # (line N, column M)" message users already rely on.
        raise
    except BAD_INPUT_ERRORS as exc:
        # Everything else a hostile file throws — permission denied, a directory,
        # nesting past the parser's stack (RecursionError), an integer literal past
        # CPython's 4300-digit conversion limit — is bad input, not a defect in the
        # kit, so it must not reach the CLI's exit-3 handler.
        raise LoadError(bad_input_reason(exc, label="Scorecard JSON", name=path.name)) from exc
    checks: list[ScorecardCheck] = []
    aggregate: float | None = None
    result_date: str | None = None
    if isinstance(data, dict):
        scorecard_obj = data.get("scorecard") if isinstance(data.get("scorecard"), dict) else None
        if scorecard_obj is not None:
            checks = _coerce_checks(scorecard_obj.get("checks"))
            aggregate = _coerce_aggregate_score(scorecard_obj.get("score"))
        if not checks:
            checks = _coerce_checks(data.get("checks"))
        if aggregate is None:
            aggregate = _coerce_aggregate_score(data.get("score"))
        result_date = _coerce_date(data.get("date"))
    return ScorecardBundle(
        checks=checks, raw_path=str(path.resolve()), aggregate_score=aggregate, result_date=result_date
    )


def _load_scorecard_yaml(path: Path) -> Any:
    """Read a YAML scorecard-like file, refusing bad input instead of crashing.

    The YAML branch needs the same guard as :func:`load_scorecard_json`: a
    deeply-nested document raises ``RecursionError`` out of PyYAML's composer, and
    an over-long integer scalar raises ``ValueError`` — neither is a JSON error, so
    neither was caught anywhere before reaching the CLI's exit-3 handler.
    """

    reason = oversize_reason(path, MAX_EVIDENCE_BYTES, label="Scorecard YAML")
    if reason is not None:
        raise LoadError(reason)
    try:
        # The evidence ceiling, not the CI-config default: this file is an attestation the
        # operator supplied, and the check above already admitted it at that size.
        return load_yaml_file(path, max_bytes=MAX_EVIDENCE_BYTES)
    except BAD_INPUT_ERRORS as exc:
        raise LoadError(bad_input_reason(exc, label="Scorecard YAML", name=path.name)) from exc


def load_scorecard_auto(path: Path) -> ScorecardBundle:
    """Load JSON or YAML scorecard-like file."""

    suf = path.suffix.lower()
    if suf in {".yaml", ".yml"}:
        data = _load_scorecard_yaml(path)
        checks = _coerce_checks(data if isinstance(data, dict) else None)
        aggregate: float | None = None
        result_date: str | None = None
        if isinstance(data, dict):
            aggregate = _coerce_aggregate_score(data.get("score"))
            if aggregate is None and isinstance(data.get("scorecard"), dict):
                aggregate = _coerce_aggregate_score(data["scorecard"].get("score"))
            result_date = _coerce_date(data.get("date"))
        return ScorecardBundle(
            checks=checks, raw_path=str(path.resolve()), aggregate_score=aggregate, result_date=result_date
        )
    return load_scorecard_json(path)


def checks_as_map(bundle: ScorecardBundle | None) -> dict[str, ScorecardCheck]:
    if bundle is None:
        return {}
    return {c.name.lower(): c for c in bundle.checks}
