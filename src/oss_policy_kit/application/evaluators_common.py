"""Shared evaluator helpers.

Holds the small set of building blocks reused across evaluator modules
(``evaluators.py``, ``evaluators_iac.py``, ``evaluators_fuzzing.py``,
and the upcoming ``evaluators_containers.py`` / ``evaluators_k8s.py``).

The helpers here are intentionally narrow:

- :func:`evidence_is_api_backed` distinguishes live API-collected JSON
  from manual scaffold output (used to upgrade outcomes to PASS only when
  the evidence chain is trustworthy).
- :func:`evidence_placeholder_outcome` returns a NOT_EVALUATED outcome
  when scaffold-style placeholder tokens leak into committed evidence.
- :func:`validate_json_evidence` runs Draft202012 schema validation and
  surfaces placeholders.
- :func:`is_valid_sha256_digest` rejects empty/low-entropy/template
  digest strings before they can satisfy artifact-bound controls.
- :func:`load_packaged_schema` reads a JSON schema bundled under
  ``oss_policy_kit.data.schema``.

This module is part of the v5.6 refactor that is gradually splitting
``application/evaluators.py`` along category boundaries. The legacy
underscore-prefixed aliases inside ``evaluators.py`` continue to work so
existing call sites keep their byte-equivalent semantics.
"""

from __future__ import annotations

import importlib.resources as ir
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from oss_policy_kit.application.evidence_placeholders import has_placeholder_values
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

DIGEST_PLACEHOLDER_REASON = (
    "Evidence file digest fields contain template/placeholder values. Replace with real SHA256 digests "
    "from the actual release artifacts."
)

INVALID_DIGEST_REASON = (
    "Artifact digest is a placeholder or invalid SHA-256 value. Replace with the actual artifact digest."
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_WEAK_DIGEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^(.)\1{63}$"),
    re.compile(r"^(..)\1{31}$"),
    re.compile(r"^0{64}$"),
)


def evidence_is_api_backed(data: dict[str, Any]) -> bool:
    """True when JSON was produced by ``collect-evidence`` / cloud API collection (not manual scaffold)."""

    att = str(data.get("attested_by", "")).strip().lower()
    if att in ("aws-api-collection", "azure-devops-api-collection", "github-api-collection"):
        return True
    coll = data.get("collection")
    if isinstance(coll, dict):
        if str(coll.get("evidence_collection_method", "")).strip().lower() == "live":
            return True
        if str(coll.get("mode", "")).strip().lower() == "api":
            return True
    return False


def evidence_placeholder_outcome(evidence: Path, placeholders: list[str]) -> EvalOutcome | None:
    """Return a :class:`EvalOutcome` when scaffold-style placeholders remain in evidence JSON."""

    if not placeholders:
        return None
    preview = ", ".join(placeholders[:5])
    return EvalOutcome(
        status=ControlStatus.NOT_EVALUATED,
        reason=(
            f"Evidence file {evidence.name} contains unfilled placeholder tokens ({preview}). "
            "Replace template values before relying on this control."
        ),
        remediation="Edit the evidence JSON and remove REPLACE_ME-style placeholders and template dates.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        operational_warnings=(f"Evidence {evidence.name}: placeholder tokens ({preview}).",),
    )


def validate_json_evidence(
    evidence: Path,
    *,
    schema_loader: Callable[[], dict[str, Any]],
    evidence_name: str,
) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    """Validate *evidence* JSON against a Draft202012 schema. Returns ``(data, error, placeholders)``."""

    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{evidence_name} evidence is unreadable or invalid JSON: {exc}", []
    if not isinstance(data, dict):
        return None, f"{evidence_name} evidence root must be a JSON object.", []
    try:
        Draft202012Validator(schema_loader()).validate(data)
    except ValidationError as exc:
        loc = "/".join(str(p) for p in exc.absolute_path) if exc.absolute_path else "root"
        return None, f"{evidence_name} evidence does not match schema: {exc.message} (at {loc})", []
    return data, None, has_placeholder_values(data)


def is_valid_sha256_digest(value: object) -> bool:
    """Return True only when *value* is a plausible, non-placeholder SHA-256 hex digest.

    A digest is rejected when any of the following is true:

    - value is not a string
    - value is not 64 lowercase hexadecimal characters
    - value matches a low-entropy placeholder pattern (``0..0``, ``aa..aa``, ``ab ab ...``)
    """

    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    if not _SHA256_PATTERN.match(normalized):
        return False
    return not any(pat.match(normalized) for pat in _WEAK_DIGEST_PATTERNS)


def load_packaged_schema(filename: str) -> dict[str, Any]:
    """Load a JSON schema from ``oss_policy_kit.data.schema``."""

    raw = ir.files("oss_policy_kit.data.schema").joinpath(filename).read_bytes()
    return cast(dict[str, Any], json.loads(raw))
