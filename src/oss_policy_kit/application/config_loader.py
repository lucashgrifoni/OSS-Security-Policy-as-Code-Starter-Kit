"""Loader for the persisted ``oss-policy-kit.yaml`` project config.

This module is the read-side counterpart of :mod:`init_writer`. It locates
the config file under a target directory, parses it safely, validates the
schema version, and returns a :class:`ProjectConfig` that ``evaluate`` can
use as a fallback when the user omits flags such as ``--profile``.

Design notes:

- We never auto-discover the config above ``--target`` (no parent walk).
  Keeping discovery lexically explicit avoids surprising behavior in
  monorepos and CI environments.
- The loader is permissive about *missing* fields: only fields that the
  CLI consumes are required, everything else is metadata.
- Schema mismatches surface as :class:`InvalidInputError` so the CLI can
  produce a clean exit code 2 with a friendly message.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oss_policy_kit.domain.errors import InvalidInputError

#: Filename of the persisted project config; matches ``init_planner``.
CONFIG_FILENAME = "oss-policy-kit.yaml"

#: Schema versions the loader can read. Add new versions here when the
#: contract changes; never remove an old version without a major bump.
SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset(
    {"oss-policy-kit/config/v1"},
)

#: Allowed values for the ``fail_on`` field. Mirrors ``cli/common.py``.
SUPPORTED_FAIL_ON: frozenset[str] = frozenset({"none", "fail", "degraded"})


@dataclass(slots=True, frozen=True)
class ProjectConfig:
    """Validated view of the persisted project config.

    Attributes:
        path: Absolute path to the config file the values came from.
        schema_version: The exact schema version string read from disk.
        profile: Profile ID to use when ``evaluate --profile`` is omitted.
        fail_on: Default fail-on policy when the flag is omitted.
        output_dir: Default output directory when ``--output-dir`` is omitted.
        report_json_contract: Default report contract version (``1.0`` etc).
        detected_platform: Best-effort platform recorded by ``init``.
        detected_primary_stack: Optional language stack recorded by ``init``.
    """

    path: Path
    schema_version: str
    profile: str
    fail_on: str
    output_dir: str
    report_json_contract: str
    detected_platform: str | None
    detected_primary_stack: str | None


def find_project_config(target: Path) -> Path | None:
    """Return the absolute path to the config under ``target`` or ``None``.

    The lookup is intentionally non-recursive: only the directory passed in
    is inspected. Returning ``None`` (rather than raising) lets the CLI
    layer decide whether the absence is fatal in the current invocation.
    """

    candidate = (target / CONFIG_FILENAME).resolve()
    return candidate if candidate.is_file() else None


def _require_str(payload: dict[str, Any], key: str, *, where: Path) -> str:
    """Pull a non-empty string field from ``payload`` or raise."""

    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InvalidInputError(
            f"{where.name}: required field {key!r} is missing or empty.",
        )
    return value.strip()


def _optional_str(payload: dict[str, Any], key: str) -> str | None:
    """Return a stripped string for ``key`` or ``None`` when absent/null."""

    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def load_project_config(path: Path) -> ProjectConfig:
    """Parse and validate ``path`` into a :class:`ProjectConfig`.

    Args:
        path: Absolute path to the config file.

    Raises:
        InvalidInputError: When the file is unreadable, not valid YAML,
            uses an unknown schema, or lacks required fields.
    """

    if not path.is_file():
        raise InvalidInputError(f"Config file not found: {path}.")

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"Could not read {path}: {exc}.") from exc

    try:
        payload = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise InvalidInputError(f"{path.name}: invalid YAML: {exc}.") from exc

    if not isinstance(payload, dict):
        raise InvalidInputError(
            f"{path.name}: root must be a mapping (got {type(payload).__name__}).",
        )

    schema_version = _require_str(payload, "schema_version", where=path)
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
        raise InvalidInputError(
            f"{path.name}: unsupported schema_version {schema_version!r}. "
            f"Supported: {supported}. Re-run `oss-policy-kit init --force` "
            "to regenerate the file.",
        )

    profile = _require_str(payload, "profile", where=path)
    fail_on = _require_str(payload, "fail_on", where=path).lower()
    if fail_on not in SUPPORTED_FAIL_ON:
        raise InvalidInputError(
            f"{path.name}: fail_on must be one of: none, fail, degraded (got {fail_on!r}).",
        )

    output_dir = _require_str(payload, "output_dir", where=path)
    report_contract = _optional_str(payload, "report_json_contract") or "1.0"

    detected = payload.get("detected", {}) or {}
    if not isinstance(detected, dict):
        detected = {}

    return ProjectConfig(
        path=path,
        schema_version=schema_version,
        profile=profile,
        fail_on=fail_on,
        output_dir=output_dir,
        report_json_contract=report_contract,
        detected_platform=_optional_str(detected, "platform"),
        detected_primary_stack=_optional_str(detected, "primary_stack"),
    )


def load_project_config_for_target(target: Path) -> ProjectConfig | None:
    """Convenience wrapper: locate and load the config under ``target``.

    Returns ``None`` when no config file exists; raises when one exists
    but is invalid. This matches the CLI behavior of "config is optional,
    but a broken config is always an error".
    """

    found = find_project_config(target)
    if found is None:
        return None
    return load_project_config(found)
