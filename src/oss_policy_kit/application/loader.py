"""Load bundled or custom catalog and profiles."""

from __future__ import annotations

import importlib.resources as ir
import json
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from oss_policy_kit.domain.errors import LoadError, ProfileLoadError
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

REMOVED_CONTROL_IDS: frozenset[str] = frozenset({"SEC-AUDIT-016", "CI-SBOM-017"})


def _raise_if_removed_controls_referenced(control_ids: tuple[str, ...], context: str) -> None:
    bad = sorted(c for c in control_ids if c in REMOVED_CONTROL_IDS)
    if not bad:
        return
    listed = ", ".join(bad)
    raise ProfileLoadError(
        f"Control(s) removed in v4.0.0: {listed}. {context} "
        "See docs/v4.0.0-migration-guide.md for replacement controls."
    )


def _profile_spec_validator() -> Draft202012Validator:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("profile-spec.schema.json").read_bytes()
    schema = json.loads(raw.decode("utf-8"))
    return Draft202012Validator(schema)


_ASSURANCE_VALUES = frozenset({"deterministic", "signal", "evidence-backed"})


@dataclass(frozen=True, slots=True)
class ControlSpec:
    """Catalog entry for a control."""

    id: str
    title: str
    category: str
    automation: str
    lifecycle: str = "stable"
    assurance: str = "signal"
    deprecation_note: str | None = None
    weight: int = 1


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    """Profile definition."""

    id: str
    title: str
    description: str
    audience: str
    control_ids: tuple[str, ...]


def bundled_kit_root() -> Path:
    """Directory containing packaged `controls/` and `profiles/`."""

    return Path(__file__).resolve().parent.parent / "data"


def load_catalog(controls_yaml: Path) -> dict[str, ControlSpec]:
    """Load control catalog."""

    try:
        raw = load_yaml_file(controls_yaml)
    except Exception as exc:  # noqa: BLE001
        raise LoadError(f"Failed to load catalog {controls_yaml}: {exc}") from exc
    if not isinstance(raw, dict):
        raise LoadError("Catalog root must be a mapping")
    items = raw.get("controls")
    if not isinstance(items, list):
        raise LoadError("Catalog must contain a 'controls' list")
    out: dict[str, ControlSpec] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        cid = str(item.get("id", "")).strip()
        if not cid:
            continue
        dep = item.get("deprecation_note")
        dep_s = str(dep).strip() if dep is not None else None
        raw_assurance = str(item.get("assurance", "signal")).strip().lower()
        if raw_assurance not in _ASSURANCE_VALUES:
            raise LoadError(
                f"Control {cid}: invalid assurance {raw_assurance!r}; expected one of {sorted(_ASSURANCE_VALUES)}."
            )
        raw_weight = item.get("weight", 1)
        try:
            weight = max(1, min(3, int(raw_weight)))
        except (TypeError, ValueError):
            weight = 1
        out[cid] = ControlSpec(
            id=cid,
            title=str(item.get("title", cid)),
            category=str(item.get("category", "general")),
            automation=str(item.get("automation", "unknown")),
            lifecycle=str(item.get("lifecycle", "stable")),
            assurance=raw_assurance,
            deprecation_note=dep_s,
            weight=weight,
        )
    if not out:
        raise LoadError("Catalog contains no controls")
    return out


def load_profile(path: Path, *, validate_external_schema: bool = False) -> ProfileSpec:
    """Load a single profile YAML.

    When *validate_external_schema* is True, validate the parsed document against
    ``profile-spec.schema.json`` (used for ``--profile`` filesystem paths).
    """

    try:
        raw = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001
        raise LoadError(f"Failed to load profile {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise LoadError("Profile root must be a mapping")
    if validate_external_schema:
        try:
            _profile_spec_validator().validate(raw)
        except ValidationError as exc:
            raw_msg = exc.message
            if "'id' is a required property" in raw_msg:
                hint = (
                    " Hint: external profiles use field 'id' (not 'profile_id'). "
                    "Required fields: id (string), title (string), controls (list of control ID strings)."
                )
            elif "is not of type 'string'" in raw_msg and "controls" in str(exc.absolute_path):
                hint = (
                    " Hint: controls must be a flat list of control ID strings. "
                    "Example: controls: [GOV-SEC-001, CI-WF-005, REL-CHANGE-012]"
                )
            else:
                hint = ""
            raise ProfileLoadError(f"External profile failed schema validation ({path}): {raw_msg}.{hint}") from exc
    pid = str(raw.get("id", "")).strip()
    if not pid:
        raise LoadError(f"Profile missing id: {path}")
    ctrls = raw.get("controls")
    if not isinstance(ctrls, list) or not ctrls:
        raise LoadError(f"Profile has no controls: {path}")
    ids = tuple(str(x).strip() for x in ctrls if str(x).strip())
    _raise_if_removed_controls_referenced(ids, f"Invalid profile {path}:")
    return ProfileSpec(
        id=pid,
        title=str(raw.get("title", pid)),
        description=str(raw.get("description", "")),
        audience=str(raw.get("audience", "")),
        control_ids=ids,
    )


# Bundled profile id -> directory name under ``profiles/`` (same id except legacy aliases).
# In v5.0.0 the legacy alias `github-release-hardening` was removed; the mapping is empty
# and kept only as a public symbol for downstream tooling that imports it.
PROFILE_DIRECTORY_ALIASES: dict[str, str] = {}
BUNDLED_PROFILE_LEGACY_IDS: frozenset[str] = frozenset(PROFILE_DIRECTORY_ALIASES.keys())

# Profile ids that were removed in v5.0.0. Resolving these raises a hard error with
# explicit migration guidance instead of silently mapping to the canonical id.
REMOVED_PROFILE_IDS: dict[str, str] = {
    "github-release-hardening": "github-release-hardening-1",
}


def resolve_profile_file(kit_root: Path, profile_id: str) -> Path:
    """Return path to ``profiles/<id>/profile.yaml``.

    Profile ids removed in v5.0.0 raise ``LoadError`` with migration guidance.
    """

    if profile_id in REMOVED_PROFILE_IDS:
        canonical = REMOVED_PROFILE_IDS[profile_id]
        raise LoadError(
            f"Profile id '{profile_id}' was removed in v5.0.0. "
            f"The canonical profile is '{canonical}' (same control set). "
            f"Update your scripts and CI workflows. See docs/v5.0.0-migration-guide.md."
        )
    dirname = PROFILE_DIRECTORY_ALIASES.get(profile_id, profile_id)
    candidate = kit_root / "profiles" / dirname / "profile.yaml"
    if not candidate.is_file():
        raise LoadError(f"Unknown profile '{profile_id}' (missing {candidate})")
    return candidate


def _is_filesystem_profile_ref(profile_id: str) -> bool:
    """Return True when *profile_id* points to an existing YAML profile file."""

    p = Path(profile_id)
    return p.is_file() and p.suffix.lower() in {".yaml", ".yml"}


def load_profile_by_id(kit_root: Path, profile_id: str) -> ProfileSpec:
    """Load profile by bundled id or by path to a YAML profile file."""

    if _is_filesystem_profile_ref(profile_id):
        return load_profile(Path(profile_id).resolve(), validate_external_schema=True)
    path = resolve_profile_file(kit_root, profile_id)
    return load_profile(path)


def merge_kit_root(cli_kit_root: Path | None) -> Path:
    """Resolve kit root: CLI override or bundled data."""

    if cli_kit_root is not None:
        root = cli_kit_root.resolve()
        if not root.is_dir():
            raise LoadError(f"--kit-root is not a directory: {root}")
        return root
    return bundled_kit_root()
