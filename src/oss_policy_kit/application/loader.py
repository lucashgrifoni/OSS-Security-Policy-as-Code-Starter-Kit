"""Load bundled or custom catalog and profiles."""

from __future__ import annotations

import importlib.resources as ir
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from oss_policy_kit.application.input_limits import BAD_INPUT_ERRORS, bad_input_detail, too_deep_reason
from oss_policy_kit.domain.errors import LoadError, ProfileLoadError

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


def _load_kit_yaml(path: Path, *, label: str) -> Any:
    """Read and parse a catalog/profile YAML under the SHARED nesting budget.

    Reading through :func:`oss_policy_kit.infrastructure.yaml_io.load_yaml_file` left the
    depth budget to ``RecursionError``, which flow-style YAML simply never reaches: a
    ``profile.yaml`` nested 250 levels parsed happily here, so ``evaluate`` exited 0 and
    evaluated the profile while ``diff-catalogs`` — which reads the very same file through
    ``load_capped_document`` — refused it with exit 2. Two commands disagreeing about the
    same bytes is the defect.

    The guard, the 200-level budget and the wording all come from
    :mod:`oss_policy_kit.application.input_limits`; this is deliberately not a second
    depth scanner or a second error vocabulary. ``yaml.safe_load`` mirrors
    ``load_yaml_file`` exactly (safe loader only) — the text is only needed here because
    the budget is checked before the parser sees it.

    *label* is the capitalised noun (``"Catalog"`` / ``"Profile"``); every message names
    the file by its bare name only, because ``merge_kit_root`` and ``load_profile_by_id``
    both hand this function a RESOLVED path whose directories would leak the cwd, home
    directory and OS account name (M-002).
    """

    try:
        text = path.read_text(encoding="utf-8")
        too_deep = too_deep_reason(text, label=f"{label} '{path.name}'")
        if too_deep is not None:
            # Complete and path-free in the shared wording already; wrapping it in
            # "Failed to load ..." would only name the file twice.
            raise LoadError(too_deep)
        return cast(Any, yaml.safe_load(text))
    except LoadError:
        raise
    except OSError as exc:
        raise LoadError(f"Failed to load {label.lower()} '{path.name}': {exc.strerror or 'unreadable'}") from exc
    except BAD_INPUT_ERRORS as exc:
        # Shared taxonomy: malformed YAML, nesting past the parser stack, an integer
        # literal past CPython's conversion limit. Already exit 2 before this change;
        # bad_input_detail replaces the raw interpreter text with actionable wording.
        raise LoadError(f"Failed to load {label.lower()} '{path.name}': {bad_input_detail(exc)}") from exc
    except Exception as exc:  # noqa: BLE001
        # Parse errors (YAML) reference the in-memory buffer, not the path on disk.
        raise LoadError(f"Failed to load {label.lower()} '{path.name}': {exc}") from exc


def _profile_spec_validator() -> Draft202012Validator:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("profile-spec.schema.json").read_bytes()
    schema = json.loads(raw.decode("utf-8"))
    return Draft202012Validator(schema)


_ASSURANCE_VALUES = frozenset({"deterministic", "signal", "evidence-backed"})


@dataclass(frozen=True, slots=True)
class ApplicabilitySpec:
    """Declared, inspectable precondition for a control (ADR-028).

    ``requires_any_files`` is a list of glob patterns (relative to the repo root);
    the control is applicable when at least one pattern matches a real file. The
    predicate is purely filesystem-inspectable — no code execution. Empty means
    "always applicable" (equivalent to no precondition).
    """

    requires_any_files: tuple[str, ...] = ()


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
    #: Optional declared precondition (ADR-028). Only consulted when the
    #: applicability engine is enabled (opt-in); otherwise ignored.
    applicability: ApplicabilitySpec | None = None


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


_APPLICABILITY_KEYS = frozenset({"requires_any_files"})


def _parse_applicability(cid: str, raw: object) -> ApplicabilitySpec | None:
    """Parse and validate an optional ``applicability`` block (ADR-028); fail-closed on typos.

    Returns ``None`` when no block is declared. Raises :class:`LoadError` for a
    malformed block so a typo cannot silently disable a precondition.
    """

    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise LoadError(f"Control {cid}: 'applicability' must be a mapping.")
    unknown = set(raw) - _APPLICABILITY_KEYS
    if unknown:
        raise LoadError(
            f"Control {cid}: unknown applicability key(s) {sorted(unknown)}; expected {sorted(_APPLICABILITY_KEYS)}."
        )
    files = raw.get("requires_any_files", [])
    if not isinstance(files, list) or not files:
        raise LoadError(f"Control {cid}: applicability.requires_any_files must be a non-empty list of glob strings.")
    patterns = tuple(str(p).strip() for p in files if str(p).strip())
    if not patterns:
        raise LoadError(f"Control {cid}: applicability.requires_any_files contains no usable glob patterns.")
    return ApplicabilitySpec(requires_any_files=patterns)


def load_catalog(controls_yaml: Path) -> dict[str, ControlSpec]:
    """Load control catalog."""

    raw = _load_kit_yaml(controls_yaml, label="Catalog")
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
            applicability=_parse_applicability(cid, item.get("applicability")),
        )
    if not out:
        raise LoadError("Catalog contains no controls")
    return out


def load_profile(path: Path, *, validate_external_schema: bool = False) -> ProfileSpec:
    """Load a single profile YAML.

    When *validate_external_schema* is True, validate the parsed document against
    ``profile-spec.schema.json`` (used for ``--profile`` filesystem paths).
    """

    # M-002: ``path`` may be a resolved absolute path (an external ``--profile`` file is
    # resolved by ``load_profile_by_id``), so every user-facing message below echoes only
    # the basename — never the full path, which would leak cwd/home/OS username.
    display = path.name
    raw = _load_kit_yaml(path, label="Profile")
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
            raise ProfileLoadError(
                f"External profile failed schema validation ('{display}'): {raw_msg}.{hint}"
            ) from exc
    pid = str(raw.get("id", "")).strip()
    if not pid:
        raise LoadError(f"Profile missing id: '{display}'")
    ctrls = raw.get("controls")
    if not isinstance(ctrls, list) or not ctrls:
        raise LoadError(f"Profile has no controls: '{display}'")
    # De-duplicate control ids preserving first-seen order (#17): an external profile that
    # lists the same control id more than once must not inflate controls_total, the
    # summary-by-status counts, or the weighted score. ``dict.fromkeys`` keeps insertion
    # order; bundled profiles carry no duplicates, so they are unaffected.
    ids = tuple(dict.fromkeys(str(x).strip() for x in ctrls if str(x).strip()))
    _raise_if_removed_controls_referenced(ids, f"Invalid profile '{display}':")
    return ProfileSpec(
        id=pid,
        title=str(raw.get("title", pid)),
        description=str(raw.get("description", "")),
        audience=str(raw.get("audience", "")),
        control_ids=ids,
    )


# Bundled profile id -> canonical directory name under ``profiles/`` for DEPRECATED aliases.
# EMPTY since v10.0.0: the last alias (`cra-eu-ready-2-1`, ADR-029) completed its one-major
# deprecation cycle and moved to REMOVED_PROFILE_IDS. The machinery stays so a future rename
# can reuse the same one-cycle pattern.
PROFILE_DIRECTORY_ALIASES: dict[str, str] = {}
BUNDLED_PROFILE_LEGACY_IDS: frozenset[str] = frozenset(PROFILE_DIRECTORY_ALIASES.keys())

# Profile ids that were removed. Resolving these raises a hard error with explicit
# migration guidance instead of silently mapping to the canonical id.
REMOVED_PROFILE_IDS: dict[str, str] = {
    "github-release-hardening": "github-release-hardening-1",
    # ADR-029: renamed in v9.0.0 (deprecated alias for one major), removed in v10.0.0.
    "cra-eu-ready-2-1": "cra-eu-conformance-evidence-1",
}
_REMOVED_PROFILE_VERSIONS: dict[str, str] = {
    "github-release-hardening": "v5.0.0",
    "cra-eu-ready-2-1": "v10.0.0",
}


def resolve_profile_file(kit_root: Path, profile_id: str) -> Path:
    """Return path to ``profiles/<id>/profile.yaml``.

    Profile ids removed in v5.0.0 raise ``LoadError`` with migration guidance.
    """

    if profile_id in REMOVED_PROFILE_IDS:
        canonical = REMOVED_PROFILE_IDS[profile_id]
        removed_in = _REMOVED_PROFILE_VERSIONS.get(profile_id, "an earlier major")
        raise LoadError(
            f"Profile id '{profile_id}' was removed in {removed_in}. "
            f"The canonical profile is '{canonical}'. "
            f"Update your scripts and CI workflows. See docs/{removed_in}-migration-guide.md."
        )
    dirname = PROFILE_DIRECTORY_ALIASES.get(profile_id, profile_id)
    candidate = kit_root / "profiles" / dirname / "profile.yaml"
    if not candidate.is_file():
        # Sanitize the location: report a repo-relative path, never the absolute
        # install/site-packages path (which would leak the OS username). A value that
        # looks like an external YAML path gets a clearer "file not found" message
        # instead of the confusing "<id>.yaml/profile.yaml" double-suffix.
        if profile_id.strip().lower().endswith((".yaml", ".yml")):
            # An ABSOLUTE value is named by its basename only, which is the same line
            # `cli.common.display_path` holds: a relative value is echoed as the operator
            # wrote it, and anything absolute loses its parent directories on purpose.
            #
            # Not hypothetical hardening. Anchoring a config-supplied profile to the target
            # made the CLI hand this message a CONSTRUCTED absolute path, so `--target .`
            # answered with the operator's full host path -- account name included -- in a
            # message written to be pasted into an issue. It was defended at the time with
            # "display_path already anonymises that message". It does not: it is never
            # applied here. Fixed at the message so every caller benefits, and without the
            # application layer importing the CLI layer.
            shown = Path(profile_id).name if Path(profile_id).is_absolute() else profile_id
            raise LoadError(
                f"Profile file not found: '{shown}'. Pass the path to an existing YAML profile, "
                "or a bundled profile id (run 'oss-policy-kit profiles' to list bundled ids)."
            )
        raise LoadError(
            f"Unknown profile '{profile_id}' (no bundled profile at data/profiles/{dirname}/profile.yaml). "
            "Run 'oss-policy-kit profiles' to list available ids."
        )
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
            # Echo the user-supplied string, never root.resolve() — the resolved path
            # leaks the cwd / home directory / OS username (M-002). Mirrors the
            # missing-catalog / bad-profile messages hardened in the same release.
            raise LoadError(f"--kit-root is not a directory: {cli_kit_root}")
        return root
    return bundled_kit_root()
