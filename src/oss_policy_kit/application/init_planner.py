"""Pure planning logic for the ``init`` CLI command.

This module decides *what* the ``oss-policy-kit init`` command should do
(detect platform, pick a profile, determine which optional artifacts to
generate). It deliberately does **not** read or write files: that belongs to
``init_writer`` so the planner stays trivially testable without filesystem
side effects.

Public surface:

- :class:`InitPlan` — dataclass holding every decision the writer needs.
- :func:`build_init_plan` — turn a target path plus user flags into an
  :class:`InitPlan` by reusing :func:`build_profile_recommendation`.

The planner intentionally mirrors the conservative defaults already used by
``recommend-profile``: when no platform is forced and no signals are visible,
it falls back to ``github-level-1`` so that downstream evaluation always has
a valid profile to run against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from oss_policy_kit.application.loader import (
    bundled_kit_root,
    resolve_profile_file,
)
from oss_policy_kit.application.profile_hints import (
    FEW_SIGNALS_FALLBACK_NOTE,
    STACK_LABEL_BY_SIGNAL_ID,
    ProfileRecommendation,
    build_profile_recommendation,
)
from oss_policy_kit.domain.errors import InvalidInputError, LoadError

#: Schema version for the persisted ``oss-policy-kit.yaml`` config file.
CONFIG_SCHEMA_VERSION = "oss-policy-kit/config/v1"

#: Schema version for the JSON output of ``init --format json``.
INIT_RESULT_SCHEMA_VERSION = "oss-policy-kit/init-result/v1"

#: Default profile when no platform signal is detected and the user
#: did not pass ``--profile`` or ``--platform``.
DEFAULT_FALLBACK_PROFILE = "github-level-1"

#: Default profile per platform when the user forces ``--platform`` but
#: does not pass ``--profile``.
DEFAULT_PROFILE_PER_PLATFORM: dict[str, str] = {
    "github": "github-level-1",
    "gitlab": "gitlab-level-1",
    "azure": "azure-level-1",
    "aws": "aws-level-1",
}

#: Platforms accepted by ``--platform``. Hybrid and regulatory profiles are
#: deliberately not auto-selectable here: they require a deliberate choice.
SUPPORTED_PLATFORMS: frozenset[str] = frozenset({"github", "gitlab", "azure", "aws"})

#: Platforms for which per-platform evidence templates exist and can be scaffolded
#: by ``--with-evidence``. github/gitlab/azure/aws all ship evidence templates
#: (``evidence_scaffold`` emits them; gitlab added in v6.4.0). Only ``unknown`` has no
#: templates, so ``--with-evidence`` is downgraded (with a note) for it rather than
#: silently dropped.
EVIDENCE_PLATFORMS: frozenset[str] = frozenset({"github", "gitlab", "azure", "aws"})

#: Allowed values for ``--fail-on``. Mirrors :mod:`oss_policy_kit.cli.common`.
SUPPORTED_FAIL_ON: frozenset[str] = frozenset({"none", "fail", "degraded"})

#: Filename of the persisted config written under ``--target``.
CONFIG_FILENAME = "oss-policy-kit.yaml"

#: Filename of the optional waivers stub written under ``--target``.
WAIVERS_FILENAME = "waivers.yaml"

#: Default workflow filename written under ``.github/workflows/`` for GitHub
#: targets. Azure / AWS skip workflow generation in this iteration because
#: their pipeline file location is project-specific.
GITHUB_WORKFLOW_FILENAME = "oss-policy-check.yml"


@dataclass(slots=True)
class InitPlan:
    """All decisions ``init`` needs in order to execute (or to dry-run).

    Attributes:
        target: Resolved repository root the command operates on.
        platform: One of ``github`` / ``azure`` / ``aws`` / ``unknown``.
            ``unknown`` is used when the user neither passed ``--platform``
            nor produced any platform signals; the planner still picks a
            conservative fallback profile but flags the situation.
        primary_stack: Detected primary language stack (e.g. ``Python``,
            ``Node.js``, ``Go``) or ``None`` when nothing was detected.
        signals: Stable signal IDs that drove the recommendation. Useful
            for JSON output and audit trails; never includes raw paths.
        profile: The profile ID the resulting config will reference.
        profile_source: ``user`` when the user passed ``--profile``,
            ``recommended`` when the planner chose from the recommendation,
            ``platform_default`` when ``--platform`` was forced without
            ``--profile``, ``fallback`` when nothing was detected.
        fail_on: Validated ``--fail-on`` value.
        output_dir: Path the config will reference for evaluation reports.
            Stored as a string so the YAML stays portable across OSes.
        write_config: Always ``True`` for now; reserved for future flags.
        write_waivers: Whether the writer should create ``waivers.yaml``.
        scaffold_evidence: Whether the writer should populate
            ``.oss-policy-kit/evidence/``.
        write_workflow: Whether the writer should drop a workflow template
            under ``.github/workflows/``.
        workflow_filename: Name of the workflow file to write (only used
            when ``write_workflow`` is ``True``).
        force: Whether existing files should be overwritten.
        dry_run: When ``True`` the writer only reports what *would* happen.
        notes: Human-facing notes propagated from the recommendation
            (e.g. "Multiple CI platforms detected").
        recommendation: The full recommendation object, kept for callers
            that want to surface alternative suggestions.
    """

    target: Path
    platform: str
    primary_stack: str | None
    signals: list[str]
    profile: str
    profile_source: str
    fail_on: str
    output_dir: str
    write_config: bool = True
    write_waivers: bool = False
    scaffold_evidence: bool = False
    write_workflow: bool = False
    workflow_filename: str = GITHUB_WORKFLOW_FILENAME
    force: bool = False
    dry_run: bool = False
    notes: list[str] = field(default_factory=list)
    recommendation: ProfileRecommendation | None = None


def _validate_fail_on(value: str) -> str:
    """Normalize and validate ``--fail-on``.

    Raises :class:`InvalidInputError` when the value is outside the supported
    set so the CLI can map it to a clean exit code 2 with a friendly message.
    """

    normalized = value.strip().lower()
    if normalized not in SUPPORTED_FAIL_ON:
        raise InvalidInputError(
            "--fail-on must be one of: none, fail, degraded.",
        )
    return normalized


def _validate_platform(value: str | None) -> str | None:
    """Normalize and validate ``--platform``; ``None`` means "auto-detect"."""

    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == "":
        return None
    if normalized not in SUPPORTED_PLATFORMS:
        raise InvalidInputError(
            "--platform must be one of: github, gitlab, azure, aws "
            "(hybrid and regulatory profiles must be selected via --profile).",
        )
    return normalized


def _pick_profile(
    *,
    forced_profile: str | None,
    forced_platform: str | None,
    recommendation: ProfileRecommendation,
) -> tuple[str, str]:
    """Return ``(profile_id, profile_source)`` based on flags + recommendation.

    Resolution order:

    1. Explicit ``--profile`` from the user wins (source: ``user``).
    2. If ``--platform`` was forced, use the platform default
       (source: ``platform_default``).
    3. Otherwise, use the top recommendation when present
       (source: ``recommended``).
    4. Final fallback: :data:`DEFAULT_FALLBACK_PROFILE`
       (source: ``fallback``).
    """

    if forced_profile is not None and forced_profile.strip():
        return forced_profile.strip(), "user"

    if forced_platform is not None:
        return DEFAULT_PROFILE_PER_PLATFORM[forced_platform], "platform_default"

    if recommendation.suggestions:
        first = recommendation.suggestions[0]
        pid = first.get("profile_id")
        if isinstance(pid, str) and pid.strip():
            return pid, "recommended"

    return DEFAULT_FALLBACK_PROFILE, "fallback"


def _validate_user_profile(profile_id: str) -> None:
    """Reject an unknown ``--profile`` before any filesystem write (incl. dry-run).

    Uses the SAME lookup ``evaluate`` relies on so the two commands agree on what
    is a valid profile:

    - An external YAML path (``.yaml`` / ``.yml`` that exists on disk) is accepted
      verbatim; ``evaluate`` loads it directly via :func:`load_profile_by_id`.
    - Otherwise the value must resolve to a bundled
      ``data/profiles/<id>/profile.yaml`` through
      :func:`resolve_profile_file` (removed ids get the loader's migration pointer
      verbatim). A miss is converted into a friendly
      :class:`InvalidInputError` (exit 2) instead of writing a poisoned
      ``oss-policy-kit.yaml`` that ``evaluate`` would later reject.
    """

    candidate = Path(profile_id)
    if candidate.suffix.lower() in {".yaml", ".yml"} and candidate.is_file():
        return
    try:
        resolve_profile_file(bundled_kit_root(), profile_id)
    except LoadError as exc:
        # Preserve the loader's removed-profile guidance verbatim (it names the
        # canonical replacement id); only genuinely-unknown ids get the generic hint.
        if "was removed" in exc.message:
            raise InvalidInputError(exc.message) from exc
        raise InvalidInputError(
            f"Unknown profile '{profile_id}'. Run 'oss-policy-kit profiles' to list available ids."
        ) from exc


def _detect_platform_from_signals(signals: list[dict[str, str]]) -> str:
    """Pick the strongest platform from the list of detected signal IDs.

    Returns ``"unknown"`` when no platform-specific signal was emitted.
    Mirrors the priority used by :func:`build_profile_recommendation` so
    the value reported to the user matches the recommendation.
    """

    sig_ids = {s.get("id", "") for s in signals}
    if any(s.startswith("github_") for s in sig_ids):
        return "github"
    if any(s.startswith("gitlab_") for s in sig_ids):
        return "gitlab"
    if any(s.startswith("azure_") for s in sig_ids):
        return "azure"
    if any(s.startswith("aws_") for s in sig_ids):
        return "aws"
    return "unknown"


def _detect_primary_stack_from_signals(signals: list[dict[str, str]]) -> str | None:
    """Map tech-stack signal IDs to a friendly stack label.

    The labels come from `profile_hints`, which is the module that emits these signals in the
    first place. This function used to keep its own copy of the dict, and the two had already
    drifted: this one knew `container_docker` while `profile_hints` knew `node_lockfile`, so the
    stack a repository was said to use depended on which module you asked.
    """

    for sig in signals:
        label = STACK_LABEL_BY_SIGNAL_ID.get(sig.get("id", ""))
        if label is not None:
            return label
    return None


def _carry_recommendation_notes(
    notes: list[str],
    *,
    profile: str,
    profile_source: str,
    platform: str,
) -> list[str]:
    """Forward the recommender's notes, minus any that `init`'s own choice made untrue.

    `build_profile_recommendation` runs for its signals even when the profile is settled by
    `--platform` or `--profile`, and it emits its fallback note whenever the clone shows no
    platform. `init` used to print that note verbatim: `init --platform gitlab` wrote
    `profile: gitlab-level-1` into the config and then told the reader, three lines below the
    correct `Profile: gitlab-level-1`, that it was "defaulting to a conservative GitHub
    baseline profile". Same for azure and aws -- three of the four supported platforms, on the
    first command a new adopter runs.

    The note stays whenever it is still true, which is exactly when the profile did come from
    the recommendation (`recommended`) or from the GitHub fallback (`fallback`). Otherwise it
    is replaced by what actually happened.
    """

    if profile_source in {"recommended", "fallback"}:
        return list(notes)

    carried = [note for note in notes if note != FEW_SIGNALS_FALLBACK_NOTE]
    if len(carried) == len(notes):
        return carried

    if profile_source == "platform_default":
        carried.append(
            f"Few strong platform signals were detected in the clone; the profile is {profile}, "
            f"the default for --platform {platform}, not a detected one.",
        )
    else:
        carried.append(
            f"Few strong platform signals were detected in the clone; the profile is {profile} "
            "because --profile named it.",
        )
    return carried


def build_init_plan(
    *,
    target: Path,
    forced_profile: str | None,
    forced_platform: str | None,
    fail_on: str,
    output_dir: str,
    with_waivers: bool,
    with_evidence: bool,
    with_workflow: bool,
    force: bool,
    dry_run: bool,
) -> InitPlan:
    """Build a complete :class:`InitPlan` from CLI flags and repo signals.

    The function expects ``target`` to be an existing, resolved directory:
    the CLI layer is responsible for that check and for translating
    filesystem errors into user-facing messages.

    Args:
        target: Resolved repository root.
        forced_profile: Value of ``--profile``, or ``None``.
        forced_platform: Value of ``--platform``, or ``None`` (case-insensitive).
        fail_on: Value of ``--fail-on``.
        output_dir: Value of ``--output-dir``; stored verbatim.
        with_waivers: Whether ``--with-waivers`` was passed.
        with_evidence: Whether ``--with-evidence`` was passed.
        with_workflow: Whether ``--with-workflow`` was passed.
        force: Whether ``--force`` was passed.
        dry_run: Whether ``--dry-run`` was passed.

    Returns:
        An :class:`InitPlan` ready for the writer (or for dry-run rendering).

    Raises:
        InvalidInputError: When ``--fail-on`` or ``--platform`` is invalid.
    """

    fail_on_normalized = _validate_fail_on(fail_on)
    platform_forced = _validate_platform(forced_platform)

    recommendation = build_profile_recommendation(target)
    detected_platform = (
        platform_forced
        if platform_forced is not None
        else _detect_platform_from_signals(recommendation.signals_detected)
    )
    primary_stack = _detect_primary_stack_from_signals(recommendation.signals_detected)

    profile, profile_source = _pick_profile(
        forced_profile=forced_profile,
        forced_platform=platform_forced,
        recommendation=recommendation,
    )

    # A user-supplied --profile must be a real bundled id (or external YAML path)
    # before we write oss-policy-kit.yaml. Validating here — using the same lookup
    # evaluate uses — keeps init from emitting a poisoned config that evaluate would
    # later reject, and runs ahead of every write path (including --dry-run).
    if profile_source == "user":
        _validate_user_profile(profile)

    # Workflow generation only makes sense for GitHub in this iteration
    # because the bundled templates live under ``.github/workflows/``. We
    # silently downgrade ``with_workflow`` for non-GitHub targets and
    # surface a note so the user understands why nothing was written.
    will_write_workflow = with_workflow and detected_platform == "github"
    extra_notes: list[str] = _carry_recommendation_notes(
        recommendation.notes,
        profile=profile,
        profile_source=profile_source,
        platform=detected_platform,
    )
    if with_workflow and detected_platform != "github":
        extra_notes.append(
            "Workflow templates are only generated for GitHub targets in this version; "
            "skipped --with-workflow because the detected platform is "
            f"{detected_platform}.",
        )

    # Evidence templates exist for github/gitlab/azure/aws. Mirror the workflow handling:
    # downgrade --with-evidence only for an unknown platform and surface a note, instead of
    # silently dropping it (which left a dangling "fill the evidence files" next-step
    # and was invisible in --format json). ADR-043/9.0.1 first-run honesty fix; gitlab
    # parity restored in v10.0.1 (templates shipped since v6.4.0).
    will_scaffold_evidence = with_evidence and detected_platform in EVIDENCE_PLATFORMS
    if with_evidence and detected_platform not in EVIDENCE_PLATFORMS:
        extra_notes.append(
            "Evidence templates are only scaffolded for github / gitlab / azure / aws targets; "
            f"skipped --with-evidence because the detected platform is {detected_platform}. "
            "Pass --platform github|gitlab|azure|aws to scaffold evidence.",
        )

    signal_ids = [s.get("id", "") for s in recommendation.signals_detected if s.get("id")]

    return InitPlan(
        target=target,
        platform=detected_platform,
        primary_stack=primary_stack,
        signals=signal_ids,
        profile=profile,
        profile_source=profile_source,
        fail_on=fail_on_normalized,
        output_dir=output_dir,
        write_config=True,
        write_waivers=with_waivers,
        scaffold_evidence=will_scaffold_evidence,
        write_workflow=will_write_workflow,
        workflow_filename=GITHUB_WORKFLOW_FILENAME,
        force=force,
        dry_run=dry_run,
        notes=extra_notes,
        recommendation=recommendation,
    )
