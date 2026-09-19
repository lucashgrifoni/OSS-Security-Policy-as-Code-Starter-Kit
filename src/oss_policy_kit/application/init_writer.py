"""File-system execution for the ``init`` CLI command.

Given an :class:`InitPlan` produced by :mod:`init_planner`, this module
writes (or refuses to overwrite) every artifact the user requested:

- ``oss-policy-kit.yaml`` — persisted project configuration.
- ``waivers.yaml`` — minimal stub aligned with the templates folder.
- ``.oss-policy-kit/evidence/`` — scaffolded via the existing
  :func:`scaffold_evidence_files`, which already handles per-platform
  template selection and ``--force`` semantics.
- ``.github/workflows/oss-policy-check.yml`` — copied from the bundled
  workflow templates.

Outcomes are reported via :class:`InitOutcome`, which mirrors the shape
already used by ``scaffold-evidence`` (``created`` / ``skipped`` /
``overwritten`` lists) so the human and JSON renderers can reuse the same
pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from oss_policy_kit.application.evidence_scaffold import (
    ScaffoldEvidenceResult,
    scaffold_evidence_files,
)
from oss_policy_kit.application.init_planner import (
    CONFIG_FILENAME,
    CONFIG_SCHEMA_VERSION,
    EVIDENCE_PLATFORMS,
    GITHUB_WORKFLOW_FILENAME,
    WAIVERS_FILENAME,
    InitPlan,
)
from oss_policy_kit.domain.errors import InvalidInputError
from oss_policy_kit.domain.models import utc_now

GENERATOR_LABEL_PREFIX = "oss-policy-kit init"

_WORKFLOW_TEMPLATE_PACKAGE = "oss_policy_kit.data.templates.workflows"
_WORKFLOW_TEMPLATE_REPO_PATH = Path("templates") / "workflows"

_WORKFLOW_SOURCE_BY_DEST: dict[str, str] = {
    "oss-policy-check.yml": "github-oss-policy-check.yml",
    "oss-policy-check-with-waivers.yml": "github-oss-policy-check-with-waivers.yml",
    "oss-policy-check-level-2.yml": "github-oss-policy-check-level-2.yml",
}

#: One argument of a template's ``evaluate`` invocation, alone on its line.
#:
#: Anchored to the start of the line after its indentation, which is what keeps the rewrite off
#: the prose. Line 3 of every template reads "Customize --profile and --fail-on to match your
#: desired strictness"; a free-floating pattern would rewrite that sentence into nonsense. The
#: trailing continuation is captured and restored so the shell block keeps working.
_WORKFLOW_ARG_RE = re.compile(
    r"^(?P<indent>[ \t]+)(?P<name>--profile|--fail-on)[ \t]+(?P<value>\S+)(?P<tail>[ \t]*\\?)$",
    re.MULTILINE,
)


@dataclass(slots=True)
class InitOutcome:
    """Summary of every filesystem action the writer took.

    Each list holds paths **relative to the init target** (M-002). They used to be
    absolute, which meant ``init --target .`` answered a relative argument with a dozen
    fully-qualified paths -- home directory, account name and all -- in ``--format
    json``, the output most likely to be pasted into a PR, a CI log, or an issue.
    ``evaluate`` already answers relative, and these paths are more useful relative
    anyway: ``.github/workflows/oss-policy-check.yml`` is what the adopter commits,
    whatever machine ran ``init``.

    The target itself is printed alongside the list by the renderer, so nothing about
    which directory was touched is lost.
    """

    created: list[Path] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)
    overwritten: list[Path] = field(default_factory=list)
    evidence_outcome: ScaffoldEvidenceResult | None = None
    next_steps: list[str] = field(default_factory=list)


def _now_iso_utc() -> str:
    """Return an ISO 8601 timestamp in UTC with a ``Z`` suffix.

    Routed through :func:`utc_now` so a reproducible build that pins
    ``SOURCE_DATE_EPOCH`` gets the same ``oss-policy-kit.yaml`` bytes on every
    run, like every other generated artifact in the kit.
    """

    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _kit_version() -> str:
    """The version stamped into the embedded ``generator`` label.

    This used to read the INSTALLED distribution's metadata, which is not necessarily the
    version of the code that ran. Measured from a source checkout with an older wheel
    installed under the same name:

        source __version__          : 10.0.17
        installed distribution meta : 10.0.4

    So ``init`` wrote ``generator: oss-policy-kit 10.0.4`` into ``oss-policy-kit.yaml``
    while the evaluation report, the batch report, the findings artifact and ``--version``
    from the same run all said 10.0.17. And when the distribution could not be found at
    all it wrote ``unknown``, which is a label nobody can trace back to anything.

    The scanners settled this first, and their reason applies here word for word: a stale
    installed distribution must never relabel an artifact it did not produce.
    """

    from oss_policy_kit import __version__ as _src_version

    return _src_version


def _render_config_yaml(plan: InitPlan) -> str:
    """Render ``oss-policy-kit.yaml`` from a plan.

    Hand-rolling the YAML keeps the diff stable and easy to read: PyYAML's
    default dumper would re-flow the file on every run.
    """

    # One clock read for the whole file: two reads can straddle a second boundary
    # and leave the header disagreeing with `generated_at` in the same document.
    generated_at = _now_iso_utc()
    lines = [
        "# oss-policy-kit configuration",
        f"# Generated by `{GENERATOR_LABEL_PREFIX}` on {generated_at}.",
        "# Edit freely; future kit versions will read this file when --profile is omitted.",
        "",
        f"schema_version: {CONFIG_SCHEMA_VERSION}",
        f"profile: {plan.profile}",
        f"profile_source: {plan.profile_source}",
        f"fail_on: {plan.fail_on}",
        f'output_dir: "{plan.output_dir}"',
        'report_json_contract: "2.0"',
        "",
        "detected:",
        f"  platform: {plan.platform}",
    ]
    if plan.primary_stack is not None:
        lines.append(f'  primary_stack: "{plan.primary_stack}"')
    else:
        lines.append("  primary_stack: null")
    if plan.signals:
        lines.append("  signals:")
        for sig in plan.signals:
            lines.append(f"    - {sig}")
    else:
        lines.append("  signals: []")
    lines.extend(
        [
            "",
            f"generated_at: {generated_at}",
            f"generator: {GENERATOR_LABEL_PREFIX} ({_kit_version()})",
            "",
        ]
    )
    return "\n".join(lines)


def _render_waivers_stub() -> str:
    """Return a minimal ``waivers.yaml`` stub compatible with the parser."""

    return (
        "# oss-policy-kit waivers\n"
        "# Each entry must have: control_id, owner, justification, expires_at (YYYY-MM-DD).\n"
        "# Waived findings remain visible in reports but stop tripping --fail-on.\n"
        "# Remove or update entries before the expires_at date.\n"
        "\n"
        "waivers: []\n"
        "\n"
        "# Example (uncomment and adjust):\n"
        "# waivers:\n"
        "#   - control_id: GH-PIN-007\n"
        "#     owner: appsec-team\n"
        "#     justification: Pinned-by-tag is acceptable for internal-only repository.\n"
        "#     expires_at: 2026-12-31\n"
    )


def _resolve_workflow_template(dest_filename: str) -> tuple[str, str]:
    """Map a destination filename to its source template name and body."""

    source = _WORKFLOW_SOURCE_BY_DEST.get(dest_filename)
    if source is None:
        raise InvalidInputError(
            f"Unknown workflow template: {dest_filename}. Supported: {', '.join(sorted(_WORKFLOW_SOURCE_BY_DEST))}.",
        )

    try:
        ref = resources.files(_WORKFLOW_TEMPLATE_PACKAGE).joinpath(source)
        if ref.is_file():
            return source, ref.read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError):
        pass

    repo_local = _WORKFLOW_TEMPLATE_REPO_PATH / source
    if repo_local.is_file():
        return source, repo_local.read_text(encoding="utf-8")

    raise InvalidInputError(
        f"Workflow template not found: {source}. Expected under packaged data or {_WORKFLOW_TEMPLATE_REPO_PATH}/.",
    )


def _apply_workflow_settings(body: str, *, profile: str | None, fail_on: str) -> str:
    """Put the plan's gate settings into the template's ``evaluate`` invocation.

    The templates ship with working defaults because ``docs/adoption-guide.md`` tells adopters
    to copy one by hand, so each has to run exactly as it sits on disk. That is why this
    rewrites the body on the way out rather than turning the files into placeholders.

    ``profile`` is ``None`` when the selected profile is an external path, which would not
    resolve on a runner; the template keeps its own and the planner has already recorded a note.

    A template that exposes neither argument on its own line is a packaging fault rather than
    bad input, and it fails here rather than silently writing an un-substituted gate.
    """

    replacements = {"--fail-on": fail_on}
    if profile is not None:
        replacements["--profile"] = profile

    seen: set[str] = set()

    def _swap(match: re.Match[str]) -> str:
        name = match.group("name")
        seen.add(name)
        value = replacements.get(name, match.group("value"))
        return f"{match.group('indent')}{name} {value}{match.group('tail')}"

    rewritten = _WORKFLOW_ARG_RE.sub(_swap, body)

    missing = sorted({"--profile", "--fail-on"} - seen)
    if missing:
        raise InvalidInputError(
            f"Workflow template does not expose {' and '.join(missing)} on its own line, "
            "so init cannot make it enforce the configured gate.",
        )
    return rewritten


def _reported_path(path: Path, root: Path) -> Path:
    """Render an artifact path the way the outcome reports it: relative to *root* (M-002).

    A path that somehow lands outside the target degrades to its bare name rather than
    to the absolute path: the point of the relativization is that no host directory or
    OS account name reaches stdout, and the fallback has to hold that line too.
    """

    try:
        return path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return Path(path.name)


def _record_dry_run_action(path: Path, root: Path, force: bool, outcome: InitOutcome) -> None:
    """Append ``path`` to the matching outcome bucket for a dry-run."""

    reported = _reported_path(path, root)
    if not path.exists():
        outcome.created.append(reported)
    elif force:
        outcome.overwritten.append(reported)
    else:
        outcome.skipped.append(reported)


def _write_text_idempotent(
    *,
    path: Path,
    root: Path,
    body: str,
    force: bool,
    outcome: InitOutcome,
) -> None:
    """Write ``body`` to ``path`` honoring ``force``; updates ``outcome``."""

    path.parent.mkdir(parents=True, exist_ok=True)
    reported = _reported_path(path, root)
    if path.exists() and not force:
        outcome.skipped.append(reported)
        return
    existed = path.exists()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)
    if existed:
        outcome.overwritten.append(reported)
    else:
        outcome.created.append(reported)


def execute_init_plan(plan: InitPlan) -> InitOutcome:
    """Execute (or dry-run) an :class:`InitPlan`."""

    outcome = InitOutcome()

    config_path = plan.target / CONFIG_FILENAME
    waivers_path = plan.target / WAIVERS_FILENAME
    evidence_dir = plan.target / ".oss-policy-kit" / "evidence"
    workflow_path = plan.target / ".github" / "workflows" / plan.workflow_filename

    if plan.dry_run:
        if plan.write_config:
            _record_dry_run_action(config_path, plan.target, plan.force, outcome)
        if plan.write_waivers:
            _record_dry_run_action(waivers_path, plan.target, plan.force, outcome)
        if plan.scaffold_evidence:
            outcome.created.append(_reported_path(evidence_dir, plan.target))
        if plan.write_workflow:
            _record_dry_run_action(workflow_path, plan.target, plan.force, outcome)
        outcome.next_steps = _build_next_steps(plan)
        return outcome

    # Resolve the workflow template BEFORE writing anything. It is the only step that can
    # fail on something the caller cannot see coming -- the template ships with the
    # package, so its absence is a packaging fault, not bad input -- and it used to fail
    # last, after the config and seven evidence files were already on disk. The adopter
    # was left with a half-initialised repository and an error about a file they never
    # named. Resolving first makes `init` all-or-nothing for that failure.
    workflow_body: str | None = None
    if plan.write_workflow:
        _, template_body = _resolve_workflow_template(plan.workflow_filename)
        workflow_body = _apply_workflow_settings(
            template_body,
            profile=plan.workflow_profile,
            fail_on=plan.fail_on,
        )

    if plan.write_config:
        _write_text_idempotent(
            path=config_path,
            root=plan.target,
            body=_render_config_yaml(plan),
            force=plan.force,
            outcome=outcome,
        )

    if plan.write_waivers:
        _write_text_idempotent(
            path=waivers_path,
            root=plan.target,
            body=_render_waivers_stub(),
            force=plan.force,
            outcome=outcome,
        )

    if plan.scaffold_evidence and plan.platform in EVIDENCE_PLATFORMS:
        scaffold = scaffold_evidence_files(plan.target, plan.platform, force=plan.force)
        # ``scaffold_evidence_files`` reports absolute paths to its own CLI command; they
        # are relativized here rather than there so ``scaffold-evidence``'s own output
        # contract is untouched by this change.
        outcome.evidence_outcome = scaffold
        outcome.created.extend(_reported_path(p, plan.target) for p in scaffold.created)
        outcome.skipped.extend(_reported_path(p, plan.target) for p in scaffold.skipped)
        outcome.overwritten.extend(_reported_path(p, plan.target) for p in scaffold.overwritten)

    if plan.write_workflow:
        assert workflow_body is not None  # resolved above, before any write
        _write_text_idempotent(
            path=workflow_path,
            root=plan.target,
            body=workflow_body,
            force=plan.force,
            outcome=outcome,
        )

    outcome.next_steps = _build_next_steps(plan)
    return outcome


def _build_next_steps(plan: InitPlan) -> list[str]:
    """Generate user-facing next steps tailored to the resulting plan."""

    steps: list[str] = []
    steps.append(
        f"Review {CONFIG_FILENAME} and adjust profile, fail_on, or output_dir as needed.",
    )
    steps.append(
        f"Run: oss-policy-kit evaluate --target . --profile {plan.profile} --fail-on {plan.fail_on}",
    )
    if plan.scaffold_evidence:
        steps.append(
            "Fill the scaffolded evidence files under .oss-policy-kit/evidence/ before relying on results.",
        )
    if plan.write_workflow and plan.platform == "github":
        steps.append(
            f"Commit .github/workflows/{GITHUB_WORKFLOW_FILENAME} to enable continuous "
            f"baseline checks on pull requests; it runs "
            f"{plan.workflow_profile or "the template's own profile"} with --fail-on {plan.fail_on}.",
        )
    if plan.write_waivers:
        steps.append(
            "Add real entries to waivers.yaml (owner, justification, expires_at) only when remediation is deferred.",
        )
    if plan.platform == "unknown":
        steps.append(
            "No CI platform was detected; pass --platform or add CI workflows before running evaluate.",
        )
    return steps
