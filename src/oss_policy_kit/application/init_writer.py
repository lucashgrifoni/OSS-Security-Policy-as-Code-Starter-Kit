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
from oss_policy_kit.application.input_limits import MAX_CONFIG_BYTES, oversize_reason
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
    r"^(?P<indent>[ \t]+)(?P<name>--profile|--fail-on|--output-dir)[ \t]+(?P<value>\S+)(?P<tail>[ \t]*\\?)$",
    re.MULTILINE,
)


#: The `path:` of the artifact-upload step, anchored on the value the template's own
#: `--output-dir` already carries. Both are rewritten from that one source, so they cannot
#: drift: a job that writes one directory and uploads another fails silently, with exit 0
#: and an empty artifact. Built per call rather than fixed, because the anchor is the old
#: value and a bare `path:` pattern would match unrelated steps.
def _artifact_path_re(current: str) -> re.Pattern[str]:
    stem = re.escape(current.rstrip("/").removeprefix("./"))
    return re.compile(rf"^(?P<indent>[ \t]+)path:[ \t]+\.?/?{stem}/?[ \t]*$", re.MULTILINE)


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

    # The stub used to say that waived findings "stop tripping --fail-on", with no word about
    # how. They do only in a run handed this file with --waivers, and the workflow `init`
    # writes next to it does not pass one, so an adopter who filled this in saw CI fail on
    # the very control they had waived. The example named GH-PIN-007, which is not in the
    # catalog; uncommented, it waived nothing and produced a warning instead.
    return (
        "# oss-policy-kit waivers\n"
        "# Each entry must have: control_id, owner, justification, expires_at (YYYY-MM-DD).\n"
        "# An entry applies only to a run given this file: evaluate --waivers waivers.yaml.\n"
        "# The workflow `init --with-workflow` writes does not pass that flag; add it to the\n"
        "# evaluate step for these waivers to apply in CI.\n"
        "# A waived finding stays visible in the report but stops tripping --fail-on.\n"
        "# Remove or update entries before the expires_at date.\n"
        "\n"
        "waivers: []\n"
        "\n"
        "# Example (uncomment and adjust):\n"
        "# waivers:\n"
        "#   - control_id: CI-PIN-008\n"
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

    # This fallback resolves against the working directory, so when the packaged
    # templates are missing it reads `templates/workflows/` out of whatever repository
    # `init` was run in. That file is not ours, so it gets the same bound as any other
    # document this package did not write.
    repo_local = _WORKFLOW_TEMPLATE_REPO_PATH / source
    if repo_local.is_file():
        too_big = oversize_reason(repo_local, MAX_CONFIG_BYTES, label="Workflow template")
        if too_big is not None:
            raise InvalidInputError(too_big)
        return source, repo_local.read_text(encoding="utf-8")

    raise InvalidInputError(
        f"Workflow template not found: {source}. Expected under packaged data or {_WORKFLOW_TEMPLATE_REPO_PATH}/.",
    )


#: The header line that tells a reader to copy the template somewhere. Two of the three
#: bundled templates carry one, and the waivers template folds a second instruction into the
#: same sentence, so the remainder is captured rather than discarded with it.
_WORKFLOW_COPY_INSTRUCTION_RE = re.compile(r"^# Copy (?:this file )?to \S+(?P<tail>.*)$")

#: What follows the destination path differs per template: " in your repository." on one,
#: " and ensure waivers/waivers.yaml is committed." on the other. Only the second half of an
#: `and` clause survives `init`, so it is matched separately rather than folded into the line
#: pattern above. A single combined regex matched the waivers template and silently left the
#: main one untouched, which is the defect this whole change is about.
_WORKFLOW_COPY_REMAINDER_RE = re.compile(r"\band\s+(?P<rest>.+?)\.?\s*$")


def _drop_copy_instruction(body: str) -> str:
    """Remove the "copy this somewhere" header from a workflow ``init`` is about to write.

    The instruction is correct for someone reading the template in `templates/workflows/` on
    GitHub, which `docs/adoption-guide.md` tells adopters to do. It is wrong in the file
    `init --with-workflow` just created, because that file is already at the destination the
    sentence names: the adopter is told to copy it to where it is.

    The templates on disk keep the line. Only the generated copy loses it, which is the same
    split the profile and fail-on substitution already uses.

    The waivers template writes "Copy to <path> and ensure waivers/waivers.yaml is committed",
    where the second half still applies after `init` has run. That remainder is kept as its
    own line instead of being dropped with the clause around it.
    """

    kept: list[str] = []
    for line in body.splitlines(keepends=True):
        match = _WORKFLOW_COPY_INSTRUCTION_RE.match(line)
        if match is None:
            kept.append(line)
            continue
        remainder = _WORKFLOW_COPY_REMAINDER_RE.search(match.group("tail"))
        if remainder is not None:
            # Keep the half that still applies, as its own comment line.
            rest = remainder.group("rest")
            ending = line[len(line.rstrip("\r\n")) :]
            kept.append(f"# {rest[0].upper()}{rest[1:]}.{ending}")
        # Otherwise the whole line goes, newline included, so no blank gap is left behind.
    return "".join(kept)


def _apply_workflow_settings(body: str, *, profile: str | None, fail_on: str, output_dir: str) -> str:
    """Put the plan's gate settings into the template's ``evaluate`` invocation.

    The templates ship with working defaults because ``docs/adoption-guide.md`` tells adopters
    to copy one by hand, so each has to run exactly as it sits on disk. That is why this
    rewrites the body on the way out rather than turning the files into placeholders.

    ``profile`` is ``None`` when the selected profile is an external path, which would not
    resolve on a runner; the template keeps its own and the planner has already recorded a note.

    A template that exposes none of these arguments on its own line is a packaging fault
    rather than bad input, and it fails here rather than silently writing an un-substituted
    gate.

    ``output_dir`` reaches two places, and they have to move together. The `--output-dir`
    argument decides where the run writes; the `path:` of the upload step decides what gets
    published. Rewriting only the first leaves a job that writes one directory and uploads
    another, which fails as an empty artifact and an exit code of 0. The upload `name:` is
    deliberately left alone: it is a label rather than a path, and a nested value such as
    `out/reports` would make it invalid, because an artifact name cannot contain a slash.
    """

    replacements = {"--fail-on": fail_on, "--output-dir": output_dir}
    if profile is not None:
        replacements["--profile"] = profile

    seen: set[str] = set()
    previous_output_dir: str | None = None

    def _swap(match: re.Match[str]) -> str:
        nonlocal previous_output_dir
        name = match.group("name")
        seen.add(name)
        if name == "--output-dir":
            previous_output_dir = match.group("value")
        value = replacements.get(name, match.group("value"))
        return f"{match.group('indent')}{name} {value}{match.group('tail')}"

    rewritten = _WORKFLOW_ARG_RE.sub(_swap, body)

    missing = sorted({"--profile", "--fail-on", "--output-dir"} - seen)
    if missing:
        raise InvalidInputError(
            f"Workflow template does not expose {' and '.join(missing)} on its own line, "
            "so init cannot make it enforce the configured gate.",
        )

    assert previous_output_dir is not None  # guaranteed by the `missing` check above
    published = 0

    def _swap_path(match: re.Match[str]) -> str:
        nonlocal published
        published += 1
        return f"{match.group('indent')}path: {output_dir.rstrip('/')}/"

    rewritten = _artifact_path_re(previous_output_dir).sub(_swap_path, rewritten)
    if published != 1:
        raise InvalidInputError(
            f"Workflow template publishes {published} paths matching its own --output-dir "
            f"({previous_output_dir}); init cannot keep the run and the upload in step.",
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


def _record_scaffold(scaffold: ScaffoldEvidenceResult, root: Path, outcome: InitOutcome) -> None:
    """Sort the evidence files into the outcome, relative to *root*, for a run or a preview."""

    outcome.created.extend(_reported_path(p, root) for p in scaffold.created)
    outcome.skipped.extend(_reported_path(p, root) for p in scaffold.skipped)
    outcome.overwritten.extend(_reported_path(p, root) for p in scaffold.overwritten)


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
    workflow_path = plan.target / ".github" / "workflows" / plan.workflow_filename

    if plan.dry_run:
        if plan.write_config:
            _record_dry_run_action(config_path, plan.target, plan.force, outcome)
        if plan.write_waivers:
            _record_dry_run_action(waivers_path, plan.target, plan.force, outcome)
        if plan.scaffold_evidence and plan.platform in EVIDENCE_PLATFORMS:
            _record_scaffold(
                scaffold_evidence_files(plan.target, plan.platform, force=plan.force, dry_run=True),
                plan.target,
                outcome,
            )
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
            _drop_copy_instruction(template_body),
            profile=plan.workflow_profile,
            output_dir=str(plan.output_dir),
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
        _record_scaffold(scaffold, plan.target, outcome)

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
        applies = "They apply only to a run given --waivers waivers.yaml"
        if plan.write_workflow and plan.platform == "github":
            applies += f"; add that flag to the evaluate step in .github/workflows/{GITHUB_WORKFLOW_FILENAME}"
        steps.append(
            "Add real entries to waivers.yaml (owner, justification, expires_at) only when remediation is deferred. "
            f"{applies}.",
        )
    if plan.platform == "unknown":
        steps.append(
            "No CI platform was detected; pass --platform or add CI workflows before running evaluate.",
        )
    return steps
