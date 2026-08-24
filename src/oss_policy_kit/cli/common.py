"""Shared Typer app, console plumbing, and `evaluate` shared implementation."""

from __future__ import annotations

import json
import logging
import sys
import textwrap
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, NoReturn, cast

import typer
from rich.console import Console
from rich.markup import escape as _rich_markup_escape
from typer.core import HAS_RICH, TyperGroup

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.adapters.scorecard_json import load_scorecard_auto
from oss_policy_kit.application.cli_output import FailOnPolicy, fail_on_violated, print_stdout_summary
from oss_policy_kit.application.config_loader import load_project_config_for_target
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.input_limits import (
    MAX_EVIDENCE_BYTES,
    bad_input_detail,
    is_bad_input,
    oversize_reason,
)
from oss_policy_kit.application.insights_evidence import load_insights_evidence
from oss_policy_kit.application.loader import (
    PROFILE_DIRECTORY_ALIASES,
    load_catalog,
    load_profile_by_id,
    merge_kit_root,
)
from oss_policy_kit.application.reporting import _sanitize_target_path_for_payload, write_reports
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.help_text import ROOT_CLI_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


class OssPolicyKitTyperGroup(TyperGroup):
    """Root Click group: prepend the ASCII banner before Typer plain or Rich help."""

    # ``ctx``/``formatter`` are typed ``Any``: Typer vendored Click into ``typer._click``
    # (0.26+), so the base ``format_help`` signature uses private, version-dependent types.
    # This override only forwards them unchanged to ``super()``/``rich_format_help``.
    def format_help(self, ctx: Any, formatter: Any) -> None:
        use_rich = bool(HAS_RICH and self.rich_markup_mode is not None)
        if not use_rich:
            terminal_ui.write_cli_banner_to_formatter(formatter)
            return super().format_help(ctx, formatter)

        terminal_ui.print_cli_banner_before_typer_rich_help()
        from typer import rich_utils as typer_rich_utils

        rich_mode = self.rich_markup_mode
        # Unreachable at runtime -- `use_rich` above is exactly `rich_markup_mode is not None`
        # and the plain path already returned -- but it is what narrows `MarkupMode` to
        # `MarkupModeStrict` for `rich_format_help` below. Deleting it trades a dead branch for
        # a type error, so it stays.
        if rich_mode is None:  # pragma: no cover
            return super().format_help(ctx, formatter)
        # Suppress Typer's flat plain-text epilog on the Rich path; we render it as
        # soft-bordered panels below so the whole screen shares one visual language.
        # The non-Rich path above still uses the plain ``epilog`` string.
        saved_epilog = self.epilog
        self.epilog = None
        try:
            typer_rich_utils.rich_format_help(obj=self, ctx=ctx, markup_mode=rich_mode)
        finally:
            self.epilog = saved_epilog
        terminal_ui.print_root_help_epilog_panels()
        return None


app = typer.Typer(
    name="oss-policy-kit",
    cls=OssPolicyKitTyperGroup,
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["--help", "-h"]},
    help=(
        "Evaluate a local repository clone against bundled OSS security profiles.\n\n"
        "Preferred usage:\n"
        "  python -m oss_policy_kit evaluate --target <repo> --profile <profile>\n\n"
        "Compatibility usage:\n"
        "  python -m oss_policy_kit --target <repo> --profile <profile>"
    ),
    epilog=ROOT_CLI_EPILOG,
)


def enable_debug_logging() -> None:
    """Raise the ``oss_policy_kit`` logger to DEBUG with a stderr handler (CLI ``--debug``).

    Scoped to this package's logger so third-party libraries stay quiet, and writes to
    stderr so stdout report output is unchanged. Idempotent across repeated calls.
    """

    pkg_logger = logging.getLogger("oss_policy_kit")
    if not any(getattr(h, "_oss_policy_kit_debug", False) for h in pkg_logger.handlers):
        handler = logging.StreamHandler()  # defaults to sys.stderr
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        handler._oss_policy_kit_debug = True  # type: ignore[attr-defined]
        pkg_logger.addHandler(handler)
    pkg_logger.setLevel(logging.DEBUG)


def stderr_console() -> Console:
    """Rich console for stderr human messages (rebuilt so width tracks current ``sys.stderr``)."""

    return terminal_ui.build_stderr_console()


def markup_safe(value: object) -> str:
    """Render *value* as text Rich will print literally, tags and all.

    Rich reads ``[word]`` as a style tag and drops it from the rendered line. Exception
    text and filesystem paths routinely contain one, and the loss is silent: the
    missing-extra hint ``pip install 'oss-policy-kit[github]'`` reached users as
    ``pip install 'oss-policy-kit'`` — a command that installs nothing they are missing.
    Every non-literal interpolated into a markup string goes through here, so the one
    string the user has to copy survives rendering.
    """

    return _rich_markup_escape(str(value))


def display_path(value: str | Path, *, root: str | Path | None = None) -> str:
    """Render *value* for a user-facing message without leaking the host layout (M-002).

    Three rules, applied in order:

    - A **relative** value is returned exactly as it was given. The adopter typed
      ``--target .``; answering with the fully-qualified home-directory path hands their
      OS account name to whoever reads the terminal, the CI log, or the pasted issue --
      and tells them nothing they did not already type.
    - An **absolute** value that sits under the current directory is shown relative to it.
      Where an artifact landed is genuinely useful, and cwd-relative is the form that is
      both useful and free of everything above the working directory.
    - Anything else falls back to *root* -- the directory the command was pointed at --
      and finally to the bare name. Losing the parent directories is the point: the
      fallback has to hold the same line the first two rules do.

    ``root`` is the artifact's own root (an output directory, a repository target), not a
    second chance to print the host layout: it is only ever used as the base to subtract.
    """

    raw = str(value)
    if not raw:
        return raw
    path = Path(raw)
    if not path.is_absolute():
        return raw
    try:
        resolved = path.resolve()
    except OSError:
        return path.name or raw
    bases: list[Path] = []
    # A deleted working directory makes ``Path.cwd()`` raise; the fallbacks below still apply.
    with suppress(OSError):
        bases.append(Path.cwd())
    if root is not None:
        bases.append(Path(root))
    for base in bases:
        try:
            return str(resolved.relative_to(base.resolve()))
        except (OSError, ValueError):
            continue
    return path.name or raw


def exit_for_unexpected(exc: BaseException) -> NoReturn:
    """The one last-resort handler: exit 2 for unreadable input, exit 3 for our defect.

    Every command ended with the same two lines -- print "Unexpected error", exit 3 --
    which made exit 3 the outcome for anything that escaped, including an evidence file
    the adopter's own repository happened to contain. Exit 3 is documented as "always a
    bug in the kit", so that told adopters the tool was broken when their input was.

    Routing all 23 handlers through here means the classification is stated once and
    cannot drift between commands. ``is_bad_input`` deliberately keeps a bare
    ``ValueError`` on the exit-3 side: the point is to stop misreporting input problems,
    not to stop reporting defects.

    The message carries no path. ``str(OSError)`` embeds the absolute filename, which is
    how these handlers leaked the home directory and OS account name (M-002).
    """

    if is_bad_input(exc):
        stderr_console().print(f"[red]Error:[/red] input could not be read: {markup_safe(bad_input_detail(exc))}")
        raise typer.Exit(code=2) from exc
    stderr_console().print(f"[red]Unexpected error:[/red] {markup_safe(exc)}")
    raise typer.Exit(code=3) from exc


def write_stdout_text(text: str) -> None:
    """Write *text* to stdout; fall back to UTF-8 bytes when the console codepage cannot encode symbols.

    Goes through ``redact_home`` for the same reason the Rich console does: this is the
    other way text reaches the operator, and it is the one the ``scan-*`` commands use --
    the exact commands a validation sweep caught printing the account name on a
    successful run. A boundary that covers one of two exits is not a boundary.
    """

    text = terminal_ui.redact_home(text)
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        buf = getattr(sys.stdout, "buffer", None)
        if buf is None:
            raise
        buf.write(text.encode("utf-8", errors="replace"))
        buf.flush()


def write_stderr_text(text: str) -> None:
    """Write *text* to stderr; fall back to UTF-8 bytes when the console codepage cannot encode symbols."""

    try:
        sys.stderr.write(text)
    except UnicodeEncodeError:
        buf = getattr(sys.stderr, "buffer", None)
        if buf is None:
            raise
        buf.write(text.encode("utf-8", errors="replace"))
        buf.flush()


def write_wrapped_stdout_block(prefix: str, body: str, continuation: str) -> None:
    """Write ``body`` to stdout wrapped to ``terminal_width``, preserving ``prefix`` on first line."""

    tw = max(20, terminal_ui.terminal_width(sys.stdout))
    chunk = max(12, tw - len(prefix))
    parts = textwrap.wrap(body, width=chunk, break_long_words=True, break_on_hyphens=False)
    if not parts:
        return
    sys.stdout.write(f"{prefix}{parts[0]}\n")
    for ln in parts[1:]:
        sys.stdout.write(f"{continuation}{ln}\n")


def normalize_evaluate_format(raw: str) -> str:
    """Map evaluate ``--format`` aliases to ``human`` or ``json``."""

    f = raw.lower().strip()
    if f == "json":
        return "json"
    if f in {"human", "table", "compact", "detailed"}:
        return "human"
    raise InvalidInputError(
        "--format must be human or json (aliases: table, compact, detailed all map to human stdout layout)."
    )


def normalize_profiles_format(raw: str) -> str:
    """Map profiles ``--format`` aliases to table/compact/detailed/json."""

    f = raw.lower().strip()
    if f == "human":
        return "compact"
    if f == "verbose":
        return "detailed"
    if f in {"detailed", "compact", "table", "json"}:
        return f
    raise InvalidInputError(
        "profiles --format must be one of: detailed, compact, table, json "
        "(aliases: human -> compact, verbose -> detailed)."
    )


def normalize_recommend_format(raw: str) -> str:
    """Map recommend-profile ``--format`` aliases."""

    f = raw.lower().strip()
    if f in {"human", "table", "compact"}:
        return "human"
    if f == "json":
        return "json"
    raise InvalidInputError("recommend-profile --format must be human or json (aliases: table, compact map to human).")


def warn_if_batch_skipped_directories(batch_json_path: Path) -> None:
    """Print a short stderr summary when the consolidated batch skipped one or more directories.

    Reads the batch JSON that `evaluate-many` just wrote and, if `skipped_directories` is non-empty,
    emits a single yellow line pointing operators at `evaluation-batch.json.skipped_directories`.
    Does not alter the batch JSON, the exit code, or the batch contract; fails silently if the file
    cannot be read for any reason (the main flow is the source of truth).
    """

    try:
        with batch_json_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    skipped = payload.get("skipped_directories")
    if not isinstance(skipped, list) or not skipped:
        return
    count = len(skipped)
    suffix = "y" if count == 1 else "ies"
    stderr_console().print(
        f"[yellow]Skipped {count} director{suffix}[/yellow] under --skip-non-repos "
        f"(see {markup_safe(batch_json_path.name)}.skipped_directories for details)."
    )


def print_operational_warning_summary(warnings: list[str]) -> None:
    """Surface a short warning summary on stderr without changing exit semantics."""

    if not warnings:
        return
    count = len(warnings)
    c = stderr_console()
    c.print(f"[dim]Operational warnings ({count})[/dim] [dim]-- see Markdown/JSON reports[/dim]")
    for msg in warnings[:3]:
        wrapped = terminal_ui.human_wrap_lines(msg, stream=sys.stderr, subtract=4)
        # `str.split` always yields at least one element -- `"".split("\n")` is `[""]` -- so
        # `lines[0]` is safe without an emptiness check, which could never have been taken.
        lines = wrapped.split("\n")
        c.print(f"[dim]-[/dim] [dim]{markup_safe(lines[0])}[/dim]")
        for cont in lines[1:]:
            c.print(f"[dim]  {markup_safe(cont)}[/dim]")


def _looks_like_path(token: str) -> bool:
    """Heuristic: does *token* look like a filesystem path (vs a mistyped subcommand)?

    Used by :func:`prepare_cli_args` to decide whether a bare leading argument should be
    routed to ``evaluate`` as a target. A real target path contains a separator / home /
    drive prefix, or already exists on disk; a mistyped command name (e.g. ``recommend``
    for ``recommend-profile``) does none of these and is better surfaced as
    ``No such command`` than as a confusing "Not a directory" path error.
    """

    if any(sep in token for sep in ("/", "\\")):
        return True
    if token in {".", ".."} or token.startswith(("~", ".")):
        return True
    if len(token) >= 2 and token[1] == ":":  # Windows drive prefix, e.g. C:\repo
        return True
    return Path(token).exists()


#: Every registered subcommand name. Used both to recognize an explicit subcommand as
#: ``args[0]`` and to locate the subcommand boundary when re-placing a misplaced flag.
SUBCOMMAND_NAMES: frozenset[str] = frozenset(
    {
        "evaluate",
        "profiles",
        "evaluate-many",
        "scaffold-evidence",
        "collect-evidence",
        "diff-reports",
        "recommend-profile",
        "init",
        "osps-coverage",
        "diff-catalogs",
        "scan-sast",
        "scan-iac",
        "scan-k8s",
        "scan-cfn",
        "scan-pulumi",
        "scan-bicep",
        "emit-vex",
        "emit-insights",
        "ingest-insights",
        "ingest-scorecard",
        "correlate-findings",
        "export-evidence",
        "export-policy",
    }
)

#: The root compatibility callback declares this flag so ``oss-policy-kit
#: --with-findings-summary --target ... --profile ...`` works without typing ``evaluate``.
#: It is the only root option that a user plausibly types before a subcommand and expects
#: to change the artifact, so it is the only one :func:`_relocate_misplaced_root_flag`
#: moves. Every other root option that lands there is already loud (``--target`` before a
#: subcommand leaves ``evaluate`` with no target, and it exits 2).
_MISPLACED_ROOT_FLAG = "--with-findings-summary"

#: Root-callback options that consume the following token as their value. A
#: ``--with-findings-summary`` sitting in one of those slots is that option's value, not a
#: misplaced flag, so it is left exactly where the user put it.
_ROOT_VALUE_OPTIONS: frozenset[str] = frozenset(
    {
        "--profile",
        "-p",
        "--output-dir",
        "-o",
        "--waivers",
        "-w",
        "--scorecard-json",
        "-sj",
        "--kit-root",
        "-k",
        "--target",
        "-t",
        "--format",
        "-f",
        "--fail-on",
        "-fo",
        "--report-json-contract",
        "--sarif-output",
    }
)


def _relocate_misplaced_root_flag(args: list[str]) -> list[str]:
    """Move a pre-subcommand ``--with-findings-summary`` to just after the subcommand.

    The root callback declares the flag for compatibility usage, so Click parses it there
    happily — and then the callback returns early because a subcommand was named, dropping
    every root parameter on the floor. ``oss-policy-kit --with-findings-summary evaluate
    ...`` therefore exited 0 having written a report with an empty ``extensions`` object:
    the user asked for a block, got a green run, and got no block and no warning.

    Moving the token behind the subcommand delivers the request to the command that can
    honour it. A subcommand that does not accept the flag (``profiles``, ``init``, ...)
    now gets Click's "No such option" and exit 2 instead of ignoring it silently — the
    same fail-closed behaviour a misplaced ``--debug`` already gets.
    """

    try:
        flag_idx = args.index(_MISPLACED_ROOT_FLAG)
    except ValueError:
        return args
    cmd_idx = next((i for i, token in enumerate(args) if token in SUBCOMMAND_NAMES), None)
    if cmd_idx is None or flag_idx > cmd_idx:
        return args  # compatibility usage, or already correctly placed
    if flag_idx > 0 and args[flag_idx - 1] in _ROOT_VALUE_OPTIONS:
        return args  # the token is the preceding option's value
    without_flag = [*args[:flag_idx], *args[flag_idx + 1 :]]
    new_cmd_idx = cmd_idx - 1  # the removed token sat before the subcommand
    return [*without_flag[: new_cmd_idx + 1], _MISPLACED_ROOT_FLAG, *without_flag[new_cmd_idx + 1 :]]


def prepare_cli_args(args: list[str]) -> list[str]:
    """Normalize argv so a leading repository path dispatches to the `evaluate` subcommand.

    Click/Typer parses optional group-level positionals before subcommand names. A bare
    ``python -m oss_policy_kit ./repo --profile ...`` would otherwise steal ``evaluate`` as a
    positional. Inserting ``evaluate`` keeps shell, subprocess, and CliRunner behavior aligned
    when the first token is a path-like argument (not an option and not already ``evaluate``).

    It also re-places a ``--with-findings-summary`` typed before the subcommand, which the
    root callback would otherwise parse and silently discard
    (see :func:`_relocate_misplaced_root_flag`).
    """

    if not args:
        return args
    args = _relocate_misplaced_root_flag(args)
    first = args[0]
    if first in SUBCOMMAND_NAMES:
        return args
    if first in ("--help", "-h", "--version", "-V"):
        return args
    if first.startswith("-"):
        return args
    if not _looks_like_path(first):
        # A bare token that is neither a known subcommand nor a path-like value: treat it
        # as a mistyped command and let Click raise a clear "No such command" instead of
        # routing it to `evaluate` as a target (which yielded a confusing
        # "Not a directory or does not exist" path error). 9.0.1 UX fix.
        return args
    return ["evaluate", *args]


_SCAN_EVIDENCE_MAP: tuple[tuple[str, str, str], ...] = (
    ("K8S-", "k8s-baseline.json", "scan-k8s"),
    ("IAC-TF-", "iac-terraform.json", "scan-iac"),
    ("IAC-CFN-", "iac-cfn.json", "scan-cfn"),
    ("IAC-PUL-", "iac-pulumi.json", "scan-pulumi"),
    ("IAC-BICEP-", "iac-bicep.json", "scan-bicep"),
    ("SAST-SEMGREP-", "sast-semgrep.json", "scan-sast"),
)


def _warn_deprecated_profile_alias(profile_id: str) -> None:
    """Emit a stderr deprecation notice when the requested profile is a deprecated alias (ADR-029).

    The alias still resolves to the canonical profile (existing CI keeps working); the notice goes to
    stderr so it never corrupts JSON stdout. Aliases are removed in the next major (v10.0.0).
    """
    canonical = PROFILE_DIRECTORY_ALIASES.get(profile_id)
    if canonical is None:
        return
    stderr_console().print(
        f"[yellow]warning:[/yellow] profile '{markup_safe(profile_id)}' is deprecated and was renamed to "
        f"'{markup_safe(canonical)}'. The alias still resolves but is removed in v10.0.0 — update your config/CI."
    )


def _warn_missing_scan_evidence(
    repo_root: Path,
    control_ids: set[str],
    machine_stdout: bool,
    *,
    target_display: str | None = None,
) -> None:
    """Print a prominent banner when the profile bundles scan-* controls but the
    corresponding evidence file is missing. Prevents the UX gap where evaluate
    against k8s/iac/sast profiles returns opaque manual-review-required for every
    control because the user did not know to run the scan-* command first.

    The command the banner tells the operator to run quotes the target as they typed it
    (``target_display``), not the resolved path: this is a line meant to be copied, and a
    resolved path both leaks the account name (M-002) and is not what they asked for.
    """
    if machine_stdout:
        return  # JSON-mode stdout must stay pure; banner would corrupt parsing.
    shown_target = display_path(target_display if target_display is not None else repo_root)
    evidence_dir = repo_root / ".oss-policy-kit" / "evidence"
    missing: list[tuple[str, str]] = []
    for prefix, filename, scan_cmd in _SCAN_EVIDENCE_MAP:
        if not any(cid.startswith(prefix) for cid in control_ids):
            continue
        if not (evidence_dir / filename).is_file():
            missing.append((scan_cmd, shown_target))
    if not missing:
        return
    out = stderr_console()
    for scan_cmd, target in missing:
        out.print(
            f"[yellow bold]NOTE:[/yellow bold] profile uses controls that depend on "
            f"[bold]oss-policy-kit {markup_safe(scan_cmd)}[/bold] evidence; none was found in "
            f".oss-policy-kit/evidence/. Those controls will return manual-review-required. "
            f"To enable detection, run first: "
            f'[bold]oss-policy-kit {markup_safe(scan_cmd)} --target "{markup_safe(target)}"[/bold]',
        )


@dataclass(frozen=True, slots=True)
class EvaluateRequest:
    """Bundled inputs for :func:`execute_evaluate` (root callback + `evaluate`)."""

    target_pos: str | None
    target_opt: str | None
    profile: str | None
    output_dir: Path
    waivers: Path | None
    scorecard_json: Path | None
    kit_root: Path | None
    output_format: str
    summary_only: bool
    fail_on: str
    verbose: bool = False
    quiet: bool = False
    report_json_contract: str = "2.0"
    sarif_output: Path | None = None
    include_absolute_path: bool = False
    #: ADR-033: opt-in consumption of a target's SECURITY-INSIGHTS.yml as self-attested
    #: evidence for the disclosure-control allowlist. Default off (additive evaluation).
    use_insights_evidence: bool = False
    #: ADR-028: opt-in applicability engine. When True, controls that declare a
    #: precondition resolve to NOT_APPLICABLE consistently when it is unmet. Default off.
    applicability_engine: bool = False
    #: ADR-028: opt-in ATTESTED emission. When True, a control whose pass is anchored on a
    #: verified attestation record (PROV-VERIFY-061) resolves to ATTESTED instead of PASS.
    #: Never relaxes a FAIL/MRR. Default off.
    enable_attested: bool = False
    #: ADR-030 (A-S8): opt-in additive ``extensions.findings_summary`` block, computed
    #: IN-PROCESS from the same clone-local scanner evidence during this invocation.
    #: evaluate never reads a pre-existing findings artifact (fence FT-1) and no control
    #: state, summary, digest, or exit code depends on it (fence FT-2). Default off.
    with_findings_summary: bool = False
    #: X5-03: whether the user explicitly passed the corresponding CLI flag on this
    #: invocation. The CLI populates these from Click's parameter source so an explicit
    #: flag always wins over ``oss-policy-kit.yaml`` — even when the flag value coincides
    #: with the typer default (e.g. ``--fail-on none`` while the config says ``fail``).
    #: Default ``True`` (= "provided") keeps CLI-wins semantics for direct constructors.
    fail_on_provided: bool = True
    output_dir_provided: bool = True
    report_json_contract_provided: bool = True


#: Root-callback parameter name -> the flag the user typed. Used only to explain a
#: command line that put a root option before the subcommand; ``--with-findings-summary``
#: is absent on purpose because :func:`_relocate_misplaced_root_flag` already moves it.
_ROOT_CALLBACK_FLAGS: tuple[tuple[str, str], ...] = (
    ("target_opt", "--target"),
    ("profile", "--profile"),
    ("output_dir", "--output-dir"),
    ("waivers", "--waivers"),
    ("scorecard_json", "--scorecard-json"),
    ("kit_root", "--kit-root"),
    ("output_format", "--format"),
    ("fail_on", "--fail-on"),
    ("summary_only", "--summary-only"),
    ("report_json_contract", "--report-json-contract"),
    ("sarif_output", "--sarif-output"),
    ("use_insights_evidence", "--use-insights-evidence"),
)


def _current_cli_context() -> Any | None:
    """Best-effort handle on the Click context of the running command, or ``None``.

    Typer 0.26+ vendors Click into ``typer._click``, so the context stack the runtime
    pushes onto is NOT the one top-level ``click.get_current_context`` reads -- that one
    answers ``None`` here. Both are tried, newest first, and any failure yields ``None``:
    this only enriches an error message, and no diagnostic is worth an exception on the
    way out.
    """

    from importlib import import_module

    for module_name in ("typer._click.globals", "click.globals"):
        try:
            ctx = import_module(module_name).get_current_context(silent=True)
        except Exception:  # noqa: BLE001 - diagnostics only; never break the real error
            continue
        if ctx is not None:
            return ctx
    return None


def _root_flags_typed_before_subcommand() -> list[str]:
    """Return the root options the user typed *before* the subcommand, in declaration order.

    The root callback exists so ``oss-policy-kit --target <repo> --profile <p>`` works
    without typing ``evaluate``. When a subcommand IS named, Click still parses those
    options at the root and the callback returns early, so they never reach the
    subcommand. Naming them is what turns a contradictory error into an actionable one.

    Empty when there is no parent context (compatibility usage, where the options *were*
    honoured) or when provenance is unavailable.
    """

    ctx = _current_cli_context()
    parent = getattr(ctx, "parent", None)
    if parent is None:
        return []
    typed: list[str] = []
    for name, flag in _ROOT_CALLBACK_FLAGS:
        try:
            source = parent.get_parameter_source(name)
        except Exception:  # noqa: BLE001 - provenance is best-effort
            continue
        if source is not None and getattr(source, "name", "") == "COMMANDLINE":
            typed.append(flag)
    return typed


def _missing_target_message() -> str:
    """Explain a missing target -- naming the misplaced root options when that is the cause.

    ``oss-policy-kit --target <repo> evaluate --profile p`` used to exit 2 with "Provide a
    repository path as TARGET or via --target/-t" while ``--target`` was visibly on the
    command line, so the message contradicted what the operator could read in front of
    them. The same flags work with no subcommand and after the subcommand; only this one
    placement drops them, and that is what the message now says.
    """

    misplaced = _root_flags_typed_before_subcommand()
    if not misplaced:
        return "Provide a repository path as TARGET or via --target/-t."
    flags = ", ".join(misplaced)
    verb = "was" if len(misplaced) == 1 else "were"
    return (
        f"{flags} {verb} typed before the subcommand, where it configures oss-policy-kit "
        f"itself and is not handed to `evaluate`. Put it after the subcommand "
        f"(`oss-policy-kit evaluate {misplaced[0]} <value> ...`), or drop the subcommand "
        f"to use the compatibility form (`oss-policy-kit {misplaced[0]} <value> ...`)."
    )


def _resolve_eval_target(req: EvaluateRequest) -> Path:
    chosen = req.target_opt or req.target_pos
    if not chosen:
        raise InvalidInputError(_missing_target_message())
    return resolve_existing_dir(chosen)


@dataclass(frozen=True, slots=True)
class _EffectiveEvalSettings:
    """Resolved ``profile`` / ``fail_on`` / ``output_dir`` / ``report_json_contract``.

    Each field is the CLI flag when the user set it, otherwise the value recorded in
    ``oss-policy-kit.yaml`` (when a config exists), otherwise the built-in default.
    """

    profile: str
    fail_on: str
    output_dir: Path
    report_json_contract: str


def _announce_gate_policy_from_config(fail_on: str, config_name: str) -> None:
    """Say on stderr that the gate policy came from the evaluated repository, not from the operator.

    The precedence itself is documented and deliberate (`docs/cli-reference.md`): the config is a
    fallback and an explicit flag always wins. What was wrong was the silence. The kit already
    announced the profile it took from this same file, and said nothing about `fail_on` -- the one
    fallback that can turn a run with failing controls into exit 0. Two repositories identical but
    for that value exited 1 and 0, and stderr mentioned only the profile.

    `none` is called out separately because it is the value that costs something: an operator
    skimming a green run needs to read that nothing could have failed it, not that a setting was
    loaded. Both interpolations go through ``markup_safe`` at the call site -- they are text from a
    repository nobody vouched for, and `test_v10_0_7_markup_escaping` scans for the literal call
    rather than trusting a pre-computed variable, which is what caught the first version of this.
    """

    if fail_on == "none":
        stderr_console().print(
            f"[yellow]Using --fail-on none from {markup_safe(config_name)}: "
            "this run will never fail the gate.[/yellow]",
        )
        return
    stderr_console().print(
        f"[dim]Using --fail-on {markup_safe(fail_on)} from {markup_safe(config_name)}.[/dim]",
    )


def _config_profile_ref(raw: str, repo_root: Path) -> str:
    """Anchor a relative profile FILE named by the target's config to the target.

    ``load_profile_by_id`` takes either a bundled id or a path to a YAML profile, and resolves the
    path form against the process working directory. That is right for ``--profile ./mine.yaml``,
    which the operator typed. It is wrong for the same value arriving from ``oss-policy-kit.yaml``,
    which lives in the repository under evaluation while the operator may be standing anywhere:
    with a ``perfil.yaml`` in each place, the operator's file was loaded and the verdict computed
    from a profile the target never named. Same defect ``output_dir`` had, same half fixed.

    Two values pass through untouched, each for its own reason:

    - a bundled id (``github-level-1``) has no YAML suffix, and must stay an id rather than
      becoming a filename looked up inside the repository. This is the only thing keeping bundled
      ids working, so it is load-bearing rather than merely defensive;
    - an absolute path is left to PATH-01b, the open question of whether a repository nobody
      audited may point the kit outside itself -- not something to settle in a path helper.

    A third guard was written here and then removed, recorded because the reasoning was wrong
    rather than merely unnecessary. It passed the raw value through when the anchored file did not
    exist, justified as avoiding an M-002 host-path leak in the resulting ``Profile file not
    found`` message. Measured: :func:`display_path` already anonymises that message, and the
    guard's real effect was to fall back to the OPERATOR's working directory -- preserving the
    very defect this helper exists to remove. It also masked the suffix guard above, so while both
    were present neither could be killed by a mutation.
    """

    candidate = Path(raw)
    if candidate.is_absolute() or candidate.suffix.lower() not in {".yaml", ".yml"}:
        return raw
    return str(repo_root / candidate)


def _config_output_dir(raw: str, repo_root: Path) -> Path:
    """Resolve an ``output_dir`` that came from the TARGET's config, against the target.

    The file lives in the repository being evaluated, so a RELATIVE value in it means "inside this
    repository". It was turned into a bare ``Path``, which resolved it against the OPERATOR's
    working directory instead: a target carrying ``output_dir: ../ELSEWHERE`` wrote its reports
    beside the operator's other projects -- nowhere near the repository being scanned, and
    dependent on where the operator happened to stand -- and exited 0.

    An ABSOLUTE value is left alone. `init` writes this file for the adopter's own repository and
    `test_config_output_dir_used_when_flag_omitted` pins that an absolute path outside the repo is
    honoured, which is a legitimate "put my reports in the shared folder" flow. Whether a config
    should be allowed to point outside AT ALL when the repository is untrusted is a product
    decision, not one to make inside a path helper -- recorded as PATH-01b.
    """

    candidate = Path(raw)
    return candidate if candidate.is_absolute() else (repo_root / candidate)


def _resolve_eval_settings(req: EvaluateRequest, repo_root: Path) -> _EffectiveEvalSettings:
    """Resolve the effective eval settings, honoring ``oss-policy-kit.yaml``.

    The project config is loaded exactly once. An explicit CLI flag always wins;
    the config only fills a setting the user did NOT pass on the command line
    (tracked via the request's ``*_provided`` flags, populated from Click's parameter
    source — so ``--fail-on none`` still wins over a config that says ``fail``). This
    lets ``init`` persist ``fail_on`` / ``output_dir`` / ``report_json_contract`` and
    have ``evaluate`` honor them without the user re-typing the flags (X5-03), while
    the profile fallback keeps its existing behavior and error message.
    """

    project_config = load_project_config_for_target(repo_root)

    # --- profile ---
    if req.profile is not None:
        profile = req.profile
    elif project_config is not None:
        profile = _config_profile_ref(project_config.profile, repo_root)
        stderr_console().print(
            f"[dim]Using profile from {markup_safe(project_config.path.name)}: "
            f"{markup_safe(project_config.profile)}[/dim]",
        )
    else:
        raise InvalidInputError(
            "--profile is required, and no oss-policy-kit.yaml was found under the target. "
            "Either pass --profile <id> or run `oss-policy-kit init` first.",
        )

    # --- fail_on / output_dir / report_json_contract fallbacks ---
    # Only applied when a config exists AND the user did not pass the corresponding flag
    # (``*_provided`` is False). The CLI flag always wins, even if its value equals the
    # typer default (that ambiguity is why we track provenance instead of comparing).
    fail_on = req.fail_on
    output_dir = req.output_dir
    report_json_contract = req.report_json_contract
    if project_config is not None:
        if not req.fail_on_provided:
            fail_on = project_config.fail_on
            _announce_gate_policy_from_config(fail_on, project_config.path.name)
        if not req.output_dir_provided:
            output_dir = _config_output_dir(project_config.output_dir, repo_root)
        if not req.report_json_contract_provided:
            report_json_contract = project_config.report_json_contract

    return _EffectiveEvalSettings(
        profile=profile,
        fail_on=fail_on,
        output_dir=output_dir,
        report_json_contract=report_json_contract,
    )


def _load_eval_waivers(waivers: Path | None):  # type: ignore[no-untyped-def]
    if waivers is None:
        return None
    wp = Path(waivers)
    if not wp.is_file():
        raise InvalidInputError(f"Waivers file not found: {wp}")
    oversize = oversize_reason(wp, MAX_EVIDENCE_BYTES, label="Waivers")
    if oversize is not None:
        raise InvalidInputError(oversize)
    return parse_waivers_file(wp)


def _load_eval_scorecard(scorecard_json: Path | None):  # type: ignore[no-untyped-def]
    if scorecard_json is None:
        return None
    sp = Path(scorecard_json)
    if not sp.is_file():
        raise InvalidInputError(f"Scorecard file not found: {sp}")
    oversize = oversize_reason(sp, MAX_EVIDENCE_BYTES, label="Scorecard JSON")
    if oversize is not None:
        raise InvalidInputError(oversize)
    try:
        return load_scorecard_auto(sp)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(
            f"Scorecard JSON could not be parsed: {sp}: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno}). "
            "Provide a valid OpenSSF Scorecard JSON export."
        ) from exc


def _make_verbose_emit(verbose: bool, *, machine_stdout: bool = False) -> Callable[[str], None] | None:
    """Build the ``--verbose`` per-control line emitter, or ``None`` when ``--verbose`` is off.

    Under ``--format json`` the lines go to stderr instead of stdout: stdout is the machine
    contract there, and interleaving prose with the JSON payload makes it unparseable for
    the very consumer that ``--format json`` exists to serve.
    """

    if not verbose:
        return None
    verbose_console = terminal_ui.build_stderr_console() if machine_stdout else terminal_ui.build_stdout_console()
    sink = write_stderr_text if machine_stdout else write_stdout_text

    def emit(line: str) -> None:
        with verbose_console.capture() as cap:
            verbose_console.print(line)
        sink(cap.get())

    return emit


def _write_eval_reports(  # type: ignore[no-untyped-def]
    report, req: EvaluateRequest, out: Path, extensions: dict[str, Any] | None = None
) -> tuple[Path, Path]:
    try:
        return write_reports(report, out, include_absolute_path=req.include_absolute_path, extensions=extensions)
    except OSError as exc:
        raise InvalidInputError(f"Cannot write to --output-dir '{req.output_dir}': {exc.strerror or exc}") from exc


def _output_child_display(out_display: str, path: Path) -> str:
    """Name a file the run just wrote, under the output directory as the user named it."""

    return display_path(Path(out_display) / path.name)


def _maybe_write_sarif(report, req: EvaluateRequest, out: Path, out_display: str) -> None:  # type: ignore[no-untyped-def]
    if req.sarif_output is None:
        return
    from oss_policy_kit.application.sarif_writer import write_sarif_report

    sarif_path = req.sarif_output if req.sarif_output.is_absolute() else out / req.sarif_output
    try:
        write_sarif_report(report, sarif_path)
    except OSError as exc:
        # A bad --sarif-output (existing directory, a path under a file, or a
        # read-only location) is a usage error, not an internal crash. Map it to
        # exit 2 and echo only exc.strerror so the absolute path / username is
        # never leaked (M-002), matching the report write in _write_eval_reports.
        raise InvalidInputError(f"Cannot write --sarif-output: {exc.strerror or 'filesystem error'}") from exc
    if not req.summary_only and req.output_format != "json":
        # Composed from the two pieces the user typed, so a relative --output-dir and a
        # relative --sarif-output come back as the same relative path they went in as.
        shown = (
            display_path(req.sarif_output)
            if req.sarif_output.is_absolute()
            else display_path(Path(out_display) / req.sarif_output)
        )
        stderr_console().print(f"[green]Wrote[/green] {markup_safe(shown)}")


def _render_eval_table(report, out_display: str) -> None:  # type: ignore[no-untyped-def]
    if terminal_ui.human_tty_stdout():
        terminal_ui.print_evaluate_executive_preface(
            report,
            unicode_icons=terminal_ui.stream_supports_unicode(sys.stdout),
        )
    table = terminal_ui.render_eval_results_table(
        report,
        unicode_icons=terminal_ui.stream_supports_unicode(sys.stdout),
    )
    stdout_console = terminal_ui.build_stdout_console()
    with stdout_console.capture() as cap:
        stdout_console.print(table)
        status_str = "  ".join(f"{k}={v}" for k, v in sorted(report.summary_by_status.items()))
        stdout_console.print(
            f"\n[dim]Summary: {status_str} | Controls: {len(report.results)} | "
            f"Reports: {markup_safe(out_display)}[/dim]"
        )
    write_stdout_text(cap.get())


def _sanitize_report_for_human_stdout(report, *, include_absolute_path: bool):  # type: ignore[no-untyped-def]
    """Return *report* with host paths sanitized the way :func:`write_reports` sanitizes them (M-002).

    The human summary layout echoes ``target_path`` and the external waiver path verbatim,
    so ``--summary-only`` printed the auditor's home directory and OS username even though
    every report written to disk honours the privacy default. Sanitizing here — rather than
    inside the printer — keeps ``--include-absolute-path`` the single place that decides,
    and leaves the printer a pure renderer of whatever it is handed.
    """

    if include_absolute_path:
        return report
    waiver = report.external_waiver_path
    return replace(
        report,
        target_path=_sanitize_target_path_for_payload(report.target_path, include_absolute=False),
        external_waiver_path=(_sanitize_target_path_for_payload(waiver, include_absolute=False) if waiver else waiver),
    )


def _render_eval_report(  # type: ignore[no-untyped-def]
    report,
    req: EvaluateRequest,
    fmt: str,
    out_display: str,
    json_path: Path,
    md_path: Path,
) -> None:
    machine_stdout = fmt == "json"
    if not req.summary_only and not machine_stdout:
        # Named under the output directory as the user wrote it: a relative --output-dir
        # is answered relative, never expanded into the host layout (M-002).
        stderr_console().print(f"[green]Wrote[/green] {markup_safe(_output_child_display(out_display, json_path))}")
        stderr_console().print(f"[green]Wrote[/green] {markup_safe(_output_child_display(out_display, md_path))}")
    warnings = report.operational_warnings
    if machine_stdout:
        # ``--summary-only --format json``: stdout is the only user-facing channel (pure JSON).
        if not req.summary_only:
            stderr_console().print(f"[dim]Reports written to: {markup_safe(out_display)}[/dim]")
        print_stdout_summary(report, output_format="json", include_absolute_path=req.include_absolute_path)
        if not req.summary_only and not req.quiet:
            print_operational_warning_summary(warnings)
        return
    if req.summary_only:
        print_stdout_summary(
            _sanitize_report_for_human_stdout(report, include_absolute_path=req.include_absolute_path),
            output_format="human",
        )
        if not req.quiet:
            print_operational_warning_summary(warnings)
        return
    _render_eval_table(report, out_display)
    if not req.quiet:
        print_operational_warning_summary(warnings)


def _emit_plugin_load_warnings() -> None:
    """On --verbose, surface third-party evaluator plugin load problems (LOW-001).

    Built-in evaluation is never affected; this only improves operator confidence
    by showing why a custom evaluator package may be inactive.
    """
    from oss_policy_kit.application.evaluators import plugin_load_errors

    errs = plugin_load_errors()
    if not errs:
        return
    console = stderr_console()
    for e in errs:
        console.print(
            f"[yellow]plugin[/yellow] {markup_safe(e['name'])}: {markup_safe(e['kind'])} — {markup_safe(e['detail'])}"
        )


def _run_evaluate(req: EvaluateRequest) -> None:
    fmt = normalize_evaluate_format(req.output_format)
    if req.verbose:
        _emit_plugin_load_warnings()
    repo_root = _resolve_eval_target(req)
    settings = _resolve_eval_settings(req, repo_root)
    policy = settings.fail_on.lower()
    if policy not in {"none", "fail", "degraded"}:
        raise InvalidInputError("--fail-on must be one of: none, fail, degraded.")
    _warn_deprecated_profile_alias(settings.profile)
    root = merge_kit_root(req.kit_root)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    prof = load_profile_by_id(root, settings.profile)
    waiver_outcome = _load_eval_waivers(req.waivers)
    scorecard = _load_eval_scorecard(req.scorecard_json)
    ext_waiver = str(Path(req.waivers).resolve()) if req.waivers is not None else None
    _warn_missing_scan_evidence(
        repo_root=repo_root,
        control_ids=set(prof.control_ids),
        machine_stdout=(fmt == "json"),
        target_display=req.target_opt or req.target_pos,
    )
    insights_evidence = load_insights_evidence(repo_root) if req.use_insights_evidence else None
    report = evaluate_repository(
        repo_root=repo_root,
        profile=prof,
        catalog=catalog,
        waiver_outcome=waiver_outcome,
        scorecard=scorecard,
        external_waiver_path=ext_waiver,
        verbose_emit=_make_verbose_emit(req.verbose, machine_stdout=(fmt == "json")),
        report_json_contract=settings.report_json_contract,
        insights_evidence=insights_evidence,
        applicability_engine=req.applicability_engine,
        enable_attested=req.enable_attested,
    )
    out = settings.output_dir.resolve()
    # ``out`` is what we write through; ``out_display`` is what the operator reads back.
    # Every "Wrote ..." / "Reports: ..." line is built from the second, so a relative
    # --output-dir is never answered with the resolved host path (M-002).
    out_display = display_path(settings.output_dir)
    extensions: dict[str, Any] | None = None
    if req.with_findings_summary:
        from oss_policy_kit import __version__ as _kit_version
        from oss_policy_kit.application.findings_report import build_findings_summary

        extensions = {"findings_summary": build_findings_summary(repo_root, kit_version=_kit_version)}
    json_path, md_path = _write_eval_reports(report, req, out, extensions)
    _maybe_write_sarif(report, req, out, out_display)
    _render_eval_report(report, req, fmt, out_display, json_path, md_path)
    if fail_on_violated(cast(FailOnPolicy, policy), report.summary_by_status):
        raise typer.Exit(code=1)


def execute_evaluate(req: EvaluateRequest) -> None:
    """Shared implementation for root-level and `evaluate` subcommand invocations.

    When ``req.profile`` is ``None``, this function attempts to load the
    project config (``oss-policy-kit.yaml``) from the resolved target and
    use the profile recorded there. The fallback is logged on stderr so
    operators can see exactly which profile is being applied and why.
    """

    try:
        _run_evaluate(req)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message
        exit_for_unexpected(exc)
