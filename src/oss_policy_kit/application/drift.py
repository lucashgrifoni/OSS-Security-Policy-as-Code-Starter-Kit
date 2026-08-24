"""Compare two evaluation reports for posture drift."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oss_policy_kit.application.input_limits import (
    BAD_INPUT_ERRORS,
    bad_input_reason,
    too_deep_reason,
)
from oss_policy_kit.domain.errors import InvalidInputError

#: The only report contract since v9.0.0 removed the pre-2.0 ones under ADR-043.
REPORT_CONTRACT = "reports/2.0"

#: Control states that mean the target has earned the control. Losing one to ``FAIL`` is
#: a regression. ``UNKNOWN`` and ``NOT_APPLICABLE`` are deliberately absent: "could not
#: determine" is not "failed", and gating on it would break builds on flaky evidence.
_POSITIVE_STATES = frozenset({"PASS", "ATTESTED", "SELF_ATTESTED"})


@dataclass
class ControlDelta:
    """Single control posture change between two reports."""

    control_id: str
    title: str
    before_status: str
    after_status: str
    is_regression: bool


@dataclass
class DriftReport:
    """Aggregated drift between two evaluation JSON payloads."""

    before_path: str
    after_path: str
    before_kit_version: str
    after_kit_version: str
    regressions: list[ControlDelta] = field(default_factory=list)
    improvements: list[ControlDelta] = field(default_factory=list)
    new_controls: list[str] = field(default_factory=list)
    removed_controls: list[str] = field(default_factory=list)
    expired_waivers: list[str] = field(default_factory=list)
    has_regressions: bool = False
    profile_mismatch: bool = False
    before_profile_id: str | None = None
    after_profile_id: str | None = None
    #: Identity of the repository each side was evaluated against — the report's own
    #: ``target_path``, reduced to a basename (M-002). ``None`` when the report does not
    #: say, or says something that cannot identify a repository (``"."``, ``"unknown"``).
    before_target: str | None = None
    after_target: str | None = None
    #: True only when BOTH sides name a repository and the two names differ. Drift is
    #: the posture change of one target over time; across two targets every difference
    #: between the repositories is reported as if the posture had moved.
    target_mismatch: bool = False


def _extract_profile_id(report: dict[str, Any]) -> str | None:
    """Extract the profile id from an evaluation report regardless of contract version.

    ``reports/1.0`` nests profile data under ``profile.id``. ``reports/0.3`` and ``0.2``
    expose the flat ``profile_id`` key at the root. Returns ``None`` when no usable id
    can be found, so legacy or partial reports do not silently corrupt drift output.
    """

    nested = report.get("profile")
    if isinstance(nested, dict):
        candidate = nested.get("id")
        if isinstance(candidate, str):
            stripped = candidate.strip()
            if stripped:
                return stripped
    flat = report.get("profile_id")
    if isinstance(flat, str):
        stripped = flat.strip()
        if stripped:
            return stripped
    if flat is not None and not isinstance(flat, str):
        coerced = str(flat).strip()
        # pragma: no branch is on the next line because the falsy arm cannot be reached:
        # `flat` is neither None nor a str here, and `str()` of any other object is
        # non-empty. The check stays as the guard it reads as.
        if coerced:  # pragma: no branch
            return coerced
    return None


#: ``target_path`` values that name no particular repository. ``"."`` is what
#: :func:`reporting._sanitize_target_path_for_payload` writes when the target *was* the
#: working directory, so two reports produced from inside their own clones both say
#: ``"."`` — it can neither prove a match nor prove a mismatch.
_ANONYMOUS_TARGETS = frozenset({"", ".", "..", "unknown"})


def _basename(value: str) -> str:
    """Last path segment of *value*, treating ``/`` and ``\\`` as separators.

    :class:`~pathlib.Path` only understands the separators of the *running* OS, so a
    report written on Windows and read on Linux would keep a backslash-separated home
    path whole — and a message quoting it would publish the auditor's home directory and
    account name (M-002). Splitting on both separators makes the reduction hold
    whichever platform wrote the report and whichever one reads it.
    """

    token = value.strip().replace("\\", "/").rstrip("/")
    return token.rsplit("/", 1)[-1] if "/" in token else token


def target_identity(report: dict[str, Any]) -> str | None:
    """Name of the repository *report* was produced against, or ``None`` when unknowable.

    Reduced to a basename for two reasons: it is the only form that is safe to echo
    (M-002), and it is the only form that compares reliably — the same clone evaluated
    from a different working directory, or with ``--include-absolute-path``, records a
    different string for the same repository. Comparing basenames can therefore miss a
    mismatch (``/a/repo`` vs ``/b/repo``), which is the safe direction: a missed warning
    costs an operator a second look, a false refusal breaks a legitimate CI comparison.
    """

    raw = report.get("target_path")
    if not isinstance(raw, str):
        return None
    name = _basename(raw)
    return None if name.casefold() in _ANONYMOUS_TARGETS else name


def _result_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index a ``reports/2.0`` payload by control id.

    ``reports/2.0`` carries ``controls[]`` keyed by ``id``. This module previously read
    ``results[]`` keyed by ``control_id`` — the ``reports/1.0`` shape removed in v9.0.0
    under ADR-043 — so every report the kit produces indexed to an empty map and drift
    was always empty.
    """

    rows = report.get("controls")
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            cid = str(row.get("id", "")).strip()
            if cid:
                out[cid] = row
    return out


def _title(row: dict[str, Any]) -> str:
    return str(row.get("title", ""))


def _status(row: dict[str, Any]) -> str:
    """Return the ``reports/2.0`` control state (``PASS``, ``FAIL``, ...)."""

    return str(row.get("state", ""))


def _is_positive(state: str) -> bool:
    """States that represent a control the target has earned.

    ``ATTESTED`` and ``SELF_ATTESTED`` are earned outcomes, so losing one to ``FAIL`` is
    a real posture regression and must trip the gate.
    """

    return state in _POSITIVE_STATES


def _is_negative(state: str) -> bool:
    return state == "FAIL"


def _display_path(raw: str, *, include_absolute: bool) -> str:
    """Return the input path as a drift report should show it (M-002).

    Privacy-by-default, the same rule ``evaluate`` applies to ``target_path``: a
    shareable artifact carries the report's basename, never the absolute path that
    spells out the auditor's home directory and OS account name. ``diff-reports
    --format markdown`` is the surface most likely to be published — the command's own
    EXAMPLES block recommends posting it as a PR comment — and ``--format json`` feeds
    the same two values into CI artifacts.

    Sanitizing here rather than in each renderer is deliberate: every format reads
    :attr:`DriftReport.before_path` / :attr:`DriftReport.after_path`, so one choke
    point cannot be half-applied.
    """

    if include_absolute or not raw:
        return raw
    return Path(raw).name or raw


def _classify_status_changes(
    bm: dict[str, Any],
    am: dict[str, Any],
    shared: set[str],
) -> tuple[list[ControlDelta], list[ControlDelta]]:
    """Split the controls present on both sides into regressions and improvements.

    A control whose status changed in neither direction (``pass`` -> ``waived``, say)
    is deliberately in neither list: it moved, but not across the pass/fail line the
    drift verdict is about.
    """

    regressions: list[ControlDelta] = []
    improvements: list[ControlDelta] = []
    for cid in sorted(shared):
        b = bm[cid]
        a = am[cid]
        bs = _status(b)
        as_ = _status(a)
        if bs == as_:
            continue
        is_regression = _is_positive(bs) and _is_negative(as_)
        if not is_regression and not (_is_negative(bs) and _is_positive(as_)):
            continue
        delta = ControlDelta(
            control_id=cid,
            title=_title(a) or _title(b),
            before_status=bs,
            after_status=as_,
            is_regression=is_regression,
        )
        (regressions if is_regression else improvements).append(delta)
    return regressions, improvements


def _dropped_waivers(bm: dict[str, Any], am: dict[str, Any], shared: set[str]) -> list[str]:
    """Controls that carried a waiver before and carry none after."""

    return [
        cid
        for cid in sorted(shared)
        if isinstance(bm[cid].get("waiver"), dict) and not isinstance(am[cid].get("waiver"), dict)
    ]


def compute_drift(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    include_absolute_path: bool = False,
) -> DriftReport:
    """Compute the drift between two evaluation reports.

    Args:
        before: Parsed JSON of the earlier ``evaluation-report.json``.
        after: Parsed JSON of the more recent ``evaluation-report.json``.
        include_absolute_path: Keep the absolute input paths in ``before_path`` /
            ``after_path``. Default ``False`` sanitizes both to a basename (M-002).

    Returns:
        :class:`DriftReport` describing posture changes, regressions, and improvements.
        It also records what each side was evaluated *against* (``before_target`` /
        ``after_target`` / ``target_mismatch``): a drift number is only meaningful
        between two runs of the same target, so the caller has to be able to tell.
    """

    before_path = _display_path(str(before.get("_path", "")), include_absolute=include_absolute_path)
    after_path = _display_path(str(after.get("_path", "")), include_absolute=include_absolute_path)
    before_kv = str(before.get("kit_version", ""))
    after_kv = str(after.get("kit_version", ""))
    before_pid = _extract_profile_id(before)
    after_pid = _extract_profile_id(after)
    profile_mismatch = bool(
        before_pid is not None
        and before_pid != ""
        and after_pid is not None
        and after_pid != ""
        and before_pid != after_pid
    )
    before_target = target_identity(before)
    after_target = target_identity(after)
    # Case-insensitive: on Windows ``Repo`` and ``repo`` are the same directory, and
    # refusing to diff a repository against itself would be a worse failure than the one
    # this flag exists to catch.
    target_mismatch = bool(
        before_target is not None and after_target is not None and before_target.casefold() != after_target.casefold()
    )
    bm = _result_map(before)
    am = _result_map(after)
    before_ids = set(bm)
    after_ids = set(am)

    new_controls = sorted(after_ids - before_ids)
    removed_controls = sorted(before_ids - after_ids)

    shared = before_ids & after_ids
    regressions, improvements = _classify_status_changes(bm, am, shared)
    expired = _dropped_waivers(bm, am, shared)

    return DriftReport(
        before_path=before_path,
        after_path=after_path,
        before_kit_version=before_kv,
        after_kit_version=after_kv,
        regressions=regressions,
        improvements=improvements,
        new_controls=new_controls,
        removed_controls=removed_controls,
        expired_waivers=expired,
        has_regressions=bool(regressions),
        profile_mismatch=profile_mismatch,
        before_profile_id=before_pid,
        after_profile_id=after_pid,
        before_target=before_target,
        after_target=after_target,
        target_mismatch=target_mismatch,
    )


def load_report_json(path: Path, *, label: str = "Report") -> dict[str, Any]:
    """Load an evaluation report, rejecting anything that is not ``reports/2.0``.

    The contract check is the point. Without it a pre-2.0 report loads fine, indexes to
    an empty control map, and ``diff-reports`` prints "no status changes" with exit 0 —
    a clean drift verdict for a report it never understood. Failing closed here is the
    same rule ``--report-json-contract`` already applies on the ``evaluate`` side.

    Every way an ordinary bad file can fail — unreadable, not UTF-8, malformed, nested
    past the parser's stack — is a usage error (exit 2), never the exit 3 the contract
    reserves for a defect in the kit. *label* names which side of the comparison the
    file came from, so ``--before`` and ``--after`` cannot produce byte-identical
    rejections the way they did through v10.0.6.
    """

    try:
        # ``utf-8-sig`` matches every other reader of an operator-supplied document: it strips a
        # byte-order mark and is identical when there is none. Plain ``utf-8`` let the mark reach
        # ``json.loads``, which rejected it -- so a report an editor had saved with a BOM was
        # reported as unparseable, about a file the kit could read perfectly well.
        text = path.read_text(encoding="utf-8-sig")
    except BAD_INPUT_ERRORS as exc:
        raise InvalidInputError(bad_input_reason(exc, label=label, name=path.name)) from exc
    # Depth is checked BEFORE json.loads, not left to RecursionError: CPython 3.12
    # separates the Python recursion limit from the C stack guard, so the C JSON scanner
    # blows its stack somewhere past 2000 levels instead of raising anything a caller can
    # catch portably. See input_limits.MAX_JSON_DEPTH.
    too_deep = too_deep_reason(text, label=f"{label} '{path.name}'")
    if too_deep is not None:
        raise InvalidInputError(too_deep)
    try:
        raw = json.loads(text)
    except BAD_INPUT_ERRORS as exc:
        raise InvalidInputError(bad_input_reason(exc, label=label, name=path.name)) from exc
    if not isinstance(raw, dict):
        msg = f"{label} root must be an object: {path}"
        raise ValueError(msg)

    contract = raw.get("contract_version")
    if contract != REPORT_CONTRACT:
        seen = contract if isinstance(contract, str) and contract.strip() else "none"
        msg = (
            f"{path} is not a '{REPORT_CONTRACT}' report (contract_version: {seen}). "
            f"'{REPORT_CONTRACT}' is the only contract since v9.0.0 removed the earlier ones "
            "(ADR-043). Re-run 'evaluate' with this version of the kit to produce a comparable "
            "report. See docs/v9.0.0-migration-guide.md."
        )
        raise InvalidInputError(msg)

    raw = dict(raw)
    raw["_path"] = str(path.resolve())
    return raw
