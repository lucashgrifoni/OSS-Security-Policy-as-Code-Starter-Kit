"""Markdown and JSON report emission."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from oss_policy_kit.application.drift import ControlDelta, DriftReport
from oss_policy_kit.application.evidence_projection import (
    EVIDENCE_PROVENANCE_VERSION,
    classify_reference,
    normalize_confidence,
    project_evidence,
)
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, LiveCollectionMetadata

REPORT_JSON_SCHEMA_URL_V2_0 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"

REPORTS_V2_STATUS_MAP: dict[str, tuple[str, str | None]] = {
    "pass": ("PASS", None),
    "fail": ("FAIL", None),
    "degraded": ("FAIL", None),
    "manual-review-required": ("UNKNOWN", "manual-review-required"),
    "not-applicable": ("NOT_APPLICABLE", None),
    "skipped": ("UNKNOWN", "skipped-by-flag"),
    "error": ("UNKNOWN", "evaluator-error"),
    "attested": ("ATTESTED", None),
    "self-attested": ("SELF_ATTESTED", None),  # ADR-033: opt-in Insights self-reported evidence
    "waived": ("UNKNOWN", "waived"),
    # Kept in lockstep with engine.REPORTS_V2_STATUS_MAP; see the note there. Both were
    # unmapped ControlStatus members that surfaced to adopters as `unmapped-source-status`.
    "not-evaluated": ("UNKNOWN", "not-evaluated"),
    "not-observable": ("UNKNOWN", "not-observable-in-clone"),
}


# Windows MAX_PATH (260) less the terminating NUL. Deliberately not `os.name`-gated:
# a portable rule keeps the shrink branch reachable on every platform's test run.
_MAX_TEMP_PATH = 259

# Windows refuses a rename onto a destination another process is renaming onto at the
# same instant -- and a create over a name whose previous file is still delete-pending --
# with ERROR_ACCESS_DENIED (5) or ERROR_SHARING_VIOLATION (32). Neither describes the
# caller's rights; both clear as soon as the other handle closes.
_SHARING_CONFLICT_WINERRORS = frozenset({5, 32})

# Retry budget for exactly those conflicts: six waits, ~0.3s in total, then one final
# attempt. Eight concurrent `evaluate` runs sharing one ``--output-dir`` failed ~6% of
# their report writes without it (measured cross-process; ~19% with in-process threads),
# every failure an ``os.replace`` that would have succeeded a millisecond later.
#
# A retry must not launder a real denial, and it does not: a read-only output directory
# or an ACL that forbids writing fails every attempt, and the LAST attempt is made
# outside the loop so its own exception -- same type, same errno, same message -- is what
# reaches the caller. All the retry costs that case is a third of a second.
_CONTENTION_RETRY_DELAYS: tuple[float, ...] = (0.005, 0.01, 0.02, 0.04, 0.08, 0.16)


def _is_sharing_conflict(exc: OSError) -> bool:
    """True when *exc* is another process holding the file, not a standing denial.

    Deliberately not ``os.name``-gated, like the temp-path budget above: on POSIX
    ``winerror`` is ``None`` and the test falls back to ``PermissionError``, which keeps
    the retry branch reachable in every platform's test run. POSIX ``rename`` is atomic
    against a concurrent rename, so that fallback only ever meets a genuine ``EACCES``,
    and a genuine ``EACCES`` still surfaces -- just after the bounded backoff.
    """

    winerror = getattr(exc, "winerror", None)
    if winerror is not None:
        return winerror in _SHARING_CONFLICT_WINERRORS
    return isinstance(exc, PermissionError)


def _retry_on_sharing_conflict(operation: Callable[[], None]) -> None:
    """Run *operation*, re-running it only while a sharing conflict is what fails it.

    Any other ``OSError`` -- no such directory, no space, a name too long for the
    filesystem -- is raised on the first attempt, so a caller that reads the error to
    decide what to do next still sees it immediately.
    """

    for delay in _CONTENTION_RETRY_DELAYS:
        try:
            operation()
            return
        except OSError as exc:
            if not _is_sharing_conflict(exc):
                raise
            time.sleep(delay)
    operation()


def _create_temp_exclusive(tmp: Path, text: str) -> None:
    """Exclusively create *tmp* and write *text*, leaving nothing behind on failure."""

    try:
        with tmp.open("x", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError:
        # Either a token collision or something planted at the temp path. Both are
        # reasons to stop, never to write the destination by another route -- and never
        # to retry, because that name will not free itself.
        raise
    except OSError:
        # A write that got partway leaves the temp file behind, and the next attempt
        # would then collide with its own leftovers. Clean up before letting the error
        # out, whether it is about to be retried or reported.
        tmp.unlink(missing_ok=True)
        raise


def _stage_text(path: Path, text: str) -> Path | None:
    """Write *text* into a sibling temp file for *path* and return that temp file.

    First half of :func:`_atomic_write_text`. Split out so a caller publishing more than
    one file can get every byte onto disk before any destination changes -- see
    :func:`write_reports`, where Markdown text that will not encode, or an output
    directory with no room for it, must not leave a freshly written JSON behind.

    Returns ``None`` in exactly one case: the path-length fallback described in
    :func:`_atomic_write_text` already wrote the destination in place, so there is
    nothing left to publish.
    """

    token = uuid.uuid4().hex[:8]
    tmp = path.with_name(f".{path.name}.{token}.tmp")
    if len(str(tmp)) > _MAX_TEMP_PATH:
        # Drops the destination name from the temp file: less obvious if a hard kill
        # ever orphans one, but 13 characters instead of the destination name plus 14
        # puts the temp file back inside the budget the destination itself fits in.
        # The check is not gated on Windows so the branch is exercised everywhere.
        tmp = path.with_name(f".{token}.tmp")
    try:
        _retry_on_sharing_conflict(lambda: _create_temp_exclusive(tmp, text))
    except FileExistsError:
        # Load-bearing despite looking like a no-op: ``FileExistsError`` is an
        # ``OSError``, so without this clause a blocked temp name would fall into the
        # path-length fallback below and write the destination in place -- the exact
        # bypass the exclusive create exists to refuse.
        raise
    except OSError:
        if len(str(tmp)) <= len(str(path)):
            raise
        # The temp path is the longer one, so a failure here can be the extra
        # characters alone. Writing in place is what this function replaced; it is
        # non-atomic, but it is strictly what the caller had before. A genuine
        # ENOSPC / EACCES simply fails again here, and surfaces as it should.
        path.write_text(text, encoding="utf-8")
        return None
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _publish_staged(tmp: Path | None, path: Path, text: str) -> None:
    """Swap a file staged by :func:`_stage_text` into place at *path*.

    ``tmp is None`` means the path-length fallback already wrote the destination, so
    there is nothing to swap.
    """

    if tmp is None:
        return
    try:
        _retry_on_sharing_conflict(lambda: os.replace(tmp, path))
    except OSError as exc:
        if not _is_sharing_conflict(exc):
            tmp.unlink(missing_ok=True)
            raise
        # The conflict outlived the retry budget, so it is not another rename -- those
        # clear in milliseconds. It is a handle somebody is holding open on the
        # destination, and on Windows that blocks a rename for as long as they hold it:
        # a dashboard, a CI artifact-upload step, an editor, a backup agent, OneDrive or
        # an antivirus scanner. Measured: one reader holding the report for 50ms failed
        # 12 of 12 sequential, non-concurrent `evaluate` runs -- the retry turned a
        # transient-contention fix into a hard failure for the exact case this function's
        # docstring cites as its motivation.
        #
        # An in-place write demonstrably succeeds while that handle is open. It costs the
        # reader a torn read; refusing costs the operator their build. Between a
        # dashboard rendering a half-written report for one refresh and a CI gate failing
        # for no reason the operator can see, the dashboard loses.
        #
        # This is NOT the competing-writer case the atomic swap exists for: a second
        # `evaluate` renaming onto the same name is resolved inside the budget above and
        # never reaches here.
        try:
            path.write_text(text, encoding="utf-8")
        finally:
            tmp.unlink(missing_ok=True)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _discard_staged(tmp: Path | None) -> None:
    """Remove a staged temp file that will never be published (no-op once published)."""

    if tmp is not None:
        tmp.unlink(missing_ok=True)


def _atomic_write_text(path: Path, text: str) -> None:
    """Publish ``text`` at ``path`` through a sibling temp file and a single rename.

    Truncating the destination in place meant two evaluations sharing one
    ``--output-dir`` could interleave into a corrupt ``evaluation-report.json`` while
    both processes still exited 0, and any reader racing a write (a CI step, a
    dashboard) could parse a half-written file. Swapping the finished file in with
    ``os.replace`` leaves a reader with either the previous report or the new one,
    whole, and a failed write leaves the previous report untouched.

    The temp file is a sibling so the rename stays on one filesystem, and it is opened
    with ``"x"`` (exclusive create, umask-derived mode) rather than ``tempfile.mkstemp``:
    that refuses to follow a planted symlink while still producing exactly the
    permissions and newline translation ``Path.write_text`` produced before.

    Atomicity must not cost reach. A sibling temp file makes the path longer than the
    destination, and on Windows a destination already near the 260-char limit then
    fails to create a temp file it could have written directly -- turning an
    ``--output-dir`` that used to work into exit 2. So the name shrinks to a bare
    token when the descriptive form would overrun, and a destination that still has
    no room for any sibling falls back to writing in place: no path that could be
    written before this function existed loses the ability to be written now.

    Neither step is retried by the operating system. Two evaluations sharing one
    ``--output-dir`` both rename onto ``evaluation-report.json``, and on Windows the
    loser of that instant gets ERROR_ACCESS_DENIED -- an error about a handle held for a
    millisecond, reported to the adopter as "Cannot write to --output-dir". So both steps
    go through :func:`_retry_on_sharing_conflict`, which re-runs them for the sharing
    conflicts alone and lets every other error out on the first attempt. In particular
    the in-place fallback in :func:`_stage_text` stays reserved for the path-length case
    it was written for: a transient conflict is retried, never quietly downgraded to a
    non-atomic write that could interleave with the very process it was contending with.

    The two halves live in :func:`_stage_text` and :func:`_publish_staged` so that
    :func:`write_reports`, which has two destinations to keep consistent with each
    other, can stage both before publishing either.
    """

    _publish_staged(_stage_text(path, text), path, text)


@dataclass(frozen=True, slots=True)
class _PriorContent:
    """What a report file held before this run touched it, when that is knowable.

    ``data is None`` with ``restorable`` set means the file did not exist yet, so
    "put it back" means "delete it".
    """

    restorable: bool
    data: bytes | None


def _capture_prior_content(path: Path) -> _PriorContent:
    """Read *path* as bytes so a half-published run can be undone.

    Bytes, not text: a report directory can hold a file this kit did not write, and a
    rollback that re-encoded it -- or refused because it did not decode -- would damage
    or block something it was only supposed to preserve.
    """

    try:
        return _PriorContent(restorable=True, data=path.read_bytes())
    except FileNotFoundError:
        return _PriorContent(restorable=True, data=None)
    except OSError:
        # Present but unreadable (a lock, an ACL). Rolling back would mean either
        # inventing its contents or deleting a file we could not read. Both are worse
        # than telling the operator the pair no longer describes one run.
        return _PriorContent(restorable=False, data=None)


def _restore_prior_content(path: Path, prior: _PriorContent) -> bool:
    """Put *path* back the way :func:`_capture_prior_content` found it; ``True`` on success.

    Best effort by construction: this only runs when the surrounding write has already
    failed and is about to raise. It still publishes through a temp file and a rename,
    so a rollback that is itself interrupted cannot leave a torn report behind -- the
    failure mode the atomic write exists to prevent.
    """

    if not prior.restorable:
        return False
    if prior.data is None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            return False
        return True
    # A bare token keeps the temp name short, so a destination that only just fits
    # inside the path budget can still be rolled back.
    tmp = path.with_name(f".{uuid.uuid4().hex[:8]}.bak")
    try:
        tmp.write_bytes(prior.data)
        _retry_on_sharing_conflict(lambda: os.replace(tmp, path))
    except OSError:
        tmp.unlink(missing_ok=True)
        return False
    return True


def _mixed_report_pair_error(exc: OSError) -> OSError:
    """Re-word *exc* for the case where the JSON published and the Markdown did not.

    Reached only when the rollback in :func:`write_reports` also failed, which is the
    one path that genuinely leaves two files describing different runs. The CLI renders
    ``strerror``, so the explanation has to live there; no path is interpolated, because
    that string reaches the user (M-002).
    """

    detail = exc.strerror or "filesystem error"
    return OSError(
        exc.errno,
        f"{detail} -- evaluation-report.json was replaced but evaluation-report.md was not, "
        "and the previous JSON could not be restored. The two files in the output directory "
        "now describe different runs: delete both and re-run before reading either.",
    )


def _md_cell(value: str) -> str:
    """Escape a user-controlled value so it stays inside its Markdown table cell.

    An unescaped ``|`` (or an embedded newline) splits the row, silently shifting
    every later value under the wrong header for whoever reads or parses the report.
    """

    escaped = value.replace("|", "\\|")
    return escaped.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _sanitize_target_path_for_payload(absolute: str, *, include_absolute: bool) -> str:
    """Sanitize the target path for inclusion in shareable report files (M-002).

    Default behavior is privacy-by-default: emit only the basename of the
    target directory. If the target is the current working directory, emit
    ``"."``. Reports that ship in PR artifacts, GitHub Releases, or vulnerability
    write-ups should not leak the auditor's home directory or username.

    Pass ``include_absolute=True`` to opt back into the raw absolute path
    (useful when integrating with downstream tooling that expects it).
    """

    if include_absolute:
        return absolute
    try:
        p = Path(absolute)
        cwd = Path.cwd().resolve()
        if p.resolve() == cwd:
            return "."
        return p.name or "."
    except (OSError, ValueError):
        # Fall back to the original string rather than leaking implementation errors.
        return Path(absolute).name or absolute


def _sanitize_embedded_path_in_text(text: str, *, include_absolute: bool) -> str:
    """Sanitize any absolute paths embedded in a free-text string (M-002).

    The scorecard supplemental ``explanation`` interpolates the raw scorecard
    path into prose (e.g. ``"Loaded N entries from <abs-path>."``). When
    ``include_absolute`` is False, replace each whitespace-delimited token that
    looks like a filesystem path with its sanitized basename so the surrounding
    sentence stays readable while the auditor's home directory / username does
    not leak into shareable reports.
    """

    if include_absolute or not text:
        return text
    out: list[str] = []
    for token in text.split(" "):
        # Strip a single trailing sentence punctuation char so "<path>." sanitizes cleanly.
        suffix = ""
        core = token
        if core and core[-1] in ".,;:":
            core, suffix = core[:-1], core[-1]
        if _looks_like_rooted_path(core):
            core = _sanitize_target_path_for_payload(core, include_absolute=False)
        out.append(core + suffix)
    return " ".join(out)


def _looks_like_rooted_path(token: str) -> bool:
    """Heuristic: is this whitespace-delimited token a rooted filesystem path?

    Only rooted (absolute or home-anchored) paths leak the auditor's home
    directory / username, so the embedded-path sanitizer targets exactly those
    and leaves prose fragments like ``entr(y/ies)`` untouched.
    """

    if not token:
        return False
    if token.startswith(("/", "\\", "~/", "~\\")):
        return True
    # Windows drive-rooted path: a drive letter, a colon, then a path separator.
    return len(token) >= 3 and token[1] == ":" and token[0].isalpha() and token[2] in "/\\"


def _sanitize_scorecard_supplemental(
    supplemental: dict[str, Any] | None, *, include_absolute: bool
) -> dict[str, Any] | None:
    """Return a copy of the scorecard supplemental with paths sanitized (M-002).

    Routes the embedded ``path`` and ``explanation`` through the privacy
    sanitizer so absolute paths only survive when ``include_absolute`` is True.
    """

    if supplemental is None:
        return None
    sanitized = dict(supplemental)
    raw_path = sanitized.get("path")
    if isinstance(raw_path, str):
        sanitized["path"] = _sanitize_target_path_for_payload(raw_path, include_absolute=include_absolute)
    explanation = sanitized.get("explanation")
    if isinstance(explanation, str):
        sanitized["explanation"] = _sanitize_embedded_path_in_text(explanation, include_absolute=include_absolute)
    return sanitized


def _map_status_to_reports_v2(status: str) -> tuple[str, str | None]:
    key = status.strip().lower()
    if key in REPORTS_V2_STATUS_MAP:
        return REPORTS_V2_STATUS_MAP[key]
    return ("UNKNOWN", "unmapped-source-status")


_GITHUB_PROFILE_PREFIX = "github-"
_GITLAB_PROFILE_PREFIX = "gitlab-"
_AZURE_PROFILE_PREFIX = "azure-"
_AWS_PROFILE_PREFIX = "aws-"


def _profile_family(pid: str) -> str | None:
    if pid.startswith(_GITHUB_PROFILE_PREFIX):
        return "github"
    if pid.startswith(_GITLAB_PROFILE_PREFIX):
        return "gitlab"
    if pid.startswith(_AZURE_PROFILE_PREFIX):
        return "azure"
    if pid.startswith(_AWS_PROFILE_PREFIX):
        return "aws"
    return None


def _profile_level(pid: str) -> str | None:
    for token in ("level-1", "level-2", "level-3"):
        if token in pid:
            return "L" + token.split("-", 1)[1]
    return None


def _profile_posture(pid: str) -> str | None:
    if pid.startswith(("github-aws-", "github-azure-")):
        return "multi_platform_advisory_hybrid"
    if pid.endswith(("-level-1", "release-hardening-1")):
        return "starter"
    if pid.endswith("-level-2"):
        return "advisory"
    if pid.endswith(("-level-3", "release-hardening-3")):
        return "hard_gate"
    if pid.endswith("release-hardening-2"):
        return "release_track"
    return None


def _recommended_gate(posture: str | None, is_release_track: bool) -> str | None:
    if posture in {"starter", "release_track", "hard_gate"} or is_release_track:
        return "--fail-on fail"
    if posture in {"advisory", "multi_platform_advisory_hybrid"}:
        return "--fail-on none"
    return None


def derive_profile_metadata(profile_id: str) -> dict[str, Any]:
    """Derive lightweight profile metadata from a profile id for reports/1.0.

    Falls back to ``None`` for fields that cannot be inferred from the id alone.
    Centralizing this in the reporting layer avoids coupling reports to the CLI
    profile-listing helpers.
    """

    pid = profile_id.strip()
    is_release_track = "release-hardening" in pid
    posture = _profile_posture(pid)
    return {
        "family": _profile_family(pid),
        "level": _profile_level(pid),
        "posture": posture,
        "is_release_track": is_release_track,
        "recommended_gate": _recommended_gate(posture, is_release_track),
    }


def compute_results_digest(results: list[ControlResult]) -> str:
    """Stable sha256 digest over canonical control-result fields.

    Covers the deterministic columns: ``control_id``, ``profile``, ``status``,
    ``lifecycle``, ``assurance``, ``weight``. Excludes free-form text (reason,
    remediation), evidence references, and timestamps so the digest is robust to
    cosmetic refactors and to evidence freshness changes.
    """

    canonical = []
    for r in sorted(results, key=lambda x: (x.profile, x.control_id)):
        canonical.append(
            {
                "control_id": r.control_id,
                "profile": r.profile,
                "status": r.status.value,
                "lifecycle": r.lifecycle,
                "assurance": r.assurance,
                "weight": r.weight,
            }
        )
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _live_collection_dict(lc: LiveCollectionMetadata | None) -> dict[str, Any] | None:
    if lc is None:
        return None
    return {
        "performed": lc.performed,
        "platform": lc.platform,
        "collected_at": lc.collected_at,
        "api_evidence_sources": list(lc.api_evidence_sources),
    }


def _structural_bucket(control_id: str) -> str:
    if control_id.startswith(("GOV-", "REL-")):
        return "Governance and release artifacts (README, LICENSE, SECURITY, changelog)"
    if control_id.startswith(("CI-", "GH-")):
        return "GitHub Actions CI/CD (workflows, permissions, pins)"
    if control_id.startswith("SEC-"):
        return "Security scanning and vulnerability management in CI"
    if control_id.startswith("PLAT-"):
        return "Platform settings (branch protection, .oss-policy-kit evidence)"
    if control_id.startswith("AZ-"):
        return "Azure Pipelines and related governance"
    if control_id.startswith("AWS-"):
        return "AWS CI/CD (buildspec, CodePipeline) and related governance"
    return "Other profile controls"


def compute_priority_insights(report: ExecutionReport) -> dict[str, Any]:
    """Derive grouped non-pass signals for Markdown / JSON consumers."""

    from collections import Counter

    actionable = [r for r in report.results if r.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED)]
    bucket_counts = Counter(_structural_bucket(r.control_id) for r in actionable)
    top_causes = [{"bucket": b, "count": n} for b, n in bucket_counts.most_common(5)]

    fails = [r for r in report.results if r.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED)]
    control_ids = {r.control_id for r in fails}
    actions: list[str] = []
    if "GOV-SEC-001" in control_ids:
        actions.append("Add SECURITY.md at the repo root with a monitored private reporting channel.")
    if "GOV-LIC-004" in control_ids:
        actions.append("Add a recognizable LICENSE file at the repository root.")
    if "GOV-CON-002" in control_ids:
        actions.append("Add CONTRIBUTING.md aligned with security expectations.")
    if "CI-WF-005" in control_ids:
        actions.append("Add workflows under .github/workflows for reproducible CI.")
    if "SEC-CODEQL-010" in control_ids:
        actions.append("Add SAST or code scanning in CI (CodeQL, Semgrep, Bandit, etc.).")
    if "CI-PERM-006" in control_ids:
        actions.append("Declare explicit permissions at the top of workflows.")
    if "CI-PIN-008" in control_ids:
        actions.append("Pin third-party actions to immutable SHAs or safe version tags.")
    if not actions and fails:
        actions.append("Address fail and manual-review-required controls in the detailed table below.")
    elif not fails:
        actions.append("Keep the repository aligned with the profile; review self-attested or not-observable items.")

    by_category: dict[str, list[str]] = {}
    for r in fails:
        by_category.setdefault(r.category, []).append(r.control_id)
    for k in by_category:
        by_category[k] = sorted(set(by_category[k]))

    return {
        "top_structural_causes": top_causes,
        "recommended_actions": actions[:5],
        "failing_controls_by_category": by_category,
    }


def _take_matching_source(remaining: list[str], ref: dict[str, Any]) -> str | None:
    """Pop the first source in *remaining* that classifies to *ref*, or return ``None``.

    Consuming the list as it matches keeps two identical references (the same file cited
    by two controls' worth of sources) mapped to distinct entries in order.
    """

    for index, source in enumerate(remaining):
        if classify_reference(source) == ref:
            del remaining[: index + 1]
            return source
    return None


def _references_with_raw_sources(evidence: dict[str, Any], sources: Sequence[str]) -> dict[str, Any]:
    """Undo the evidence-reference redaction for ``--include-absolute-path``.

    The Markdown report has always restored the raw evidence path under that flag while
    the JSON kept ``<redacted-absolute>/...``, so one flag exposed two different amounts
    depending on which file the reader opened. The JSON now matches the Markdown; the
    default -- no flag -- still redacts in both, which is the case M-002 is about.

    Each projected reference is mapped back to the source that produced it by re-running
    :func:`classify_reference`, rather than by re-deriving which sources survived
    ``project_evidence``'s placeholder filter: a second copy of that rule would drift
    from the first one and silently mis-pair references with paths.
    """

    references = evidence.get("references")
    if not isinstance(references, list) or not references:
        return evidence
    remaining = list(sources)
    restored: list[Any] = []
    for ref in references:
        if not isinstance(ref, dict) or not ref.get("redacted"):
            restored.append(ref)
            continue
        raw = _take_matching_source(remaining, ref)
        restored.append(ref if raw is None else {**ref, "value": raw, "redacted": False})
    return {**evidence, "references": restored}


def _result_to_dict_v2_0(r: ControlResult, *, include_absolute_path: bool = False) -> dict[str, Any]:
    state, reason = _map_status_to_reports_v2(r.status.value)
    evidence = project_evidence(r)
    if include_absolute_path:
        evidence = _references_with_raw_sources(evidence, r.evidence_sources)
    payload: dict[str, Any] = {
        "id": r.control_id,
        "title": r.title,
        "category": r.category,
        "lifecycle": r.lifecycle,
        "profile": r.profile,
        "state": state,
        "assurance": r.assurance,
        "confidence": normalize_confidence(r.confidence),
        "weight": r.weight,
        "message": r.reason,
        "remediation": r.remediation,
        "evidence": evidence,
        "owner": r.owner,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "waiver": None,
        "extra": dict(r.extra) if isinstance(r.extra, dict) else {},
        "finding_id": f"{r.control_id}@{r.profile}",
    }
    if reason is not None:
        payload["reason"] = reason
    if r.waiver:
        payload["waiver"] = {
            "control_id": r.waiver.control_id,
            "justification": r.waiver.justification,
            "owner": r.waiver.owner,
            "status": r.waiver.status,
            "expires_at": r.waiver.expires_at.isoformat() if r.waiver.expires_at else None,
            "applies_to": r.waiver.applies_to,
        }
    if r.deprecation_note is not None:
        payload["deprecation_note"] = r.deprecation_note
    return payload


def _summary_to_reports_v2(summary_by_status: dict[str, int]) -> dict[str, int]:
    mapped: dict[str, int] = {}
    for status, count in summary_by_status.items():
        state, _ = _map_status_to_reports_v2(status)
        mapped[state] = mapped.get(state, 0) + count
    return dict(sorted(mapped.items()))


def report_to_dict_v2_0(
    report: ExecutionReport,
    *,
    include_absolute_path: bool = False,
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile_meta = derive_profile_metadata(report.profile_id)
    profile_block = {
        "id": report.profile_id,
        "title": report.profile_title,
        "family": profile_meta["family"],
        "level": profile_meta["level"],
        "posture": profile_meta["posture"],
        "is_release_track": profile_meta["is_release_track"],
        "recommended_gate": profile_meta["recommended_gate"],
    }

    weighted_score_block: dict[str, Any] | None = None
    if report.weighted_score is not None:
        weighted_score_block = {
            "earned": report.weighted_score.earned,
            "possible": report.weighted_score.possible,
            "percent": report.weighted_score.percent,
        }

    controls = [_result_to_dict_v2_0(r, include_absolute_path=include_absolute_path) for r in report.results]
    return {
        "schema_version": REPORT_JSON_SCHEMA_URL_V2_0,
        "contract_version": "reports/2.0",
        "evidence_provenance_version": EVIDENCE_PROVENANCE_VERSION,
        "generated_at": report.generated_at,
        "kit_version": report.kit_version,
        "target_path": _sanitize_target_path_for_payload(report.target_path, include_absolute=include_absolute_path),
        "profile": profile_block,
        "summary_by_status": _summary_to_reports_v2(report.summary_by_status),
        "controls_total": sum(report.summary_by_status.values()),
        "controls": controls,
        "results_digest": compute_results_digest(report.results),
        "operational_warnings": report.operational_warnings,
        "scorecard": {
            "path": (
                _sanitize_target_path_for_payload(report.scorecard_path, include_absolute=include_absolute_path)
                if report.scorecard_path
                else report.scorecard_path
            ),
            "supplemental": _sanitize_scorecard_supplemental(
                report.scorecard_supplemental, include_absolute=include_absolute_path
            ),
        },
        "external_waiver_path": (
            _sanitize_target_path_for_payload(report.external_waiver_path, include_absolute=include_absolute_path)
            if report.external_waiver_path
            else report.external_waiver_path
        ),
        "action_insights": compute_priority_insights(report),
        "live_collection": _live_collection_dict(report.live_collection),
        "weighted_score": weighted_score_block,
        "migration": {
            # Pointer for consumers converting STORED legacy reports; the pre-2.0
            # contracts themselves were removed from the kit in v9.0.0 (ADR-043).
            "from": "reports/1.0",
            "removed_in": "v9.0.0 (ADR-043)",
            "status_mapping": "docs/reports-contract-v2.0.md#mapping-from-reports10-to-reports20",
        },
        "extensions": dict(extensions) if extensions else {},
    }


def report_to_dict(
    report: ExecutionReport,
    *,
    schema_version_override: str | None = None,
    include_absolute_path: bool = False,
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize execution report to a JSON-compatible ``reports/2.0`` dict.

    v9.0.0 (ADR-043, BREAKING): ``reports/2.0`` is the only report contract — the legacy
    pre-2.0 contracts (0.1/0.2/0.3/1.0) were removed. ``schema_version_override`` is accepted
    for signature compatibility but no longer selects a legacy shape (contract validation now
    happens upstream in :func:`engine.report_json_schema_url`).

    ``include_absolute_path`` controls whether the host paths in the payload -- ``target_path``,
    the scorecard and external-waiver paths, and the per-control evidence references -- are
    sanitized (default, privacy-by-default) or kept whole. It governs exactly the same set of
    fields the Markdown report exposes under the same flag, so the two files never disclose
    different amounts about the same run.
    """

    return report_to_dict_v2_0(report, include_absolute_path=include_absolute_path, extensions=extensions)


def _json_report_text(
    report: ExecutionReport,
    *,
    schema_version_override: str | None = None,
    include_absolute_path: bool = False,
    extensions: dict[str, Any] | None = None,
) -> str:
    """Render the exact bytes-to-be of ``evaluation-report.json`` without writing anything."""

    payload = report_to_dict(
        report,
        schema_version_override=schema_version_override,
        include_absolute_path=include_absolute_path,
        extensions=extensions,
    )
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def write_json_report(
    report: ExecutionReport,
    path: Path,
    *,
    schema_version_override: str | None = None,
    include_absolute_path: bool = False,
    extensions: dict[str, Any] | None = None,
) -> None:
    """Write evaluation-report.json."""

    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(
        path,
        _json_report_text(
            report,
            schema_version_override=schema_version_override,
            include_absolute_path=include_absolute_path,
            extensions=extensions,
        ),
    )


def write_markdown_report(
    report: ExecutionReport,
    path: Path,
    *,
    include_absolute_path: bool = False,
) -> None:
    """Write evaluation-report.md."""

    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path, _markdown_report_text(report, include_absolute_path=include_absolute_path))


def _markdown_report_text(  # noqa: C901
    report: ExecutionReport,
    *,
    include_absolute_path: bool = False,
) -> str:
    """Render the exact text of ``evaluation-report.md`` without writing anything."""

    lines: list[str] = []
    lines.append("# OSS Policy Kit - evaluation report")
    lines.append("")
    lines.append(f"- **Generated (UTC)**: `{report.generated_at}`")
    lines.append(f"- **Kit version**: `{report.kit_version}`")
    _target_display = _sanitize_target_path_for_payload(report.target_path, include_absolute=include_absolute_path)
    lines.append(f"- **Target**: `{_target_display}`")
    lines.append(f"- **Profile**: `{report.profile_id}` - {report.profile_title}")
    if report.scorecard_path:
        _scorecard_display = _sanitize_target_path_for_payload(
            report.scorecard_path, include_absolute=include_absolute_path
        )
        lines.append(f"- **Scorecard file**: `{_scorecard_display}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("| --- | ---: |")
    for k, v in report.summary_by_status.items():
        lines.append(f"| `{k}` | {v} |")
    lines.append("")
    if report.weighted_score is not None:
        ws = report.weighted_score
        lines.append("## Weighted posture score")
        lines.append("")
        lines.append(
            f"**{ws.earned} / {ws.possible} points ({ws.percent}%)** — risk-adjusted score based on control weights "
            f"(critical=3, high=2, medium=1). Controls with status `not-applicable` or `not-evaluated` are excluded."
        )
        lines.append("")
    lines.extend(_md_prioritization_lines(report))
    lines.append("## Waivers and trust boundary")
    lines.append("")
    lines.append(
        "This evaluation only observes what is visible in a local clone (plus optional evidence under "
        "`.oss-policy-kit/evidence/`). It **does not** replace human audit or prove absence of risk."
    )
    lines.append("")
    if report.external_waiver_path:
        _waiver_display = _sanitize_target_path_for_payload(
            report.external_waiver_path, include_absolute=include_absolute_path
        )
        lines.append(
            f"- **External waiver file loaded for this run** (`--waivers`): `{_waiver_display}`. "
            "That file is **not** the same as **versioned in-repo** waiver policy."
        )
        lines.append(
            "- Control `GOV-WAIV-014` specifically checks for a waiver policy file **inside the clone** "
            "(for example `waivers/waivers.yaml`). It may therefore stay `manual-review-required` when no "
            "in-repo waiver file exists even when `--waivers` waives other controls."
        )
    else:
        lines.append(
            "- No external waiver file was passed via `--waivers` in this run. "
            "`GOV-WAIV-014` continues to evaluate **versioned in-repo** waivers only."
        )
    lines.append("")
    if report.operational_warnings:
        lines.append("## Operational warnings")
        lines.append("")
        for w in report.operational_warnings:
            lines.append(f"- {w}")
        lines.append("")
    lines.extend(_md_scorecard_supplemental_lines(report, include_absolute_path=include_absolute_path))
    lines.extend(_md_controls_table_lines(report))
    lines.extend(_md_control_detail_lines(report, include_absolute_path=include_absolute_path))
    return "\n".join(lines)


def _md_prioritization_lines(report: ExecutionReport) -> list[str]:
    """Markdown lines for the structural-prioritization section."""

    insights = compute_priority_insights(report)
    out: list[str] = ["## Prioritization (structural causes)", "", "### Top structural buckets", ""]
    for row in insights["top_structural_causes"][:5]:
        b, n = row["bucket"], row["count"]
        out.append(f"- **{b}** — {n} control(s) failing or requiring manual review in this bucket.")
    if not insights["top_structural_causes"]:
        out.append("- (no aggregated structural findings in this run)")
    out.extend(["", "### Recommended next actions", ""])
    out.extend(f"- {item}" for item in insights["recommended_actions"][:5])
    out.extend(["", "### Failing controls by category", ""])
    if insights["failing_controls_by_category"]:
        for cat, ids in sorted(insights["failing_controls_by_category"].items()):
            out.append(f"- **{cat}**: {', '.join(f'`{i}`' for i in ids)}")
    else:
        out.append("- (no controls in `fail` or `manual-review-required`)")
    out.append("")
    return out


def _md_scorecard_supplemental_lines(report: ExecutionReport, *, include_absolute_path: bool = False) -> list[str]:
    """Markdown lines for the optional Scorecard-supplemental section (empty when absent)."""

    if not report.scorecard_supplemental:
        return []
    ss = _sanitize_scorecard_supplemental(report.scorecard_supplemental, include_absolute=include_absolute_path) or {}
    influenced = ss.get("influenced_control_ids") or []
    influenced_line = (
        f"- **Influenced controls**: {', '.join(f'`{c}`' for c in influenced)}"
        if influenced
        else "- **Influenced controls**: (none in this run)"
    )
    return [
        "## Scorecard supplemental",
        "",
        f"- **Loaded**: `{ss.get('loaded')}`",
        f"- **Check count**: {ss.get('check_count')}",
        influenced_line,
        f"- **Workflows satisfied CodeQL signal**: `{ss.get('workflows_satisfied_codeql_signal')}`",
        f"- **Explanation**: {ss.get('explanation', '')}",
        "",
    ]


def _md_controls_table_lines(report: ExecutionReport) -> list[str]:
    """Markdown lines for the controls summary table."""

    out: list[str] = [
        "## Controls",
        "",
        "| ID | Category | Lifecycle | Assurance | Status | Confidence | Reason | Remediation | Waiver |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in report.results:
        # Every cell below carries evaluator- or waiver-file-supplied text, so all of
        # them are escaped — not just the two free-text columns.
        w = f"yes ({_md_cell(r.waiver.owner)})" if r.waiver else ""
        out.append(
            f"| `{_md_cell(r.control_id)}` | {_md_cell(r.category)} | {_md_cell(r.lifecycle)} |"
            f" `{_md_cell(r.assurance)}` | `{_md_cell(r.status.value)}` | {_md_cell(r.confidence)} |"
            f" {_md_cell(r.reason)} | {_md_cell(r.remediation)} | {w} |"
        )
    out.append("")
    return out


def _md_evidence_display(source: str, *, include_absolute_path: bool) -> str:
    """Redact a single evidence source for the Markdown report (M-002).

    Routes each evidence reference through the SAME redaction the JSON report
    applies (:func:`classify_reference` -> ``<redacted-absolute>/...``) so a
    shareable ``.md`` never leaks an absolute path / username that the JSON path
    already scrubs. URLs and already-relative repo paths pass through unchanged.
    When ``include_absolute_path`` is True the raw source is preserved; the JSON
    report restores the same references under the same flag
    (:func:`_references_with_raw_sources`), so neither format shows more than the
    other.
    """

    if include_absolute_path:
        return source
    return str(classify_reference(source).get("value", source))


def _md_control_detail_lines(report: ExecutionReport, *, include_absolute_path: bool = False) -> list[str]:
    """Markdown lines for the per-control detail section."""

    out: list[str] = ["## Detail", ""]
    for r in report.results:
        out.append(f"### `{r.control_id}` - {r.title}")
        out.append("")
        out.append(f"- **Status**: `{r.status.value}`")
        out.append(f"- **Lifecycle**: {r.lifecycle}")
        out.append(f"- **Assurance**: `{r.assurance}`")
        out.append(f"- **Evidence collection method**: `{r.evidence_collection_method}`")
        out.append(f"- **Confidence**: {r.confidence}")
        out.append(f"- **Reason**: {r.reason}")
        out.append(f"- **Remediation**: {r.remediation}")
        if r.evidence_sources:
            out.append("- **Evidence**:")
            out.extend(
                f"  - `{_md_evidence_display(e, include_absolute_path=include_absolute_path)}`"
                for e in r.evidence_sources
            )
        if r.waiver:
            out.append("- **Waiver**:")
            out.append(f"  - **Owner**: {r.waiver.owner}")
            out.append(f"  - **Justification**: {r.waiver.justification}")
            if r.waiver.expires_at:
                out.append(f"  - **Expires**: {r.waiver.expires_at.isoformat()}")
        out.append("")
    return out


def write_reports(
    report: ExecutionReport,
    output_dir: Path,
    *,
    schema_version_override: str | None = None,
    include_absolute_path: bool = False,
    extensions: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    """Write JSON and Markdown reports; return paths.

    ``include_absolute_path`` is forwarded to both writers, and both honour it over the
    same set of host paths -- the target, the scorecard and waiver files, and every
    evidence reference. Default is privacy-by-default: sanitized in both files.

    The two files are one run's answer, so they are published as a pair: **both land or
    neither does.** Writing them as two independent calls meant a Markdown write that
    failed left the NEW JSON sitting beside the STALE Markdown, with nothing in either
    file saying so. Measured: seed an ``--output-dir`` from one target, hold only
    ``evaluation-report.md`` open, evaluate a different target -- the JSON was replaced,
    the Markdown was not, and the directory then described two different repositories.
    Whoever reads that pair reads a run that never happened.

    Three steps buy that guarantee:

    1. Both files are rendered before either destination is touched, so a renderer that
       raises leaves both artifacts still describing the previous run.
    2. Both are staged into sibling temp files, so text that cannot be UTF-8 encoded (a
       lone surrogate reaching ``reason`` from a malformed source file), a full disk, or
       a read-only output directory all fail before anything is published.
    3. If the Markdown still fails to publish -- a handle held on it in a mode that
       blocks the rename *and* the in-place fallback -- the JSON is rolled back to what
       it held before this run. Only when that rollback is itself impossible does a
       mixed pair survive, and then the error says so in as many words
       (:func:`_mixed_report_pair_error`) rather than reporting a generic write failure
       and leaving the operator to compare timestamps.

    The one seam left open is the path-length fallback in :func:`_stage_text`: a
    destination with no room for any sibling temp file is written in place, which lands
    the JSON at step 2. That case is still covered by the step-3 rollback; it just loses
    the "nothing was touched" guarantee on the way there.
    """

    json_path = output_dir / "evaluation-report.json"
    md_path = output_dir / "evaluation-report.md"
    output_dir.mkdir(parents=True, exist_ok=True)

    json_text = _json_report_text(
        report,
        schema_version_override=schema_version_override,
        include_absolute_path=include_absolute_path,
        extensions=extensions,
    )
    md_text = _markdown_report_text(report, include_absolute_path=include_absolute_path)
    prior_json = _capture_prior_content(json_path)

    staged_json: Path | None = None
    staged_md: Path | None = None
    # Two distinct states, and conflating them would mis-report one of them:
    #  * the JSON destination may already differ from ``prior_json``, so it has to be put
    #    back on any failure from here on;
    #  * the JSON is published and only the Markdown is outstanding, which is the one
    #    state in which a failed rollback leaves a genuinely mixed pair.
    json_may_have_changed = False
    markdown_outstanding = False
    try:
        staged_json = _stage_text(json_path, json_text)
        json_may_have_changed = staged_json is None  # the path-length fallback wrote it in place
        staged_md = _stage_text(md_path, md_text)
        json_may_have_changed = True
        _publish_staged(staged_json, json_path, json_text)
        markdown_outstanding = True
        _publish_staged(staged_md, md_path, md_text)
    except OSError as exc:
        restored = _rewind_json(json_path, prior_json, json_may_have_changed)
        _discard_staged(staged_json)
        _discard_staged(staged_md)
        if restored or not markdown_outstanding:
            raise
        raise _mixed_report_pair_error(exc) from exc
    except BaseException:
        _rewind_json(json_path, prior_json, json_may_have_changed)
        _discard_staged(staged_json)
        _discard_staged(staged_md)
        raise
    return json_path, md_path


def _rewind_json(json_path: Path, prior: _PriorContent, needed: bool) -> bool:
    """Undo a JSON publish when one happened; report whether the file is back as it was."""

    if not needed:
        return True
    return _restore_prior_content(json_path, prior)


def _control_delta_dict(d: ControlDelta) -> dict[str, Any]:
    return {
        "control_id": d.control_id,
        "title": d.title,
        "before_status": d.before_status,
        "after_status": d.after_status,
        "is_regression": d.is_regression,
    }


def _drift_report_dict(report: DriftReport) -> dict[str, Any]:
    return {
        "before_path": report.before_path,
        "after_path": report.after_path,
        "before_kit_version": report.before_kit_version,
        "after_kit_version": report.after_kit_version,
        "regressions": [_control_delta_dict(x) for x in report.regressions],
        "improvements": [_control_delta_dict(x) for x in report.improvements],
        "new_controls": list(report.new_controls),
        "removed_controls": list(report.removed_controls),
        "expired_waivers": list(report.expired_waivers),
        "has_regressions": report.has_regressions,
        "profile_mismatch": report.profile_mismatch,
        "before_profile_id": report.before_profile_id,
        "after_profile_id": report.after_profile_id,
    }


def render_drift_report(report: DriftReport, fmt: str, *, color: bool = True) -> str:  # noqa: C901
    """Render a :class:`~oss_policy_kit.application.drift.DriftReport` for stdout or files.

    Args:
        report: Drift summary from :func:`~oss_policy_kit.application.drift.compute_drift`.
        fmt: ``table`` (default Rich layout), ``json``, or ``markdown`` / ``md``.
        color: Whether ANSI colors should be emitted for ``table`` format.

    Returns:
        Serialized representation as a single string (UTF-8 text).
    """

    f = fmt.strip().lower()
    if f == "json":
        return json.dumps(_drift_report_dict(report), indent=2, ensure_ascii=False) + "\n"
    if f in {"markdown", "md"}:
        return _drift_markdown(report)
    return _drift_table(report, color)


def _drift_row(d: ControlDelta) -> str:
    """One Markdown row of the drift table, with every cell escaped."""

    return f"| `{_md_cell(d.control_id)}` | `{_md_cell(d.before_status)}` | `{_md_cell(d.after_status)}` |"


def _drift_markdown(report: DriftReport) -> str:
    """Render a drift report as Markdown."""

    lines = ["# Drift report", ""]
    if report.profile_mismatch:
        lines.extend(
            [
                "> **Note:** Before profile "
                f"(`{report.before_profile_id}`) differs from after profile (`{report.after_profile_id}`). "
                "New or removed controls may reflect profile scope change, not posture change.",
                "",
            ]
        )
    lines.extend(
        [
            f"- **Before**: `{report.before_path}`",
            f"- **After**: `{report.after_path}`",
            f"- **Kit versions**: {report.before_kit_version} → {report.after_kit_version}",
            f"- **Regressions**: {len(report.regressions)}",
            f"- **Improvements**: {len(report.improvements)}",
            "",
            "## Regressions",
            "",
            "| Control | Before | After |",
            "| --- | --- | --- |",
        ]
    )
    # Control ids and statuses come from whatever JSON the caller diffed, so they are
    # escaped like any other user-controlled table cell.
    lines.extend(_drift_row(d) for d in report.regressions)
    lines.extend(["", "## Improvements", "", "| Control | Before | After |", "| --- | --- | --- |"])
    lines.extend(_drift_row(d) for d in report.improvements)
    if report.new_controls:
        lines.extend(["", "## New controls in after", ""])
        lines.extend(f"- `{c}`" for c in report.new_controls)
    if report.removed_controls:
        lines.extend(["", "## Removed controls (present only in before)", ""])
        lines.extend(f"- `{c}`" for c in report.removed_controls)
    if report.expired_waivers:
        lines.extend(["", "## Expired waivers", ""])
        lines.extend(f"- `{c}`" for c in report.expired_waivers)
    return "\n".join(lines) + "\n"


def _drift_table(report: DriftReport, color: bool) -> str:
    """Render a drift report as a Rich table (with trailing platform notes).

    Every value below comes from whatever two report files the caller diffed, and Rich
    reads ``[word]`` in a cell or a printed line as a style tag and deletes it: a control
    id ``[bold]GOV-SEC-001`` reached the operator as ``GOV-SEC-001``, naming a different
    control than the one that regressed. ``--format markdown`` and ``--format json``
    both keep the id whole, so the table was the only view that lied. Each interpolated
    value therefore goes through ``markup_safe``; the fixed ``[red]``/``[green]`` labels
    are ours and stay live.

    ``markup_safe`` is imported here rather than at module scope because
    ``cli.common`` imports this module -- at module scope the pair does not import at
    all.
    """

    from oss_policy_kit.cli.common import markup_safe

    buf = StringIO()
    console = Console(file=buf, width=120, force_terminal=color, color_system=("standard" if color else None))
    table = Table(title="Posture drift — regressions (red) and improvements (green)")
    table.add_column("Kind", style="bold")
    table.add_column("Control")
    table.add_column("Before")
    table.add_column("After")
    for d in report.regressions:
        table.add_row(
            "[red]regression[/red]",
            markup_safe(d.control_id),
            markup_safe(d.before_status),
            markup_safe(d.after_status),
        )
    for d in report.improvements:
        table.add_row(
            "[green]improve[/green]",
            markup_safe(d.control_id),
            markup_safe(d.before_status),
            markup_safe(d.after_status),
        )
    if not report.regressions and not report.improvements:
        table.add_row("—", "(no status changes on shared controls)", "", "")
    console.print(table)
    if report.new_controls:
        console.print(f"[cyan]New in after:[/cyan] {', '.join(markup_safe(c) for c in report.new_controls)}")
    if report.removed_controls:
        console.print(f"[yellow]Removed:[/yellow] {', '.join(markup_safe(c) for c in report.removed_controls)}")
    if report.expired_waivers:
        console.print(
            f"[magenta]Expired waivers:[/magenta] {', '.join(markup_safe(c) for c in report.expired_waivers)}"
        )
    return buf.getvalue()
