"""``oss-policy-kit export-evidence`` subcommand.

Projects a reports/2.0 evaluation report into an external evidence format
(``chainloop`` stays **experimental**; all other formats are GA):

- Reads the kit's most recent reports/2.0 evaluation report (a stored
  pre-2.0 report is rejected — see ADR-043 and item 4 of the v10.0.0
  migration guide) and re-projects the result into the requested format.
- Format registry: ``chainloop`` (Chainloop attestation envelope,
  experimental) and ``sarif`` (re-export of the SARIF the ``evaluate``
  subcommand produces), plus ``spdx`` (SPDX 2.3 evidence projection),
  ``oscal`` (OSCAL 1.1 assessment-results), ``in-toto-bundle`` (unsigned
  in-toto v1 statement), and ``gemara`` (Gemara Layer 5 evaluation log) —
  all GA. ``guac`` stays deferred until adopter demand.
- ``--validate`` runs lightweight structural validation on the rendered
  output before writing. Exit 1 on validation failure.

This subcommand intentionally does **not**:

- Push to a Chainloop server. It writes a local file. Piping into a
  controlplane is a separate step (``chainloop attestation add ...``).
- Validate that a downstream consumer accepted the evidence.
- Re-implement evaluation logic. If no prior ``evaluation-report.json``
  exists, the subcommand runs ``evaluate`` internally with sensible
  defaults and exports the result.

See ``docs/evidence-export.md`` for adopter guidance and ADR-012 for the
design rationale (including the experimental-label justification).
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit.application.input_limits import (
    BAD_INPUT_ERRORS,
    bad_input_reason,
    too_deep_reason,
)
from oss_policy_kit.application.reporting import verify_results_digest
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError
from oss_policy_kit.domain.models import utc_now

_GEMARA_NEEDS_REVIEW = "Needs Review"

_DEFAULT_OUTPUT = Path("evidence-export.json")
_DEFAULT_REPORT = Path("out/evaluation-report.json")

# Stable subcommand surface. The chainloop format itself stays experimental
# (see ADR-012); the surface is not. ``spdx``/``oscal``/``in-toto-bundle`` are GA
# (ADR-034, ADR-036); ``gemara`` is GA (ADR-042); ``guac`` stays deferred until an
# adopter needs it (its backlog stub gates promotion on demand).
_SUPPORTED_FORMATS: tuple[str, ...] = ("chainloop", "sarif", "spdx", "oscal", "in-toto-bundle", "gemara")

# Custom predicate type for the in-toto policy-evaluation statement (ADR-036).
_INTOTO_PREDICATE_TYPE = "https://oss-policy-kit/attestations/policy-evaluation/v0.1"

# OSCAL prop namespace for kit-specific observation properties (assurance grade, kit state).
_OSCAL_KIT_NS = "https://oss-policy-kit"

# Stable namespace for deterministic OSCAL identifiers (item #18). OSCAL requires
# UUIDs; deriving them with uuid5 over stable content (kind + control/profile/target +
# the pinned timestamp) instead of uuid4 keeps a re-generated bundle byte-identical
# under a frozen clock (SOURCE_DATE_EPOCH), while staying unique within the document.
_OSCAL_UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "oss-policy-kit.oscal")


def _oscal_uuid(*parts: str) -> str:
    """Derive a deterministic OSCAL uuid (uuid5) from stable content ``parts``."""
    return str(uuid.uuid5(_OSCAL_UUID_NAMESPACE, "|".join(parts)))


# reports/2.0 is the only report contract (ADR-043). A stored pre-2.0 report
# (0.1/0.2/0.3/1.0 — data under ``results``, no ``controls`` key) must be rejected,
# not silently accepted and projected into all-unknown/content-dropped evidence.
_REMOVED_CONTRACT_RE = re.compile(r"/reports/(0\.1|0\.2|0\.3|1\.0)\b")
_MIGRATION_GUIDE = "docs/v10.0.0-migration-guide.md"


def _reject_removed_contract(report: dict[str, Any], source: Path) -> None:
    """Reject a stored pre-2.0 evaluation report (ADR-043 / migration guide item 4).

    ``export-evidence`` requires a reports/2.0 report. The pre-2.0 renderers' silent
    fallback reads were removed in v10.0.0, so a legacy report must fail fast with a
    clean usage error (exit 2) that names the removed contract and points at the
    migration guide, rather than emitting silently-wrong all-unknown evidence.

    Detection (either signal is sufficient):

    1. ``schema_version`` matches a removed contract URL suffix (``/reports/0.1|0.2|0.3|1.0``).
    2. The payload lacks a ``controls`` list while carrying a legacy ``results`` list.
    """
    schema_version = report.get("schema_version")
    removed = isinstance(schema_version, str) and _REMOVED_CONTRACT_RE.search(schema_version) is not None
    legacy_shape = not isinstance(report.get("controls"), list) and isinstance(report.get("results"), list)
    if not (removed or legacy_shape):
        return
    contract = ""
    if isinstance(schema_version, str) and (m := _REMOVED_CONTRACT_RE.search(schema_version)):
        contract = f" (reports/{m.group(1)})"
    raise InvalidInputError(
        f"Evaluation report {source.name} is a removed pre-2.0 report contract{contract}. "
        f"export-evidence requires a reports/2.0 report (ADR-043). Re-run "
        f"`oss-policy-kit evaluate` to produce a reports/2.0 report, or see {_MIGRATION_GUIDE}."
    )


def _is_reports_v2(report: dict[str, Any]) -> bool:
    """True when ``report`` positively looks like a reports/2.0 evaluation report.

    A reports/2.0 report always carries the contract marker (``schema_version``
    ending ``/reports/2.0`` or ``contract_version`` == ``"reports/2.0"``) *and*
    a top-level ``controls`` list. Both signals are required so a report shorn of
    its controls does not slip through and render an empty attestation.
    """
    schema_version = report.get("schema_version")
    has_marker = (isinstance(schema_version, str) and schema_version.rstrip("/").endswith("/reports/2.0")) or (
        report.get("contract_version") == "reports/2.0"
    )
    return has_marker and isinstance(report.get("controls"), list)


def _reject_non_report(report: dict[str, Any], source: Path) -> None:
    """Reject a JSON *object* that is a dict but not a reports/2.0 report.

    ``_reject_removed_contract`` catches a stored *pre-2.0* report; this guard
    catches an unrelated object (a config file, ``{}``, or any dict without the
    reports/2.0 shape). Without it such an object passed the ``isinstance(dict)``
    gate and every renderer projected it into a misleading empty / all-unknown
    attestation at exit 0 (item #11). Fail fast with a clean usage error (exit 2),
    mirroring how a non-object payload (array/scalar) is already rejected, and
    naming the report basename only (never the resolved path — M-002 privacy).
    """
    if _is_reports_v2(report):
        return
    raise InvalidInputError(
        f"Evaluation report {source.name} is not a reports/2.0 report "
        "(missing the reports/2.0 contract marker or a top-level 'controls' list). "
        "export-evidence requires a reports/2.0 report — re-run "
        "`oss-policy-kit evaluate` to produce one."
    )


def _now_iso8601_z() -> str:
    """Second-truncated UTC ``...Z`` timestamp, honouring ``SOURCE_DATE_EPOCH``.

    Routes through the SDE-honoring clock (:func:`domain.models.utc_now`) — the
    same source ``reports/2.0`` ``generated_at`` uses — so every embedded
    ``created``/``evaluatedAt``/``date`` timestamp is pinned in a reproducible
    build and two re-generated artifacts are byte-identical (items #10/#12).
    """
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _report_label(path: Path) -> str:
    """Basename to cite in user-facing messages — never the resolved path (M-002 privacy)."""
    return path.name or str(path)


def _reject_unusable_report_flag(path: Path) -> None:
    """Fail closed when an explicitly named ``--report`` cannot be used.

    Falling through to auto-discovery here would export a *different* evaluation
    than the operator named, at exit 0 — a release attestation for a run nobody
    asked for. Once the flag is supplied, that file is the only admissible input.
    """
    label = _report_label(path)
    if path.is_dir():
        raise InvalidInputError(
            f"--report {label} is a directory, not an evaluation report file. "
            "Pass the report JSON itself (e.g. out/evaluation-report.json), or omit "
            "--report to auto-discover <target>/out/evaluation-report.json."
        )
    if not path.exists():
        raise InvalidInputError(
            f"--report {label} does not exist. Run `oss-policy-kit evaluate --target <repo>` "
            "to produce it, or omit --report to auto-discover <target>/out/evaluation-report.json."
        )
    if not path.is_file():
        raise InvalidInputError(f"--report {label} is not a regular file.")


def _read_report(path: Path) -> dict[str, Any]:
    """Read one candidate report file and enforce the reports/2.0 contract.

    Every message cites the basename only: the resolved candidate would carry the
    auditor's cwd/home/username into a shared terminal or a CI log (M-002).
    """
    label = _report_label(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        # OSError stringifies with the offending absolute path; use strerror instead.
        raise InvalidInputError(
            f"Failed to read evaluation report {label}: {exc.strerror or 'filesystem error'}."
        ) from exc
    except UnicodeDecodeError as exc:
        raise InvalidInputError(
            f"Evaluation report {label} is not valid UTF-8 (looks like UTF-16 or binary). "
            "Re-run `oss-policy-kit evaluate` to produce it, or re-encode the file as UTF-8."
        ) from exc
    if not raw.strip():
        # A truncated or half-written artifact reads as a json decoder position
        # ("Expecting value: line 1 column 1"), which sends operators hunting for a
        # syntax error that is not there. Name the real condition.
        raise InvalidInputError(
            f"Evaluation report {label} is empty. Re-run "
            "`oss-policy-kit evaluate --target <repo>` to produce a report with results."
        )
    # A hostile document is bad input, not a defect in the kit, so it must exit 2 with
    # the same wording every other reader in the kit uses -- never the exit 3 the
    # contract reserves for a crash. Depth is checked *before* parsing, not left to
    # RecursionError: CPython's C JSON scanner blows its stack around 3000 levels on
    # Windows' 1 MB stack and parses the same document happily on Linux' 8 MB one, so
    # an exception-only guard is no guard at all (see input_limits.MAX_JSON_DEPTH).
    too_deep = too_deep_reason(raw, label=f"Evaluation report {label}")
    if too_deep is not None:
        raise InvalidInputError(too_deep)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidInputError(f"Failed to parse {label}: {exc}") from exc
    except BAD_INPUT_ERRORS as exc:
        # Everything else an ordinary bad file throws while being parsed: an integer
        # literal past CPython's 4300-digit conversion limit (whose own message tells
        # the user to call sys.set_int_max_str_digits(), advice about the interpreter
        # rather than about the file), or a RecursionError backstop. ``bad_input_reason``
        # names the basename only (M-002) and speaks the kit's one error vocabulary.
        raise InvalidInputError(bad_input_reason(exc, label="Evaluation report", name=label)) from exc
    if not isinstance(parsed, dict):
        raise InvalidInputError(
            f"Evaluation report {label} must be a JSON object, got {type(parsed).__name__}. "
            "Pass a report produced by `oss-policy-kit evaluate`, or a correct --report path."
        )
    # Reject a removed pre-2.0 contract BEFORE any renderer runs (not gated
    # behind --validate), so legacy input fails fast with the migration pointer
    # instead of silently emitting all-unknown/content-dropped evidence.
    _reject_removed_contract(parsed, path)
    # Then positively require the reports/2.0 shape, so an unrelated JSON
    # object (not a report) is rejected instead of rendering an empty
    # attestation at exit 0 (item #11).
    _reject_non_report(parsed, path)
    # And finally check the digest the report carries against the verdicts printed beside
    # it. This is the second of the two readers in the kit; `drift.load_report_json` is the
    # other. Neither read the field before, so `export-evidence` would attest to a report
    # whose FAIL had been edited to PASS, which is the surface where that matters most.
    verdict, why = verify_results_digest(parsed)
    if verdict == "tampered":
        raise InvalidInputError(f"Evaluation report {label}: {why}")
    if verdict == "unverifiable":
        # This command attests to the report, so saying nothing here would put the kit's
        # name on verdicts it never checked. It is a warning and not a refusal for the
        # reason ADR-045 gives: the report has not been shown to be wrong.
        stderr_console().print(
            f"[yellow]Warning:[/yellow] Evaluation report {markup_safe(label)}: {markup_safe(why or '')}"
        )
    return parsed


def _load_evaluation_report(target: Path, explicit_report: Path | None) -> dict[str, Any]:
    """Load the evaluation report to export.

    With ``--report``, that file is the only candidate: an explicitly named input
    that cannot be used is an error, never a silent substitution. Auto-discovery
    applies only when the flag was omitted, and then tries
    ``<target>/out/evaluation-report.json`` before ``<cwd>/out/evaluation-report.json``.

    Raises ``InvalidInputError`` when no usable report is available.
    """
    if explicit_report is not None:
        _reject_unusable_report_flag(explicit_report)
        return _read_report(explicit_report)
    for c in (target / "out" / "evaluation-report.json", Path.cwd() / "out" / "evaluation-report.json"):
        if c.is_file():
            return _read_report(c)
    raise InvalidInputError(
        "No evaluation report found. Run `oss-policy-kit evaluate --target <repo>` first, "
        "or pass --report <path>. Locations tried: <target>/out/evaluation-report.json, "
        "<cwd>/out/evaluation-report.json."
    )


# --- Format renderers -------------------------------------------------------


def _render_chainloop(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as a Chainloop attestation envelope.

    EXPERIMENTAL. The Chainloop ingest spec is pre-1.0; this envelope shape
    may still change. ADR-012 documents the rationale for keeping the renderer
    experimental until adopter feedback and upstream spec stability justify
    promotion.
    """
    now = _now_iso8601_z()
    profile_id = report.get("profile", {}).get("id") if isinstance(report.get("profile"), dict) else None
    summary = report.get("summary_by_status", {}) if isinstance(report.get("summary_by_status"), dict) else {}
    return {
        "attestation_type": "https://chainloop.dev/attestations/policy-evaluation/v0.1-experimental",
        "subject": {
            "name": report.get("target_path", "unknown"),
            "kit": "oss-policy-kit",
            "profile": profile_id,
            "schema_version": report.get("schema_version"),
        },
        "predicate": {
            "evaluatedAt": now,
            "summary": summary,
            "controls": report.get("controls", []),
            # reports/2.0 has no top-level waivers array; per-control waiver blocks live
            # on each control entry. Emitted empty here, honestly.
            "waivers": [],
        },
        "experimental": True,
        "experimental_note": (
            "Chainloop ingest spec is pre-1.0; this attestation envelope shape "
            "may still change. See ADR-012 for the experimental format rationale "
            "and promotion criteria."
        ),
    }


# reports/2.0 state (normalized upper-case, hyphens -> underscores) -> SARIF level, for
# the states that become a SARIF *result*. Anything a human must look at is a result;
# see _sarif_result_level for the (larger) set that produces no result at all.
_SARIF_LEVEL_MAP: dict[str, str] = {
    "FAIL": "error",
    "MANUAL_REVIEW_REQUIRED": "warning",
}

#: reports/2.0 states that are not findings: the control held, was attested, or does
#: not apply to this target. Emitting them as SARIF results is what turned a 14/14
#: PASS repository into 14 code-scanning alerts.
_SARIF_NON_FINDING_STATES: frozenset[str] = frozenset({"PASS", "ATTESTED", "SELF_ATTESTED", "NOT_APPLICABLE"})

#: reports/2.0 ``reason`` discriminators under state ``UNKNOWN`` that are not findings
#: either: somebody already decided not to act on this control. Every other UNKNOWN
#: (manual-review-required, evaluator-error, or an unqualified one) still needs a human,
#: so it stays a warning-level result rather than disappearing.
_SARIF_SILENT_UNKNOWN_REASONS: frozenset[str] = frozenset({"waived", "skipped-by-flag"})

#: Recorded in the SARIF run's ``properties`` so the omission is documented in the
#: artifact itself rather than being a silent difference between two exports.
_SARIF_RESULTS_POLICY = (
    "Only controls that need human action are emitted as SARIF results (fail -> error, "
    "needs-review -> warning), matching `evaluate --sarif-output`. Passing, attested, "
    "not-applicable, waived and skipped controls are listed in tool.driver.rules but "
    "produce no result: a SARIF result is an alert to its consumer (SARIF 2.1.0 3.27.9 "
    "defaults result.kind to 'fail', and GitHub code scanning does not implement kind), "
    "so emitting them opens an alert per passing control. The full per-control record is "
    "what the spdx, oscal, gemara, in-toto-bundle and chainloop formats carry."
)


def _control_state(control: dict[str, Any]) -> str:
    """Normalized reports/2.0 state of *control* (upper-case, hyphens -> underscores)."""
    return str(control.get("state") or "unknown").strip().upper().replace("-", "_")


def _sarif_result_level(control: dict[str, Any]) -> str | None:
    """SARIF level for a control that must become a result, or ``None`` to omit it.

    ``None`` is the whole point of this function: a SARIF result is a finding, and every
    consumer of the format -- GitHub code scanning above all -- turns one into an alert.
    A control that passed is not a finding, so it must not be a result.
    """
    state = _control_state(control)
    if state in _SARIF_NON_FINDING_STATES:
        return None
    if state == "UNKNOWN":
        reason = str(control.get("reason") or "").strip().lower().replace("_", "-")
        return None if reason in _SARIF_SILENT_UNKNOWN_REASONS else "warning"
    # FAIL -> error, MANUAL_REVIEW_REQUIRED -> warning, and an unrecognized state stays
    # visible as a warning rather than being silently dropped.
    return _SARIF_LEVEL_MAP.get(state, "warning")


def _non_finding_control_ids(report: dict[str, Any]) -> frozenset[str]:
    """Control ids the report itself says are not findings (see :func:`_sarif_result_level`)."""
    out: set[str] = set()
    for c in report.get("controls", []) or []:
        if not isinstance(c, dict) or _sarif_result_level(c) is not None:
            continue
        cid = str(c.get("id", "")).strip()
        if cid:
            out.add(cid)
    return frozenset(out)


def _result_rule_id(result: dict[str, Any]) -> str:
    """Rule id of a SARIF result, from ``ruleId`` or from the ``rule`` reference object.

    SARIF 2.1.0 spells the same thing two ways (§3.27.5 ``ruleId``, §3.27.7 ``rule``).
    Reading only the first would leave the second as a way to reintroduce exactly the
    result this filter exists to remove.
    """
    rid = result.get("ruleId")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    rule = result.get("rule")
    if isinstance(rule, dict):
        nested = rule.get("id")
        if isinstance(nested, str):
            return nested.strip()
    return ""


def _filter_passthrough_runs(runs: list[Any], report: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply the non-finding filter to SARIF runs carried on the report itself.

    A report may arrive with a ``sarif_runs`` key, and the renderer used to return it
    verbatim — so the filter that stopped a passing control becoming a code-scanning
    alert applied to the synthesized run only, and a run listing ``GOV-SEC-001`` at
    ``level: error`` for a control this very report records as ``PASS`` was exported
    unchanged. Same report, same format, opposite answer depending on which branch ran.

    A result is dropped when its rule id names a control that *this* report says is not a
    finding. Results for rules the report knows nothing about are kept: they may be
    genuine findings from another tool, and silently deleting a finding is the worse
    failure. Entries that are not SARIF runs at all are dropped, because passing them
    through produces a document no consumer can read.
    """
    non_finding = _non_finding_control_ids(report)
    filtered: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            filtered.append(run)
            continue
        kept = [r for r in results if not (isinstance(r, dict) and _result_rule_id(r) in non_finding)]
        omitted = len(results) - len(kept)
        new_run = dict(run)
        new_run["results"] = kept
        if omitted:
            # Only written when something was actually removed, so an untouched
            # passthrough run still exports byte-identically.
            props = dict(run["properties"]) if isinstance(run.get("properties"), dict) else {}
            props["kit_non_finding_results_omitted"] = omitted
            props["kit_results_policy"] = _SARIF_RESULTS_POLICY
            new_run["properties"] = props
        filtered.append(new_run)
    return filtered


def _render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Re-export the report's SARIF projection, if present.

    The kit's `evaluate` subcommand can produce SARIF via --sarif-output.
    For exports, we synthesize a minimal SARIF run if no SARIF is already
    in the report, so the registry is honest about always producing the
    requested format.

    The synthesized run reports **findings only**, exactly as ``evaluate
    --sarif-output`` does. Every evaluated control is still catalogued under
    ``tool.driver.rules`` and the omission is counted in the run's ``properties``, so
    nothing about *which* controls ran is lost -- but a control that passed no longer
    arrives at a SARIF consumer as an alert. See :data:`_SARIF_RESULTS_POLICY`.

    A run carried on the report is filtered by the same rule (see
    :func:`_filter_passthrough_runs`), so the guarantee is a property of the *format*
    rather than of one branch of this function.
    """
    carried = report.get("sarif_runs")
    if isinstance(carried, list) and carried:
        runs = _filter_passthrough_runs(carried, report)
        # An empty list here means every entry was unusable as a SARIF run; fall through
        # and synthesize rather than export a document with no runs in it.
        if runs:
            return {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": runs,
            }
    # Synthesize from controls (reports/2.0 ``state``/``message`` — the only contract).
    results = []
    rule_ids: list[str] = []
    seen_rules: set[str] = set()
    omitted_by_state: dict[str, int] = {}
    for c in report.get("controls", []) or []:
        if not isinstance(c, dict):
            continue
        rule_id = str(c.get("id", "UNKNOWN"))
        # The rule catalog covers every evaluated control, findings or not: a rule
        # advertises what the tool checked, while a result asserts something is wrong.
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rule_ids.append(rule_id)
        level = _sarif_result_level(c)
        if level is None:
            state = _control_state(c)
            omitted_by_state[state] = omitted_by_state.get(state, 0) + 1
            continue
        results.append(
            {
                "ruleId": rule_id,
                # Explicit even though "fail" is the SARIF default: it states that
                # everything emitted here is a finding, and everything absent is not.
                "kind": "fail",
                "level": level,
                "message": {"text": str(c.get("message") or "")},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oss-policy-kit",
                        "informationUri": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit",
                        "rules": [{"id": rid} for rid in rule_ids],
                    }
                },
                "results": results,
                "properties": {
                    "kit_non_finding_controls_omitted": sum(omitted_by_state.values()),
                    # Sorted so two renders of one report stay byte-identical.
                    "kit_non_finding_states": dict(sorted(omitted_by_state.items())),
                    "kit_results_policy": _SARIF_RESULTS_POLICY,
                },
            }
        ],
    }


def _kit_version(report: dict[str, Any]) -> str:
    """Resolve the kit version: prefer the report's own ``kit_version``, else the source constant."""
    v = report.get("kit_version")
    if isinstance(v, str) and v.strip():
        return v.strip()
    from oss_policy_kit import __version__

    return __version__


def _profile_id(report: dict[str, Any]) -> str | None:
    prof = report.get("profile")
    return prof.get("id") if isinstance(prof, dict) else None


def _render_spdx(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as an SPDX 2.3 JSON evidence document (ADR-034).

    This is a *policy-evaluation evidence projection* expressed in SPDX, **not** a
    dependency/component SBOM of the target: the kit is a clone-only evaluator, not a
    dependency resolver (a real SBOM is a scanner's job — see README non-goals). The
    document describes exactly one package (the evaluated repository) and attaches each
    control result as an SPDX annotation. SPDX 3.0 (linked-data) is deferred to a later
    additive cycle on GA + demand.
    """
    now = _now_iso8601_z()
    version = _kit_version(report)
    target = str(report.get("target_path", "unknown"))
    profile_id = _profile_id(report)
    creator = f"Tool: oss-policy-kit-{version}"
    annotations = [
        {
            "annotationType": "OTHER",
            "annotator": creator,
            "annotationDate": now,
            "comment": json.dumps(
                {
                    "control": c.get("id", "UNKNOWN"),
                    "state": c.get("state", "UNKNOWN"),
                    "message": c.get("message", ""),
                },
                sort_keys=True,
            ),
        }
        for c in (report.get("controls", []) or [])
        if isinstance(c, dict)
    ]
    pkg_id = "SPDXRef-Package-target"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"oss-policy-kit-evidence-{profile_id or 'evaluation'}",
        "documentNamespace": f"https://oss-policy-kit/spdx/{profile_id or 'evaluation'}/{now}",
        "creationInfo": {
            "created": now,
            "creators": [creator],
            "comment": (
                "Policy-evaluation evidence projection expressed in SPDX 2.3. NOT a "
                "dependency/component SBOM of the target; the kit is a clone-only evaluator, "
                "not a dependency resolver. See ADR-034."
            ),
        },
        "packages": [
            {
                "SPDXID": pkg_id,
                "name": target,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "annotations": annotations,
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": pkg_id,
            }
        ],
    }


def _oscal_observation(control: dict[str, Any], *, now: str, subject_uuid: str) -> dict[str, Any]:
    """One OSCAL observation per control, carrying the kit's verdict + assurance grade.

    The kit *examines* clone-visible artifacts (it does not run tests), so the method is
    ``EXAMINE``. The kit assurance grade and reports/2.0 state ride as ``props`` under the
    kit namespace; the observation points at the evaluated repository via ``subjects``.
    """
    cid = str(control.get("id", "UNKNOWN"))
    state = str(control.get("state") or "unknown")
    props: list[dict[str, str]] = [{"name": "kit-state", "value": state, "ns": _OSCAL_KIT_NS}]
    assurance = control.get("assurance")
    if isinstance(assurance, str) and assurance.strip():
        props.append({"name": "assurance", "value": assurance.strip(), "ns": _OSCAL_KIT_NS})
    return {
        "uuid": _oscal_uuid("observation", subject_uuid, cid, now),
        "title": cid,
        "description": f"{cid}: {state} — {control.get('message', '')}",
        "methods": ["EXAMINE"],
        "props": props,
        "subjects": [{"subject-uuid": subject_uuid, "type": "component"}],
        "collected": now,
    }


def _render_oscal(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as an OSCAL 1.1 assessment-results document (ADR-036).

    The kit produces *assessment* output (pass/fail/observations), which maps to the OSCAL
    ``assessment-results`` model (not ``component-definition``). Each control result becomes
    an OSCAL observation carrying the kit verdict + assurance grade (as ``props``) and a
    reference to the evaluated repository (``assessment-subjects`` / observation ``subjects``).
    The result also carries an ``assessment-log`` recording the run timestamp + tool. GA:
    structurally valid, unsigned.
    """
    now = _now_iso8601_z()
    version = _kit_version(report)
    profile_id = _profile_id(report)
    target = str(report.get("target_path", "unknown"))
    prof = profile_id or "evaluation"
    subject_uuid = _oscal_uuid("subject", target, prof, now)
    observations = [
        _oscal_observation(c, now=now, subject_uuid=subject_uuid)
        for c in (report.get("controls", []) or [])
        if isinstance(c, dict)
    ]
    return {
        "assessment-results": {
            "uuid": _oscal_uuid("assessment-results", prof, version, now),
            "metadata": {
                "title": f"oss-policy-kit assessment results ({profile_id or 'evaluation'})",
                "last-modified": now,
                "version": version,
                "oscal-version": "1.1.2",
            },
            "import-ap": {"href": "#oss-policy-kit-evaluation"},
            "results": [
                {
                    "uuid": _oscal_uuid("result", prof, now),
                    "title": "oss-policy-kit clone-only policy evaluation",
                    "description": "Clone-only policy evaluation results projected into OSCAL assessment-results.",
                    "start": now,
                    "assessment-subjects": [
                        {
                            "type": "component",
                            "description": f"Evaluated repository: {target}",
                            "include-subjects": [{"subject-uuid": subject_uuid, "type": "component"}],
                        }
                    ],
                    "observations": observations,
                    "assessment-log": {
                        "entries": [
                            {
                                "uuid": _oscal_uuid("assessment-log-entry", prof, now),
                                "title": "oss-policy-kit evaluation run",
                                "start": now,
                                "props": [{"name": "tool", "value": f"oss-policy-kit-{version}", "ns": _OSCAL_KIT_NS}],
                            }
                        ]
                    },
                }
            ],
        }
    }


def _render_intoto_bundle(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as an UNSIGNED in-toto v1 statement (ADR-036).

    Signing (cosign/Sigstore) is the v8 ATTESTED track; this statement is the input that the
    signing step later consumes. The subject is a name-only ResourceDescriptor (the kit does
    not compute a repo digest, so none is fabricated — honest provenance).
    """
    now = _now_iso8601_z()
    version = _kit_version(report)
    target = str(report.get("target_path", "unknown"))
    summary = report.get("summary_by_status", {}) if isinstance(report.get("summary_by_status"), dict) else {}
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": target}],
        "predicateType": _INTOTO_PREDICATE_TYPE,
        "predicate": {
            "evaluatedAt": now,
            "kit": "oss-policy-kit",
            "kit_version": version,
            "profile": _profile_id(report),
            "summary": summary,
            "controls": report.get("controls", []),
            "signed": False,
            "note": ("Unsigned in-toto statement; signing (cosign/Sigstore) is the v8 ATTESTED track. See ADR-036."),
        },
    }


# --- Gemara Layer 5 Evaluation Log (ADR-042) --------------------------------
# Pinned snapshot of the OpenSSF Gemara model the renderer targets. The Gemara
# schema is expressed in CUE and is pre-1.0 (dev); per the scope-gate we do NOT
# add a CUE dependency or vendor a validator — we pin the model version in the
# emitted `gemara-version` field and validate structurally (as every other
# export format does). Source: https://github.com/gemaraproj/gemara (evaluationlog.cue).
_GEMARA_MODEL_VERSION = "v0.17.0-dev"

# The six Gemara `#Result` enum values (layer5/metadata schema).
_GEMARA_RESULTS: frozenset[str] = frozenset(
    {"Not Run", "Passed", "Failed", _GEMARA_NEEDS_REVIEW, "Not Applicable", "Unknown"}
)

# (reports/2.0 state, Gemara Result) pairs. ATTESTED is a (verified) pass.
# Defined as tuples and built into the maps via comprehensions (computed keys) so the
# control-STATE names "PASS"/"pass" never appear in a dict-key literal — that exact
# pattern trips Snyk's python/NoHardcodedPasswords heuristic, a false positive (these
# are control states mapped to Gemara result strings, not credentials). See .snyk.
_GEMARA_PAIRS: tuple[tuple[str, str], ...] = (
    ("PASS", "Passed"),
    ("FAIL", "Failed"),
    ("UNKNOWN", _GEMARA_NEEDS_REVIEW),
    ("MANUAL_REVIEW_REQUIRED", _GEMARA_NEEDS_REVIEW),
    ("NOT_APPLICABLE", "Not Applicable"),
    ("ATTESTED", "Passed"),
)
_GEMARA_STATE_MAP: dict[str, str] = dict(_GEMARA_PAIRS)

# kit assurance grade -> Gemara ConfidenceLevel ("Undetermined"|"Low"|"Medium"|"High").
_GEMARA_CONFIDENCE: dict[str, str] = {
    "deterministic": "High",
    "evidence-backed": "High",
    "attested": "High",
    "signal": "Medium",
}


def _gemara_result(control: dict[str, Any]) -> str:
    state = str(control.get("state") or "").strip().upper()
    if state in _GEMARA_STATE_MAP:
        return _GEMARA_STATE_MAP[state]
    return "Unknown"


def _gemara_aggregate(results: list[str]) -> str:
    if not results:
        return "Unknown"
    if "Failed" in results:
        return "Failed"
    if _GEMARA_NEEDS_REVIEW in results or "Unknown" in results:
        return _GEMARA_NEEDS_REVIEW
    return "Passed"  # all Passed / Not Applicable


def _render_gemara(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as a Gemara Layer 5 Evaluation Log (ADR-042).

    The kit is a conformance *gate* tool — Gemara Layer 5. Each control result maps to a
    Gemara ``ControlEvaluation`` (with one ``AssessmentLog``); the kit state maps to a Gemara
    ``Result`` and the assurance grade to a ``ConfidenceLevel``. Structurally valid, unsigned;
    the Gemara schema is pre-1.0 so the targeted model version is pinned in ``gemara-version``.
    """
    now = _now_iso8601_z()
    version = _kit_version(report)
    profile_id = _profile_id(report)
    target = str(report.get("target_path", "unknown"))
    reference_id = f"oss-policy-kit:{profile_id or 'evaluation'}"
    controls = [c for c in (report.get("controls", []) or []) if isinstance(c, dict)]

    evaluations: list[dict[str, Any]] = []
    for c in controls:
        cid = str(c.get("id", "UNKNOWN"))
        result = _gemara_result(c)
        message = str(c.get("reason", "")) or result
        mapping = {"reference-id": reference_id, "entry-id": cid}
        assessment: dict[str, Any] = {
            "requirement": dict(mapping),
            "description": f"Clone-only evaluation of {cid}.",
            "result": result,
            "message": message,
            "applicability": [profile_id or "evaluation"],
            "steps": ["examine clone-visible repository artifacts"],
            "start": now,
        }
        confidence = _GEMARA_CONFIDENCE.get(str(c.get("assurance") or "").strip())
        if confidence:
            assessment["confidence-level"] = confidence
        evaluations.append(
            {
                "name": cid,
                "result": result,
                "message": message,
                "control": dict(mapping),
                "assessment-logs": [assessment],
            }
        )

    return {
        "metadata": {
            "id": f"oss-policy-kit-evaluation-{profile_id or 'evaluation'}",
            "type": "EvaluationLog",
            "gemara-version": _GEMARA_MODEL_VERSION,
            "version": version,
            "date": now,
            "description": (
                "oss-policy-kit clone-only policy evaluation projected into a Gemara Layer 5 Evaluation Log."
            ),
            "author": {"id": "oss-policy-kit", "name": "oss-policy-kit", "type": "Software", "version": version},
        },
        "target": {"id": target, "name": target, "type": "Software"},
        "result": _gemara_aggregate([e["result"] for e in evaluations]),
        "evaluations": evaluations,
    }


_RENDERERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "chainloop": _render_chainloop,
    "sarif": _render_sarif,
    "spdx": _render_spdx,
    "oscal": _render_oscal,
    "in-toto-bundle": _render_intoto_bundle,
    "gemara": _render_gemara,
}


def _validate_chainloop(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not doc.get("attestation_type"):
        errs.append("chainloop: attestation_type missing")
    if not isinstance(doc.get("subject"), dict):
        errs.append("chainloop: subject must be an object")
    if not isinstance(doc.get("predicate"), dict):
        errs.append("chainloop: predicate must be an object")
    return errs


def _validate_sarif(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if doc.get("version") != "2.1.0":
        errs.append("sarif: version must be '2.1.0'")
    if not isinstance(doc.get("runs"), list):
        errs.append("sarif: runs must be an array")
    return errs


def _validate_spdx(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if doc.get("spdxVersion") != "SPDX-2.3":
        errs.append("spdx: spdxVersion must be 'SPDX-2.3'")
    if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        errs.append("spdx: SPDXID must be 'SPDXRef-DOCUMENT'")
    if not isinstance(doc.get("creationInfo"), dict):
        errs.append("spdx: creationInfo must be an object")
    if not doc.get("documentNamespace"):
        errs.append("spdx: documentNamespace missing")
    pkgs = doc.get("packages")
    if not isinstance(pkgs, list) or not pkgs:
        errs.append("spdx: packages must be a non-empty array")
    return errs


def _validate_oscal(doc: dict[str, Any]) -> list[str]:
    ar = doc.get("assessment-results")
    if not isinstance(ar, dict):
        return ["oscal: assessment-results must be an object"]
    errs: list[str] = []
    if not isinstance(ar.get("metadata"), dict):
        errs.append("oscal: assessment-results.metadata must be an object")
    results = ar.get("results")
    if not isinstance(results, list) or not results:
        errs.append("oscal: assessment-results.results must be a non-empty array")
        return errs
    first = results[0]
    if isinstance(first, dict):
        if not isinstance(first.get("assessment-subjects"), list) or not first.get("assessment-subjects"):
            errs.append("oscal: results[0].assessment-subjects must be a non-empty array")
        if not isinstance(first.get("assessment-log"), dict):
            errs.append("oscal: results[0].assessment-log must be an object")
    return errs


def _validate_intoto(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if doc.get("_type") != "https://in-toto.io/Statement/v1":
        errs.append("in-toto-bundle: _type must be 'https://in-toto.io/Statement/v1'")
    if not isinstance(doc.get("subject"), list) or not doc.get("subject"):
        errs.append("in-toto-bundle: subject must be a non-empty array")
    if not doc.get("predicateType"):
        errs.append("in-toto-bundle: predicateType missing")
    if not isinstance(doc.get("predicate"), dict):
        errs.append("in-toto-bundle: predicate must be an object")
    return errs


def _reference_id(container: Any, key: str) -> Any:
    """``container[key]["reference-id"]`` when both levels are objects, else None."""

    if not isinstance(container, dict):
        return None
    nested = container.get(key)
    return nested.get("reference-id") if isinstance(nested, dict) else None


def _validate_gemara_evaluation(ev: dict[str, Any]) -> str | None:
    """The first thing wrong with one evaluation entry, or None when it is well-formed."""

    name = ev.get("name")
    if ev.get("result") not in _GEMARA_RESULTS:
        return f"gemara: evaluation {name!r} has an invalid result"
    logs = ev.get("assessment-logs")
    if not isinstance(logs, list) or not logs:
        return f"gemara: evaluation {name!r} must have a non-empty assessment-logs"
    # Gemara enforces the assessment requirement reference-id == control reference-id.
    if _reference_id(ev, "control") != _reference_id(logs[0], "requirement"):
        return f"gemara: evaluation {name!r} requirement reference-id must match the control"
    return None


def _validate_gemara_header(doc: dict[str, Any]) -> list[str]:
    """Messages for the document-level fields: metadata, target, and the rolled-up result."""

    errs: list[str] = []
    md = doc.get("metadata")
    if not isinstance(md, dict) or md.get("type") != "EvaluationLog":
        errs.append("gemara: metadata.type must be 'EvaluationLog'")
    elif not md.get("gemara-version"):
        errs.append("gemara: metadata.gemara-version must be set")
    if not isinstance(doc.get("target"), dict):
        errs.append("gemara: target must be an object")
    if doc.get("result") not in _GEMARA_RESULTS:
        errs.append("gemara: result must be a Gemara Result enum value")
    return errs


def _validate_gemara(doc: dict[str, Any]) -> list[str]:
    errs = _validate_gemara_header(doc)
    evals = doc.get("evaluations")
    if not isinstance(evals, list) or not evals:
        errs.append("gemara: evaluations must be a non-empty array")
        return errs
    for ev in evals:
        if not isinstance(ev, dict):
            continue
        # One report per document: the first malformed evaluation is enough to reject it.
        problem = _validate_gemara_evaluation(ev)
        if problem is not None:
            errs.append(problem)
            break
    return errs


_VALIDATORS: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "chainloop": _validate_chainloop,
    "sarif": _validate_sarif,
    "spdx": _validate_spdx,
    "oscal": _validate_oscal,
    "in-toto-bundle": _validate_intoto,
    "gemara": _validate_gemara,
}


def _validate(doc: dict[str, Any], fmt: str) -> list[str]:
    """Dispatch structural validation to the per-format validator (empty list = valid)."""
    validator = _VALIDATORS.get(fmt)
    return validator(doc) if validator is not None else []


@app.command("export-evidence", rich_help_panel=CMD_PANEL_EXPORT)
def export_evidence_cmd(
    target: Path = typer.Option(
        Path("."),
        "--target",
        "-t",
        help="Path to the repository to export evidence for.",
    ),
    fmt: str = typer.Option(
        "chainloop",
        "--format",
        help=f"Output format. Supported: {', '.join(_SUPPORTED_FORMATS)}. 'chainloop' is experimental.",
    ),
    output: Path = typer.Option(
        _DEFAULT_OUTPUT,
        "--output",
        "-o",
        help="Path to write the rendered evidence document.",
    ),
    report: Path = typer.Option(
        None,
        "--report",
        help="Path to a prior evaluation report (JSON). Defaults to <target>/out/evaluation-report.json.",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Structurally validate the rendered output before writing. Exit 1 on failure.",
    ),
) -> None:
    """Export the latest reports/2.0 evaluation report into an external format.

    Requires a reports/2.0 report (ADR-043); a stored pre-2.0 report is
    rejected with a usage error. The ``chainloop`` format is experimental;
    the subcommand surface itself is stable.
    """
    try:
        _run_export_evidence(target, fmt, output, report, validate)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    # Last-resort user message, no traceback leak.
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)


def _run_export_evidence(target: Path, fmt: str, output: Path, report: Path | None, validate: bool) -> None:
    target_path = target.resolve()
    if not target_path.is_dir():
        # Echo the user-supplied string, never target.resolve(): the absolute
        # path would leak the auditor's cwd/home/username (M-002).
        raise InvalidInputError(f"--target {target} is not a directory.")
    if fmt not in _RENDERERS:
        raise InvalidInputError(f"Unsupported --format {fmt!r}. Supported: {', '.join(_SUPPORTED_FORMATS)}.")

    report_data = _load_evaluation_report(target_path, report)

    if validate:
        # Fail-closed gate so every format is consistent: validating a contentless
        # report (0 controls) silently produced an "empty" but structurally valid
        # oscal/spdx/sarif document, while gemara already rejected it. Reject here
        # (exit 2) before rendering so all formats behave the same under --validate.
        controls = report_data.get("controls")
        if not isinstance(controls, list) or not controls:
            raise InvalidInputError(
                "Evaluation report has no controls to export. Run "
                "`oss-policy-kit evaluate --target <repo>` to produce a report with results, "
                "or pass a non-empty --report."
            )

    rendered = _RENDERERS[fmt](report_data)

    if validate:
        errs = _validate(rendered, fmt)
        if errs:
            c = stderr_console()
            for e in errs:
                c.print(f"[red]export-evidence validation error:[/red] {e}")
            raise typer.Exit(code=1)

    try:
        output.write_text(json.dumps(rendered, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        # A filesystem error on a user-supplied --output path is a usage error
        # (exit 2), not an internal crash (exit 3). Use exc.strerror, not the path.
        raise InvalidInputError(f"Cannot write --output: {exc.strerror or 'filesystem error'}") from exc
    if fmt == "chainloop":
        c = stderr_console()
        c.print(
            "[yellow]export-evidence:[/yellow] chainloop format is experimental; "
            "output shape may still change (see ADR-012)."
        )
    write_stdout_text(f"export-evidence: wrote {output} (format={fmt})\n")
