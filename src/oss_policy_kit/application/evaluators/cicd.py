"""cicd control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from dataclasses import dataclass, field

from oss_policy_kit.application.evaluators._shared import (
    _CODEQL_ACTION_PATTERNS,
    _GITIGNORE_SECRET_FRAGMENTS,
    _KEYWORD_CI_SIGNAL_WARN,
    _REUSABLE_WORKFLOW_USES_LINE,
    _SAST_SEMGREP_EVIDENCE_FILENAME,
    _SAST_SEMGREP_SCHEMA_PREFIX,
    _SECRET_SCAN_EXTRA_PATTERNS,
    _SECRET_SCAN_TOKENS,
    _SUPPLEMENTAL_SIGNAL_WARN,
    ControlStatus,
    EvalContext,
    EvalOutcome,
    EvidenceCollectionMethod,
    Path,
    _eval_sarif_adapter,
    _iter_structured_workflow_uses_with_location,
    _parse_zizmor_severity_properties,
    _python_lock_or_pins,
    _reusable_workflow_ref_has_full_sha,
    checks_as_map,
    contextlib,
    json,
    load_yaml_file,
)

_NO_WORKFLOWS_REASON = "No workflows present."


def eval_ci_wf_005(ctx: EvalContext) -> EvalOutcome:
    if ctx.workflows.workflow_paths:
        srcs = [str(p.resolve()) for p in ctx.workflows.workflow_paths]
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Found {len(srcs)} workflow file(s).",
            remediation="Keep CI workflows minimal, pinned, and least-privilege.",
            evidence_sources=srcs,
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No workflows under .github/workflows.",
        remediation="Add a CI workflow for build/test on pull requests.",
        evidence_sources=[],
        confidence="high",
    )


def eval_ci_perm_006(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows to evaluate.",
            remediation="Add workflows with explicit top-level permissions.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.missing_top_level_permissions:
        names = ", ".join(p.name for p in ctx.workflows.missing_top_level_permissions)
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Workflows missing top-level permissions: {names}",
            remediation="Declare top-level `permissions:` with the narrowest scope required.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.missing_top_level_permissions],
            confidence="medium",
        )
    if ctx.workflows.parse_errors:
        pe_names = ", ".join(sorted({p.name for p, _ in ctx.workflows.parse_errors}))
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"One or more workflow files could not be parsed ({pe_names}); "
                "top-level permissions could not be confirmed for all workflows."
            ),
            remediation="Fix YAML syntax errors, then re-run evaluation for structured permissions analysis.",
            evidence_sources=[str(p.resolve()) for p, _ in ctx.workflows.parse_errors],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="All workflows declare top-level permissions.",
        remediation="Re-audit permissions when adding new jobs.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_ci_danger_007(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=_NO_WORKFLOWS_REASON,
            remediation="Avoid pull_request_target unless strictly required and reviewed.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.uses_pull_request_target:
        names = ", ".join(p.name for p in ctx.workflows.uses_pull_request_target)
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"pull_request_target detected in: {names}",
            remediation="Remove pull_request_target or restrict to audited, minimal patterns; prefer pull_request.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.uses_pull_request_target],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No pull_request_target detected in workflows.",
        remediation="Continue avoiding pull_request_target unless necessary.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_ci_pin_008(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=_NO_WORKFLOWS_REASON,
            remediation="Pin third-party actions to full commit SHAs.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.mutable_action_refs:
        sample = ctx.workflows.mutable_action_refs[0]
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Mutable action references (tags/branches) detected.",
            remediation="Pin actions to immutable SHAs (40-char commit) from trusted repos.",
            evidence_sources=[f"{sample[0].name}: {sample[1]}"],
            confidence="medium",
        )
    if ctx.workflows.parse_errors:
        pe_names = ", ".join(sorted({p.name for p, _ in ctx.workflows.parse_errors}))
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "No obvious mutable third-party action pins detected in a raw `uses:` scan. "
                f"YAML parse errors limited structural validation ({pe_names}); "
                "treat pinning posture as lower confidence."
            ),
            remediation="Fix YAML parse errors, then re-check action pins with structured workflow analysis.",
            evidence_sources=[str(p.resolve()) for p, _ in ctx.workflows.parse_errors],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No obvious mutable third-party action pins detected.",
        remediation="Re-check when editing workflows; verify transitive action versions.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_ci_least_009(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=_NO_WORKFLOWS_REASON,
            remediation="Avoid workflow-wide contents:write unless required.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.suspicious_permissions:
        item = ctx.workflows.suspicious_permissions[0]
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Broad workflow permissions in {item[0].name}: {item[1]}",
            remediation="Narrow permissions; prefer job-level permissions scoped to the minimum.",
            evidence_sources=[str(item[0].resolve())],
            confidence="medium",
        )
    if ctx.workflows.implicit_permission_risks:
        wf, job, detail = ctx.workflows.implicit_permission_risks[0]
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Implicit broad-permissions risk in {wf.name} ({job}): {detail}",
            remediation=(
                "Add explicit `permissions:` on the affected job (or narrow workflow-level defaults) "
                "when using checkout tokens, image pushes, releases, or cloud deploy steps."
            ),
            evidence_sources=[str(wf.resolve())],
            confidence="medium",
        )
    if ctx.workflows.parse_errors:
        pe_names = ", ".join(sorted({p.name for p, _ in ctx.workflows.parse_errors}))
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"One or more workflow files could not be parsed ({pe_names}); "
                "workflow-wide permission posture could not be confirmed for all files."
            ),
            remediation="Fix YAML syntax errors, then re-run evaluation for structured permissions analysis.",
            evidence_sources=[str(p.resolve()) for p, _ in ctx.workflows.parse_errors],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No obviously over-broad workflow permissions detected.",
        remediation="Review permissions when adding publishing or release jobs.",
        evidence_sources=[],
        confidence="medium",
    )


def _codeql_action_outcome(ctx: EvalContext) -> EvalOutcome | None:
    """PASS outcome when a workflow file references the github/codeql-action, else None."""

    for p in ctx.workflows.workflow_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if any(pat in text for pat in _CODEQL_ACTION_PATTERNS):
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"github/codeql-action usage detected in {p.name}.",
                    remediation="Keep the CodeQL action pinned to an immutable SHA.",
                    evidence_sources=[str(p.resolve())],
                    confidence="high",
                )
    return None


def _scorecard_sast_outcome(ctx: EvalContext) -> EvalOutcome | None:
    """PASS outcome when the Scorecard export references CodeQL/SAST checks, else None."""

    for name in checks_as_map(ctx.scorecard):
        n = name.lower()
        if "codeql" in n or "code-ql" in n or "sast" in n:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Scorecard export references static analysis related checks (supplemental).",
                remediation="Prefer an explicit CodeQL workflow in-repo for deterministic CI evidence.",
                evidence_sources=[ctx.scorecard.raw_path or "scorecard"] if ctx.scorecard else [],
                confidence="low",
                operational_warnings=(_SUPPLEMENTAL_SIGNAL_WARN,),
            )
    return None


def eval_sec_codeql_010(ctx: EvalContext) -> EvalOutcome:
    # Check for a dedicated CodeQL workflow file — highest confidence signal.
    codeql_dedicated = [
        p for p in ctx.workflows.workflow_paths if "codeql" in p.name.lower() or "code-scanning" in p.name.lower()
    ]
    if codeql_dedicated:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Dedicated CodeQL / code-scanning workflow detected: {', '.join(p.name for p in codeql_dedicated)}.",  # noqa: E501
            remediation="Keep CodeQL workflow pinned and ensure it runs on PRs and default-branch pushes.",
            evidence_sources=[str(p.resolve()) for p in codeql_dedicated],
            confidence="high",
        )
    action_outcome = _codeql_action_outcome(ctx)
    if action_outcome is not None:
        return action_outcome
    # Broader SAST signal (any tool keyword).
    if ctx.workflows.sast_ci_signals:
        joined = ", ".join(ctx.workflows.sast_ci_signals)
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"SAST or security scanning signal in CI workflows: {joined}.",
            remediation="Keep scanning jobs pinned, scoped, and aligned with org AppSec policy.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.workflow_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    # Scorecard supplemental fallback.
    scorecard_outcome = _scorecard_sast_outcome(ctx)
    if scorecard_outcome is not None:
        return scorecard_outcome
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No CodeQL (or equivalent) signal in local workflows.",
        remediation="Add GitHub CodeQL workflow or equivalent SAST in CI.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_sec_deprev_011(ctx: EvalContext) -> EvalOutcome:
    if ctx.workflows.has_dependency_review:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="dependency-review-action detected in workflows.",
            remediation="Keep dependency review enabled for pull requests.",
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No dependency-review-action detected in workflows.",
        remediation="Add GitHub Dependency Review to pull request workflows.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_sec_secrets_050(ctx: EvalContext) -> EvalOutcome:
    """SEC-SECRETS-050: secret scanning referenced in CI workflows."""
    paths: list[Path] = list(ctx.workflows.workflow_paths)
    texts: list[tuple[Path, str]] = []
    for p in paths:
        with contextlib.suppress(OSError):
            texts.append((p, p.read_text(encoding="utf-8", errors="replace")))
    hits: list[Path] = []
    for path, text in texts:
        lower = text.lower()
        if any(tok in lower for tok in _SECRET_SCAN_TOKENS):
            hits.append(path)
            continue
        if any(rx.search(text) for rx in _SECRET_SCAN_EXTRA_PATTERNS):
            hits.append(path)
    if hits:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"Secret scanning tool signal detected in {len(hits)} workflow file(s). "
                "(keyword signal in workflow YAML — execution and blocking behavior not validated)"
            ),
            remediation="Keep secret scanning enabled on default branches and pull requests.",
            evidence_sources=[str(p.resolve()) for p in hits],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    if not paths:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "In-repo secret scanning step not implemented "
                "(no GitHub Actions workflows found in .github/workflows/)."
            ),
            remediation=(
                "Add a secret scanning step to CI (for example gitleaks, trufflehog, detect-secrets, or secretlint)."
            ),
            evidence_sources=[],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No secret scanning tool keyword found in workflow YAML (gitleaks, trufflehog, detect-secrets, etc.).",
        remediation=(
            "Add a secret scanning step to your CI workflow. Example: uses: gitleaks/gitleaks-action@v2 "
            "(pin to a commit SHA in production)."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def eval_sec_gitignore_051(ctx: EvalContext) -> EvalOutcome:
    """SEC-GITIGNORE-051: root .gitignore with basic secret-related patterns."""
    gi = ctx.repo_root / ".gitignore"
    if not gi.is_file():
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="No `.gitignore` file at repository root.",
            remediation=(
                "Add `.gitignore` with patterns such as `.env`, `*.pem`, `*.key`, `secrets.*`, `credentials.json`."
            ),
            evidence_sources=[],
            confidence="high",
        )
    try:
        raw = gi.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raw = ""
    low = raw.lower()
    matched = [frag for frag in _GITIGNORE_SECRET_FRAGMENTS if frag.lower() in low]
    if matched:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"`.gitignore` includes basic secret-protection patterns ({', '.join(matched)}).",
            remediation="Review periodically so new sensitive artifact types remain ignored.",
            evidence_sources=[str(gi.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="`.gitignore` exists but no common secret-protection patterns were detected.",
        remediation="Expand `.gitignore` with `.env`, `*.pem`, `*.key`, `secrets.*`, or `credentials.json` patterns.",
        evidence_sources=[str(gi.resolve())],
        confidence="low",
    )


def eval_sec_pinlock_052(ctx: EvalContext) -> EvalOutcome:
    """SEC-PINLOCK-052: dependency lockfile or pinned requirements when a stack is detected."""
    repo = ctx.repo_root
    stacks: list[str] = []
    if (repo / "package.json").is_file():
        stacks.append("node")
    if (repo / "requirements.txt").is_file() or (repo / "pyproject.toml").is_file():
        stacks.append("python")
    if (repo / "go.mod").is_file():
        stacks.append("go")
    if not stacks:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Node.js, Python, or Go manifest detected at repository root.",
            remediation="Not applicable until a supported dependency manifest is present.",
            evidence_sources=[],
            confidence="high",
        )

    missing: list[str] = []
    node_lock_names = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")
    if "node" in stacks and not any((repo / name).is_file() for name in node_lock_names):
        missing.append("Node.js lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml)")
    if "python" in stacks and not _python_lock_or_pins(repo):
        missing.append("Python lockfile or pinned requirements (== in requirements.txt, poetry.lock, etc.)")
    if "go" in stacks and not (repo / "go.sum").is_file():
        missing.append("go.sum")

    if not missing:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Dependency lockfile or pinned requirements detected for the observed stack(s).",
            remediation="Keep lockfiles committed and refresh them when dependencies change.",
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="Missing lockfile or pins: " + "; ".join(missing) + ".",
        remediation=(
            "For Python use pinned versions (==) or pip-compile; for Node commit package-lock.json or yarn.lock; "
            "for Go commit go.sum."
        ),
        evidence_sources=[],
        confidence="medium",
    )


@dataclass
class _WfCallShaScan:
    """Accumulator for reusable-workflow SHA-pin scanning across workflow files."""

    parse_warns: list[str] = field(default_factory=list)
    call_paths: list[Path] = field(default_factory=list)
    bad_paths: list[Path] = field(default_factory=list)
    bad_evidence_sources: list[str] = field(default_factory=list)


def _scan_wfcallsha_regex(raw: str, path: Path, acc: _WfCallShaScan) -> None:
    """Regex fallback: find reusable-workflow ``uses:`` refs and flag non-SHA pins."""

    for m in _REUSABLE_WORKFLOW_USES_LINE.finditer(raw):
        ref = m.group(1).strip()
        if not ref or ref.startswith("${{") or ".github/workflows" not in ref.lower():
            continue
        if path not in acc.call_paths:
            acc.call_paths.append(path)
        if not _reusable_workflow_ref_has_full_sha(ref):
            if path not in acc.bad_paths:
                acc.bad_paths.append(path)
            acc.bad_evidence_sources.append(f"{path.resolve()} (regex-fallback: `{ref}`)")


def _scan_wfcallsha_structured(doc: dict, path: Path, acc: _WfCallShaScan) -> None:
    """Structured pass: flag reusable-workflow ``uses:`` refs without a full SHA pin."""

    reusable = [
        (j, s, u) for (j, s, u) in _iter_structured_workflow_uses_with_location(doc) if ".github/workflows" in u.lower()
    ]
    if not reusable:
        return
    if path not in acc.call_paths:
        acc.call_paths.append(path)
    for job_name, step_label, ref in reusable:
        if not _reusable_workflow_ref_has_full_sha(ref):
            if path not in acc.bad_paths:
                acc.bad_paths.append(path)
            acc.bad_evidence_sources.append(f"{path.resolve()} :: jobs.{job_name}.{step_label} uses=`{ref}`")


def _scan_wfcallsha_path(path: Path, acc: _WfCallShaScan) -> None:
    """Scan one workflow file for reusable-workflow SHA pins (structured, regex fallback on parse failure)."""

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        doc = load_yaml_file(path)
    except Exception:  # noqa: BLE001 - fall back to regex scan on any parse error
        doc = None
    if not isinstance(doc, dict):
        acc.parse_warns.append(f"{path.name}: YAML parse failed; reusable workflow SHA pins not verified structurally.")
        _scan_wfcallsha_regex(raw, path, acc)
        return
    _scan_wfcallsha_structured(doc, path, acc)


def eval_ci_wfcallsha_055(ctx: EvalContext) -> EvalOutcome:
    """CI-WFCALLSHA-055: reusable workflow calls use full 40-character commit SHAs."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=_NO_WORKFLOWS_REASON,
            remediation="Pin reusable workflows with immutable commit SHAs when using workflow_call.",
            evidence_sources=[],
            confidence="high",
        )

    acc = _WfCallShaScan()
    for path in ctx.workflows.workflow_paths:
        _scan_wfcallsha_path(path, acc)
    parse_warns = acc.parse_warns
    call_paths = acc.call_paths
    bad_paths = acc.bad_paths
    bad_evidence_sources = acc.bad_evidence_sources

    if not call_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No reusable workflow references under .github/workflows were detected.",
            remediation="Not applicable until you call reusable workflows from another workflow.",
            evidence_sources=[],
            confidence="high",
        )
    if bad_paths:
        names = ", ".join(sorted({p.name for p in bad_paths}))
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Reusable workflow call(s) without a full 40-character SHA pin detected: {names}. "
                "Use org/repo/.github/workflows/file.yml@<40-hex-sha>."
            ),
            remediation="Pin reusable workflow entrypoints to immutable commit SHAs, not tags or branches.",
            evidence_sources=bad_evidence_sources or [str(p.resolve()) for p in bad_paths],
            confidence="medium",
            operational_warnings=tuple(parse_warns) if parse_warns else (),
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="Reusable workflow calls under .github/workflows use full commit SHA pins (parsed from workflow YAML).",
        remediation="Keep pins immutable when updating reusable workflow targets.",
        evidence_sources=[str(p.resolve()) for p in call_paths],
        confidence="medium",
        operational_warnings=tuple(parse_warns) if parse_warns else (),
    )


def eval_sast_semgrep_064(ctx: EvalContext) -> EvalOutcome:
    """SAST-SEMGREP-064: SAST evidence (Semgrep) is present and current.

    Reads ``.oss-policy-kit/evidence/sast-semgrep.json`` (produced by
    ``oss-policy-kit scan-sast``) and reports:

    - ``manual-review-required`` when the evidence file is missing.
    - ``manual-review-required`` when Semgrep was not installed at scan
      time (status ``not_available``); the gap is recorded honestly.
    - ``fail`` when there are any HIGH or CRITICAL severity findings.
    - ``pass`` when the run completed without HIGH/CRITICAL findings.
    """

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / _SAST_SEMGREP_EVIDENCE_FILENAME
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("No Semgrep evidence file found. SAST findings cannot be verified from a clone alone."),
            remediation=(
                "Run `oss-policy-kit scan-sast --target .` (requires Semgrep installed) "
                "to populate .oss-policy-kit/evidence/sast-semgrep.json."
            ),
            evidence_sources=[],
            confidence="medium",
        )

    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Could not parse Semgrep evidence file: {exc}",
            remediation="Re-run `oss-policy-kit scan-sast` to regenerate the evidence file.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    schema = str(data.get("schema_version", ""))
    if not schema.startswith(_SAST_SEMGREP_SCHEMA_PREFIX):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"Unexpected schema_version in {evidence.name}: {schema!r}. "
                f"Expected prefix {_SAST_SEMGREP_SCHEMA_PREFIX!r}."
            ),
            remediation="Regenerate via `oss-policy-kit scan-sast` to align with the current contract.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    status = str(data.get("status", "unknown")).lower()
    if status == "not_available":
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "Semgrep was not installed when scan-sast ran; the evidence is a presence stub, not a real SAST result."
            ),
            remediation=(
                "Install Semgrep (`pip install semgrep`) on the runner that executes "
                "`oss-policy-kit scan-sast` and re-run it to produce real findings."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if status in {"timeout", "error"}:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Semgrep evidence reports status={status!r}; SAST results are inconclusive.",
            remediation="Investigate the Semgrep run (see diagnostics.raw_stderr_excerpt) and re-run scan-sast.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    severity_counts = data.get("findings_by_severity", {}) or {}
    if not isinstance(severity_counts, dict):
        severity_counts = {}
    high = int(severity_counts.get("ERROR", 0) or 0) + int(severity_counts.get("HIGH", 0) or 0)
    critical = int(severity_counts.get("CRITICAL", 0) or 0)
    if critical or high:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Semgrep reported {critical} CRITICAL and {high} HIGH/ERROR severity finding(s). "
                "SAST gate considers HIGH+ findings blocking by default."
            ),
            remediation=(
                "Review evaluation-report.md and fix HIGH/CRITICAL findings, or document an "
                "explicit waiver in waivers.yaml with owner, reason, and expires_on."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )

    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Semgrep completed cleanly: {int(data.get('findings_total', 0) or 0)} total finding(s), "
            "no HIGH or CRITICAL severity entries."
        ),
        remediation="Keep Semgrep up to date and re-scan at least once per release.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_sast_zizmor_066(ctx: EvalContext) -> EvalOutcome:
    """SAST-ZIZMOR-066: zizmor SARIF findings on GitHub Actions workflows.

    The gate decision is driven by the standard SARIF ``level`` (error/warning/
    note/none) shared with the other Fase 4 adapters. When zizmor surfaces its
    own severity vocabulary via ``result.properties.security_severity_level``
    (Critical/High/Medium/Low/Informational), those counts are appended to the
    reason for operator visibility but do not change the pass/fail outcome.
    """
    outcome = _eval_sarif_adapter(
        ctx,
        tool_name="zizmor",
        evidence_relpath=".oss-policy-kit/evidence/sast/zizmor.sarif.json",
        scan_command_hint="Run `zizmor --format sarif .github/workflows/ > zizmor.sarif.json`",
        fail_on_error=True,
    )
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "sast" / "zizmor.sarif.json"
    if evidence.is_file() and outcome.status in (ControlStatus.PASS, ControlStatus.FAIL):
        sev_counts, _ = _parse_zizmor_severity_properties(evidence)
        if sev_counts is not None and sum(sev_counts.values()) > 0:
            non_zero = ", ".join(f"{k}={v}" for k, v in sev_counts.items() if v > 0)
            outcome.reason = f"{outcome.reason} zizmor severity properties: {non_zero}."
    return outcome


def eval_sast_poutine_067(ctx: EvalContext) -> EvalOutcome:
    """SAST-POUTINE-067: poutine SARIF findings on GitHub Actions / GitLab CI pipelines."""
    return _eval_sarif_adapter(
        ctx,
        tool_name="poutine",
        evidence_relpath=".oss-policy-kit/evidence/sast/poutine.sarif.json",
        scan_command_hint="Run `poutine analyze-local . --format sarif > poutine.sarif.json`",
        fail_on_error=True,
    )


def eval_sast_osv_068(ctx: EvalContext) -> EvalOutcome:
    """SAST-OSV-068: OSV-Scanner v2 SARIF findings (reachability-aware SCA)."""
    return _eval_sarif_adapter(
        ctx,
        tool_name="osv-scanner",
        evidence_relpath=".oss-policy-kit/evidence/sast/osv-scanner.sarif.json",
        scan_command_hint=(
            "Run `osv-scanner --format sarif --recursive . > osv-scanner.sarif.json` (v2+ for reachability)"
        ),
        fail_on_error=True,
    )


def eval_sast_gitleaks_069(ctx: EvalContext) -> EvalOutcome:
    """SAST-GITLEAKS-069: Gitleaks SARIF findings (secret leak detection)."""
    return _eval_sarif_adapter(
        ctx,
        tool_name="gitleaks",
        evidence_relpath=".oss-policy-kit/evidence/sast/gitleaks.sarif.json",
        # Secrets are zero-tolerance — even a single warning-level finding
        # should block until reviewed/waived.
        scan_command_hint="Run `gitleaks detect --report-format sarif --report-path gitleaks.sarif.json`",
        fail_on_error=True,
        fail_on_warning=True,
    )
