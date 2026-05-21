"""governance control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import *  # noqa: F403


def eval_gov_sec_001(ctx: EvalContext) -> EvalOutcome:
    text = _read_security(ctx.repo_root)
    if text is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="SECURITY.md present.",
            remediation="Keep SECURITY.md current and linked from the repository README.",
            evidence_sources=[str((ctx.repo_root / "SECURITY.md").resolve())],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="SECURITY.md not found at repository root.",
        remediation="Add SECURITY.md describing supported versions and how to report vulnerabilities.",
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_con_002(ctx: EvalContext) -> EvalOutcome:
    for name in ("CONTRIBUTING.md", "CONTRIBUTING", "docs/CONTRIBUTING.md"):
        p = ctx.repo_root / name
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Contributing guide present.",
                remediation="Keep contribution expectations and security expectations aligned.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="CONTRIBUTING guide not found.",
        remediation="Add CONTRIBUTING.md with workflow, review expectations, and security notes.",
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_cown_003(ctx: EvalContext) -> EvalOutcome:
    if _has_codeowners(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="CODEOWNERS file present.",
            remediation="Review CODEOWNERS coverage for critical paths.",
            evidence_sources=[],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="CODEOWNERS not found at .github/CODEOWNERS or repository root.",
        remediation="Add CODEOWNERS to route reviews for sensitive areas.",
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_lic_004(ctx: EvalContext) -> EvalOutcome:
    if _has_license(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="LICENSE (or COPYING) file detected.",
            remediation="Ensure LICENSE matches declared SPDX and distribution intent.",
            evidence_sources=[],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No LICENSE file detected at repository root.",
        remediation="Add a LICENSE file consistent with your SPDX identifier.",
        evidence_sources=[],
        confidence="high",
    )


def eval_rel_change_012(ctx: EvalContext) -> EvalOutcome:
    if _has_changelog(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Changelog or release notes file detected.",
            remediation="Keep changelog entries aligned with semver and releases.",
            evidence_sources=[],
            confidence="high",
        )
    if _exists_ci_readme(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No changelog file; workflows README present - verify release notes process.",
            remediation="Add CHANGELOG.md or document release notes process in docs/.",
            evidence_sources=[str((ctx.repo_root / ".github/workflows/README.md").resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No CHANGELOG-style file detected.",
        remediation="Add CHANGELOG.md and reference it from releases.",
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_disc_013(ctx: EvalContext) -> EvalOutcome:
    text = _read_security(ctx.repo_root)
    if text is None:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Disclosure reporting mechanism not implemented (SECURITY.md missing at repository root).",
            remediation="Add SECURITY.md with a clear reporting channel (email or form).",
            evidence_sources=[],
            confidence="high",
        )
    lower = text.lower()
    if _has_placeholder_security_contact(text):
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="SECURITY.md contains placeholder disclosure guidance instead of a real private reporting channel.",
            remediation=(
                "Replace placeholder text with a monitored private reporting channel "
                "such as security email or GitHub private vulnerability reporting."
            ),
            evidence_sources=[],
            confidence="high",
        )
    if _gov_disc_013_private_reporting_signals(lower):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "SECURITY.md includes private disclosure/reporting cues "
                "(heuristic text signal; channel monitoring is not validated from clone-only evidence)."
            ),
            remediation="Ensure the reporting channel is monitored and SLA-aligned.",
            evidence_sources=[],
            confidence="low",
            operational_warnings=(_SUPPLEMENTAL_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="SECURITY.md present but no explicit private reporting channel detected by heuristics.",
        remediation="Document how researchers should report issues privately before public disclosure.",
        evidence_sources=[],
        confidence="low",
    )


def eval_gov_waiv_014(ctx: EvalContext) -> EvalOutcome:
    candidates = [
        ctx.repo_root / "waivers.yaml",
        ctx.repo_root / "waivers.yml",
        ctx.repo_root / "waivers" / "waivers.yaml",
        ctx.repo_root / ".oss-policy-kit" / "waivers.yaml",
    ]
    for p in candidates:
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Versioned waiver file detected in repository.",
                remediation="Keep waivers justified, owned, time-bounded, and reviewed.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "No versioned waiver policy file found in repository. If waivers are not applicable, create a waivers/ "
            "directory with a documented policy statement or use an empty waivers file."
        ),
        remediation="Create waivers/policy.yaml or waivers/README.md documenting the waiver governance approach.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_plat_brprot_015(ctx: EvalContext) -> EvalOutcome:
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    if evidence.is_file():
        return _parse_branch_protection_evidence(evidence)
    return EvalOutcome(
        status=ControlStatus.NOT_EVALUATED,
        reason=(
            "Branch protection posture cannot be determined: no evidence file found at "
            "`.oss-policy-kit/evidence/branch-protection.json`. "
            "Collect evidence using the GitHub platform collector or create the file manually "
            "following the schema at `src/oss_policy_kit/data/schema/evidence-branch-protection.schema.json`."
        ),
        remediation=(
            "Run `oss-policy-kit collect-evidence --platform github` to generate the evidence file, "
            "or manually create `.oss-policy-kit/evidence/branch-protection.json` "
            "and attest branch protection settings."
        ),
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_evidfresh_054(ctx: EvalContext) -> EvalOutcome:
    """GOV-EVIDFRESH-054: evidence JSON under .oss-policy-kit/evidence is not older than policy."""

    evid_root = ctx.repo_root / ".oss-policy-kit" / "evidence"
    if not evid_root.is_dir():
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No .oss-policy-kit/evidence directory present.",
            remediation="Run collect-evidence for your platform(s) or add validated evidence JSON when required.",
            evidence_sources=[],
            confidence="high",
        )
    json_files = sorted(evid_root.rglob("*.json"))
    # Skip raw SARIF output files (scanner output, not kit-attestation evidence).
    # SARIF files have their own freshness contract via invocations[].startTimeUtc;
    # GOV-EVIDFRESH-054 covers attested_at / collected_at / generated_at on the
    # kit's structured evidence files only. Convention: scanner SARIF lives under
    # .oss-policy-kit/evidence/sast/<tool>.sarif.json — see SAST-OSV-068, SAST-ZIZMOR-066,
    # SAST-POUTINE-067, SAST-GITLEAKS-069 (v5.9.0).
    sast_dir = evid_root / "sast"
    json_files = [p for p in json_files if not (sast_dir in p.parents or p.name.endswith(".sarif.json"))]
    if not json_files:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="Evidence directory exists but contains no JSON files.",
            remediation="Populate evidence JSON via collect-evidence or controlled exports.",
            evidence_sources=[str(evid_root.resolve())],
            confidence="high",
        )

    today = datetime.now(UTC).date()
    max_age = int(ctx.evidence_max_age_days) if ctx.evidence_max_age_days else _EVIDENCE_MAX_AGE_DAYS
    if max_age <= 0:
        max_age = _EVIDENCE_MAX_AGE_DAYS
    stale: list[str] = []
    undated: list[str] = []
    expiry_warns: list[str] = []
    for path in json_files:
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=f"Evidence file {path.name} is unreadable or invalid JSON: {exc}.",
                remediation="Repair or regenerate the evidence JSON file.",
                evidence_sources=[str(path.resolve())],
                confidence="low",
            )
        if not isinstance(data, dict):
            undated.append(path.name)
            continue
        stamp: str | None = None
        coll = data.get("collection")
        if isinstance(coll, dict):
            v0 = coll.get("collected_at")
            if isinstance(v0, str) and v0.strip():
                stamp = v0.strip()
        if stamp is None:
            for key in ("collected_at", "attested_at", "generated_at"):
                v = data.get(key)
                if isinstance(v, str) and v.strip():
                    stamp = v.strip()
                    break
        parsed = _parse_evidence_date(stamp) if stamp else None
        if parsed is None:
            undated.append(path.name)
            continue
        age_days = (today - parsed).days
        if age_days > max_age:
            stale.append(f"{path.name} ({parsed.isoformat()})")
        elif age_days > max_age - _EVIDENCE_EXPIRY_WARN_DAYS:
            days_left = max_age - age_days
            expiry_warns.append(
                f"Evidence file '{path.name}' is {age_days} days old and will expire in "
                f"{days_left} day(s). Refresh before it becomes stale."
            )

    if stale:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Stale evidence JSON (older than "
            f"{max_age} days by attested_at/collected_at): "
            + "; ".join(stale[:6])
            + ("; …" if len(stale) > 6 else "")
            + ".",
            remediation="Re-run collect-evidence or refresh manual exports so dates stay current.",
            evidence_sources=[str(evid_root.resolve())],
            confidence="medium",
        )
    if undated:
        preview = ", ".join(sorted(undated)[:5])
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "Some evidence JSON files lack a usable collected_at/attested_at date: "
                f"{preview}{'…' if len(undated) > 5 else ''}."
            ),
            remediation="Ensure each evidence file includes attested_at or collected_at (ISO-8601 date or datetime).",
            evidence_sources=[str(evid_root.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"All {len(json_files)} evidence JSON file(s) carry recent dates (≤ {max_age} days).",
        remediation="Refresh evidence after material platform or pipeline changes.",
        evidence_sources=[str(evid_root.resolve())],
        confidence="medium",
        operational_warnings=tuple(expiry_warns),
    )


def eval_dep_update_001(ctx: EvalContext) -> EvalOutcome:
    """DEP-UPDATE-001: Automated dependency update tool (Dependabot or Renovate) configured."""
    repo = ctx.repo_root
    for p in (repo / ".github" / "dependabot.yml", repo / ".github" / "dependabot.yaml"):
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Dependabot configuration file detected.",
                remediation="Keep Dependabot schedules aligned with project risk tolerance.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    renovate_candidates = [
        repo / "renovate.json",
        repo / "renovate.json5",
        repo / ".renovaterc",
        repo / ".renovaterc.json",
        repo / ".github" / "renovate.json",
    ]
    for p in renovate_candidates:
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Renovate configuration file detected.",
                remediation="Keep Renovate schedules and automerge rules aligned with security policy.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No automated dependency update tool detected (Dependabot or Renovate).",
        remediation=("Add .github/dependabot.yml for Dependabot or renovate.json at the repository root for Renovate."),
        evidence_sources=[],
        confidence="high",
    )


def eval_oss_scorecard_001(ctx: EvalContext) -> EvalOutcome:
    """OSS-SCORECARD-001: OpenSSF Scorecard score meets minimum threshold (5.0/10).

    Prefers the official aggregate ``score`` emitted by the Scorecard CLI. If
    only per-check scores are present, falls back to their arithmetic mean
    with reduced confidence (Scorecard uses a weighted aggregate internally,
    so the mean is only a proxy).
    """

    if ctx.scorecard is None:
        return EvalOutcome(
            status=ControlStatus.NOT_EVALUATED,
            reason="No OpenSSF Scorecard JSON provided; cannot evaluate scorecard score.",
            remediation=(
                "Generate a Scorecard report via 'scorecard --repo=<org>/<repo> --format=json' "
                "and pass it with --scorecard-json."
            ),
            evidence_sources=[],
            confidence="low",
        )
    src = [ctx.scorecard.raw_path or "scorecard"]
    official = ctx.scorecard.aggregate_score
    if official is not None:
        aggregate = round(float(official), 1)
        if aggregate >= _SCORECARD_MIN_SCORE:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"OpenSSF Scorecard aggregate score {aggregate}/10 (official `score` field) "
                    f"meets minimum threshold ({_SCORECARD_MIN_SCORE})."
                ),
                remediation="Continue improving scorecard checks to raise the score toward 8+.",
                evidence_sources=src,
                confidence="high",
            )
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"OpenSSF Scorecard aggregate score {aggregate}/10 (official `score` field) "
                f"is below minimum threshold ({_SCORECARD_MIN_SCORE})."
            ),
            remediation=(
                "Review the failing Scorecard checks. Common high-impact fixes: pin actions to SHAs "
                "(Pinned-Dependencies), add SECURITY.md (Security-Policy), enable branch "
                "protection (Branch-Protection)."
            ),
            evidence_sources=src,
            confidence="high",
        )
    scm = checks_as_map(ctx.scorecard)
    scores = [float(c.score) for c in scm.values() if c.score is not None and float(c.score) >= 0]
    if not scores:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("Scorecard JSON present but no numeric aggregate `score` nor per-check scores could be extracted."),
            remediation=(
                "Ensure the file follows the OpenSSF Scorecard v2 JSON format (root `score` plus per-check entries)."
            ),
            evidence_sources=src,
            confidence="low",
        )
    proxy = round(sum(scores) / len(scores), 1)
    proxy_warning = (
        "Scorecard JSON lacks the official aggregate `score`; evaluator used an arithmetic mean "
        "of per-check scores as a proxy (Scorecard itself uses a weighted aggregate)."
    )
    if proxy >= _SCORECARD_MIN_SCORE:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"OpenSSF Scorecard proxy score {proxy}/10 (mean of per-check scores) "
                f"meets minimum threshold ({_SCORECARD_MIN_SCORE})."
            ),
            remediation=(
                "Regenerate Scorecard JSON with a recent CLI so the root `score` aggregate is available, "
                "then continue raising check scores toward 8+."
            ),
            evidence_sources=src,
            confidence="low",
            operational_warnings=(proxy_warning,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=(
            f"OpenSSF Scorecard proxy score {proxy}/10 (mean of per-check scores) "
            f"is below minimum threshold ({_SCORECARD_MIN_SCORE})."
        ),
        remediation=(
            "Review the failing Scorecard checks. Common high-impact fixes: pin actions to SHAs "
            "(Pinned-Dependencies), add SECURITY.md (Security-Policy), enable branch "
            "protection (Branch-Protection)."
        ),
        evidence_sources=src,
        confidence="low",
        operational_warnings=(proxy_warning,),
    )


def eval_org_mfa_001(ctx: EvalContext) -> EvalOutcome:
    """ORG-MFA-001: Organization MFA enforcement posture evidenced."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "org-mfa-posture.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Organization MFA enforcement cannot be observed from a local repository clone.",
            remediation=(
                "Verify MFA enforcement in your organization security settings and add "
                ".oss-policy-kit/evidence/org-mfa-posture.json per the evidence schema."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_org_mfa_schema,
        evidence_name="Organization MFA posture",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-org-mfa-posture.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture_raw = data.get("posture")
    posture: dict[str, Any] = dict(posture_raw) if isinstance(posture_raw, dict) else {}
    for k in ("mfa_required_for_all_members", "mfa_required_for_admins", "sso_enforced"):
        if k in data and k not in posture:
            posture[k] = data[k]

    all_m = posture.get("mfa_required_for_all_members")
    adm_m = posture.get("mfa_required_for_admins")
    if all_m is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Organization MFA evidence does not include mfa_required_for_all_members.",
            remediation="Populate mfa_required_for_all_members per the org-mfa-posture schema.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if all_m is False and adm_m is True:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "MFA is required for admins only, but not enforced for all organization members. "
                "This leaves non-admin members as a supply-chain risk vector."
            ),
            remediation="Enable MFA for every organization member, not only administrators.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if all_m is False and adm_m is not True:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="MFA not enforced for organization members or admins. This is a critical identity control gap.",
            remediation="Enable MFA enforcement for all members and administrators in your organization settings.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if adm_m is not True:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="MFA not enforced for organization administrators despite member-level MFA claims.",
            remediation="Require MFA for administrative accounts in your organization security policy.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )

    enforcement_scope_raw = data.get("enforcement_scope", None)
    enforcement_scope = enforcement_scope_raw.strip().lower() if isinstance(enforcement_scope_raw, str) else None
    if enforcement_scope in ("admins_only", "selected_teams", "partial"):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"MFA enforcement is scoped to '{enforcement_scope}' only. "
                "Full enforcement requires MFA for all organization members, "
                "not just administrators or selected teams."
            ),
            remediation=(
                "Configure MFA enforcement for all members in the organization settings, "
                "then set `enforcement_scope: all_members` in the evidence file."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )

    sso_warn: tuple[str, ...] = ()
    if posture.get("sso_enforced") is not True:
        sso_warn = ("SSO enforcement not confirmed in evidence; consider adding sso_enforced: true if applicable.",)
    if enforcement_scope is None:
        sso_warn = sso_warn + (
            "MFA enforcement scope was not specified in the evidence file. "
            "Consider adding 'enforcement_scope' to clarify who is covered.",
        )

    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Organization MFA enforcement confirmed via live API collection evidence.",
            remediation="Refresh evidence after changes to organization membership or security settings.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
            operational_warnings=sso_warn,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Organization MFA enforcement self-attested as enabled for all members and admins.",
        remediation="Prefer collect-evidence to confirm MFA posture from the platform API.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        operational_warnings=sso_warn,
    )


def eval_build_sbom_qual_003(ctx: EvalContext) -> EvalOutcome:
    """BUILD-SBOM-QUAL-003: SBOM format validity — SPDX or CycloneDX document detectable in repo or evidence."""
    # Check evidence files for documented SBOM format first.
    for evid_name in ("azure-sbom-artifact.json", "aws-sbom-artifact.json"):
        evid = ctx.repo_root / ".oss-policy-kit" / "evidence" / evid_name
        if evid.is_file():
            with contextlib.suppress(OSError, json.JSONDecodeError):
                data = json.loads(evid.read_text(encoding="utf-8"))
                sbom_block = data.get("sbom") if isinstance(data, dict) else None
                fmt = str(sbom_block.get("format", "")).strip() if isinstance(sbom_block, dict) else ""
                if fmt and ("spdx" in fmt.lower() or "cyclonedx" in fmt.lower()):
                    return EvalOutcome(
                        status=ControlStatus.PASS,
                        reason=f"Evidence documents SBOM format '{fmt}' (SPDX/CycloneDX).",
                        remediation="Keep SBOM format and digest records current with each release.",
                        evidence_sources=[str(evid.resolve())],
                        confidence="medium",
                    )
    # Scan repo for SBOM files.
    sbom_files = _find_sbom_files(ctx.repo_root)
    if sbom_files:
        valid: list[str] = []
        invalid: list[str] = []
        bsi_notes: list[str] = []
        for p in sbom_files:
            with contextlib.suppress(OSError):
                content = p.read_text(encoding="utf-8", errors="replace")
                fmt_detail, version = _detect_sbom_format_and_version(content)
                if fmt_detail:
                    label = f"{p.name} ({fmt_detail}{f' {version}' if version else ''})"
                    valid.append(label)
                    bsi = _validate_bsi_tr_03183_v2_1(content, fmt_detail, version)
                    if bsi is not None:
                        missing = [
                            k.removesuffix("_present").removesuffix("_separated") for k, v in bsi.items() if not v
                        ]
                        if missing:
                            bsi_notes.append(f"{p.name} BSI TR-03183-2 v2.1.0: missing {', '.join(missing)}")
                        else:
                            bsi_notes.append(f"{p.name} BSI TR-03183-2 v2.1.0: all required fields present")
                else:
                    invalid.append(p.name)
        if valid:
            reason = f"Valid SBOM format detected: {', '.join(valid[:3])}."
            if bsi_notes:
                reason = f"{reason} {' | '.join(bsi_notes[:3])}."
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=reason,
                remediation="Keep SBOM files current with each release; sign and attest them for supply chain trust.",
                evidence_sources=[str(p.resolve()) for p in sbom_files],
                confidence="medium",
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"SBOM-like file(s) found but SPDX/CycloneDX format not confirmed: {', '.join(invalid[:3])}.",
            remediation=(
                "Use syft, CycloneDX CLI, or trivy to generate a valid SBOM and verify "
                "it contains SPDXVersion or bomFormat/CycloneDX markers."
            ),
            evidence_sources=[str(p.resolve()) for p in sbom_files],
            confidence="low",
        )
    # Check for CI signals that might produce an SBOM.
    all_ci = (
        list(ctx.workflows.workflow_paths) + list(ctx.azure_pipelines.pipeline_paths) + list(ctx.aws_ci.buildspec_paths)
    )
    for p in all_ci:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if "cyclonedx" in text or "spdx" in text or "syft" in text:
                return EvalOutcome(
                    status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                    reason=(
                        "SBOM keyword signal detected in CI, but no verifiable SBOM file or evidence found. "
                        "Add a CycloneDX or SPDX SBOM to the repository or add an evidence file."
                    ),
                    remediation=(
                        "Commit or publish the generated SBOM alongside release artifacts. "
                        "Prefer SPDX 2.3+ or CycloneDX 1.5+ for broad tool compatibility."
                    ),
                    evidence_sources=[str(p.resolve())],
                    confidence="low",
                )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No SBOM file or format evidence found in the repository.",
        remediation=(
            "Generate an SBOM in SPDX or CycloneDX format during release builds "
            "and include it as a verifiable release artifact."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def eval_audit_stream_060(ctx: EvalContext) -> EvalOutcome:
    """AUDIT-STREAM-060: Audit log streaming to centralized SIEM/object store."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "audit-log-streaming.json"
    if not evidence.is_file():
        signal = _audit_stream_signal_match(ctx.repo_root)
        if signal is not None:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"Audit log streaming intent detected via clone signal ({signal.name}). "
                    "Heuristic only — promote to evidence-backed by adding "
                    ".oss-policy-kit/evidence/audit-log-streaming.json with destinations."
                ),
                remediation=(
                    "Document streaming destinations in .oss-policy-kit/evidence/audit-log-streaming.json "
                    "per evidence-audit-log-streaming.schema.json so trust projects to verified."
                ),
                evidence_sources=[str(signal.resolve())],
                confidence="low",
                operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "Centralized audit log streaming cannot be observed from a local clone. "
                "Add .oss-policy-kit/evidence/audit-log-streaming.json after configuring "
                "GitHub/Azure/AWS audit log streaming to a SIEM or object store (closes OWASP CICD-SEC-10)."
            ),
            remediation=(
                "Configure org-level audit log streaming (GitHub Enterprise audit-log streaming, "
                "Azure DevOps auditstreams, AWS CloudTrail) and record the destinations in evidence."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_audit_log_streaming_schema,
        evidence_name="Audit log streaming",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-audit-log-streaming.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    streaming_enabled = bool(data.get("streaming_enabled"))
    destinations = data.get("destinations") or []
    if not streaming_enabled or not destinations:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Audit log streaming evidence reports streaming_enabled=false or empty destinations[]. "
                "Centralized log forwarding is the OWASP CICD-SEC-10 mitigation."
            ),
            remediation="Enable audit log streaming for the platform org and register at least one destination.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    method = EvidenceCollectionMethod.STATIC
    coll = data.get("collection")
    if isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "live":
        method = EvidenceCollectionMethod.LIVE
    elif isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "manual":
        method = EvidenceCollectionMethod.MANUAL
    dest_kinds = ", ".join(sorted({str(d.get("kind", "?")) for d in destinations if isinstance(d, dict)}))
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Audit log streaming evidence is valid: {len(destinations)} destination(s) configured ({dest_kinds})."
        ),
        remediation="Re-attest evidence within freshness window when streaming destinations change.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=method,
    )


def eval_gov_disc_065(ctx: EvalContext) -> EvalOutcome:
    """GOV-DISC-065: Disclosure channel SLA documented (CRA reporting readiness).

    Closes a gap left by ``GOV-DISC-013`` (signal-grade existence-check on responsible
    disclosure mention) for adopters preparing for the EU CRA 2026-09-11 24-hour
    reporting deadline. The CRA report is *outbound* (manufacturer to ENISA); this
    control checks the *inbound* SLA (researcher to manufacturer), which is a
    necessary precondition for the outbound clock to be meetable.
    """

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "disclosure-policy.json"
    if not evidence.is_file():
        signal = _disclosure_sla_signal_match(ctx.repo_root)
        if signal is not None:
            path, kw = signal
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"Disclosure response-SLA intent detected via clone signal "
                    f"({path.name}, keyword '{kw}'). Heuristic only — promote to "
                    "evidence-backed by adding "
                    ".oss-policy-kit/evidence/disclosure-policy.json with explicit "
                    "acknowledgement_sla_hours, triage_sla_hours, and public_disclosure_policy."
                ),
                remediation=(
                    "Document the disclosure SLA in "
                    ".oss-policy-kit/evidence/disclosure-policy.json per "
                    "evidence-disclosure-policy.schema.json so trust projects to verified."
                ),
                evidence_sources=[str(path.resolve())],
                confidence="low",
                operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No disclosure SLA found in SECURITY.md and no evidence file present. "
                "EU CRA 2026-09-11 24-hour reporting depends on having a documented "
                "inbound disclosure channel with a stated acknowledgement window."
            ),
            remediation=(
                "Add an acknowledgement SLA to SECURITY.md (e.g. 'we will acknowledge "
                "within 72 hours') or attach "
                ".oss-policy-kit/evidence/disclosure-policy.json per "
                "evidence-disclosure-policy.schema.json."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_disclosure_policy_schema,
        evidence_name="Disclosure policy",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-disclosure-policy.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    contact = data.get("contact") or {}
    ack_sla = data.get("acknowledgement_sla_hours")
    triage_sla = data.get("triage_sla_hours")
    pdp = data.get("public_disclosure_policy") or {}
    missing: list[str] = []
    if not isinstance(contact.get("method"), str) or not isinstance(contact.get("value"), str):
        missing.append("contact.method / contact.value")
    if not isinstance(ack_sla, int) or ack_sla < 1:
        missing.append("acknowledgement_sla_hours")
    if not isinstance(triage_sla, int) or triage_sla < 1:
        missing.append("triage_sla_hours")
    if not isinstance(pdp.get("default_window_days"), int) or "negotiable" not in pdp:
        missing.append("public_disclosure_policy.default_window_days / negotiable")
    if missing:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Disclosure policy evidence is missing required SLA fields: "
                + ", ".join(missing)
                + ". The kit does not judge whether the SLA is fast enough; it requires "
                "that an SLA is documented at all."
            ),
            remediation=(
                "Fill the missing fields in .oss-policy-kit/evidence/disclosure-policy.json "
                "per evidence-disclosure-policy.schema.json."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    method = EvidenceCollectionMethod.STATIC
    coll = data.get("collection")
    if isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "live":
        method = EvidenceCollectionMethod.LIVE
    elif isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "manual":
        method = EvidenceCollectionMethod.MANUAL
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Disclosure policy evidence is valid: contact={contact.get('method')}, "
            f"acknowledgement_sla_hours={ack_sla}, triage_sla_hours={triage_sla}, "
            f"public_disclosure_window={pdp.get('default_window_days')}d "
            f"(negotiable={pdp.get('negotiable')})."
        ),
        remediation="Re-attest evidence within freshness window when the policy changes.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=method,
    )


def eval_prov_verify_061(ctx: EvalContext) -> EvalOutcome:
    """PROV-VERIFY-061: Build provenance attestation is verifiable (sigstore / Artifact Attestations)."""
    evidence_dir = ctx.repo_root / ".oss-policy-kit" / "evidence"
    candidate: Path | None = None
    schema_loader: Callable[[], dict[str, Any]] | None = None
    for filename, loader in _prov_verify_lookup_order(ctx.profile_id):
        p = evidence_dir / filename
        if p.is_file():
            candidate = p
            schema_loader = loader
            break
    if candidate is None or schema_loader is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No provenance-artifact evidence file found. PROV-VERIFY-061 requires a "
                "{github,azure,aws}-provenance-artifact.json with a populated verification block."
            ),
            remediation=(
                "Run `gh attestation verify` (or `cosign verify-bundle`) against the release artifact "
                "and record the result in .oss-policy-kit/evidence/<platform>-provenance-artifact.json "
                "under the verification field."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        candidate,
        schema_loader=schema_loader,
        evidence_name=f"{candidate.stem.replace('-', ' ')} verification",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation=f"Fix the evidence file or regenerate it with `gh attestation verify`. ({candidate.name})",
            evidence_sources=[str(candidate.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(candidate, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    verification = data.get("verification")
    if not isinstance(verification, dict):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"Evidence file {candidate.name} has no verification block. "
                "Provenance presence alone is signal-grade; PROV-VERIFY-061 requires "
                "an independent verification result (issuer, transparency-log inclusion, verified_at)."
            ),
            remediation=(
                "Run `gh attestation verify <artifact> --repo owner/name` (public repos use the sigstore "
                "public-good instance) and write the result into the verification block of this file."
            ),
            evidence_sources=[str(candidate.resolve())],
            confidence="medium",
        )
    transparency = bool(verification.get("transparency_log_inclusion"))
    if not transparency:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Verification block in {candidate.name} reports transparency_log_inclusion=false. "
                "Without transparency-log inclusion, the attestation cannot be retroactively audited."
            ),
            remediation=(
                "Re-issue the attestation through a builder that records inclusion in the Rekor transparency log."
            ),
            evidence_sources=[str(candidate.resolve())],
            confidence="high",
        )
    verified_at_raw = verification.get("verified_at")
    if not isinstance(verified_at_raw, str) or not verified_at_raw.strip():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"verification.verified_at is missing or empty in {candidate.name}.",
            remediation="Record the ISO8601 UTC timestamp at which the attestation was verified.",
            evidence_sources=[str(candidate.resolve())],
            confidence="low",
        )
    fresh = _verification_freshness_status(verified_at_raw, max_age_days=ctx.evidence_max_age_days)
    if fresh == "stale":
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Verification record in {candidate.name} is older than {ctx.evidence_max_age_days} days "
                f"(verified_at={verified_at_raw}). Re-verify the attestation before relying on this control."
            ),
            remediation="Re-run `gh attestation verify` (or cosign verify-bundle) and update verified_at.",
            evidence_sources=[str(candidate.resolve())],
            confidence="high",
        )
    if fresh in ("future", "unparseable"):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"verification.verified_at is unparseable or in the future ({verified_at_raw}).",
            remediation="Use a real ISO8601 UTC timestamp.",
            evidence_sources=[str(candidate.resolve())],
            confidence="low",
        )
    method = str(verification.get("method", "unknown"))
    source_raw = verification.get("source")
    source_suffix = ""
    if isinstance(source_raw, str) and source_raw.strip():
        source_suffix = f" source={source_raw.strip()};"
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Provenance attestation verified ({method});{source_suffix} transparency-log inclusion confirmed; "
            f"verified_at={verified_at_raw} within {ctx.evidence_max_age_days}-day freshness window."
        ),
        remediation="Re-verify on every release artifact emission to keep verified_at within the freshness window.",
        evidence_sources=[str(candidate.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.LIVE,
    )


def eval_release_archive_063(ctx: EvalContext) -> EvalOutcome:
    """RELEASE-ARCHIVE-063: Release artifacts have an explicit archival/retention policy."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "release-archival-policy.json"
    if not evidence.is_file():
        signal = _release_archive_signal_match(ctx.repo_root)
        if signal is not None:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"Release archival/retention policy intent detected via {signal.name}. "
                    "Heuristic only — promote to evidence-backed by adding "
                    ".oss-policy-kit/evidence/release-archival-policy.json with retention_years."
                ),
                remediation=(
                    "Document retention_years (>= 10 for EU CRA alignment), archive_destination, "
                    "and vulnerability_handling_doc in .oss-policy-kit/evidence/release-archival-policy.json."
                ),
                evidence_sources=[str(signal.resolve())],
                confidence="low",
                operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No release archival/retention policy evidence found. Closes NIST SSDF PS.3 (Archive & "
                "protect each release) and aligns EU CRA 10-year retention. Add either a policy file "
                "(RELEASE_ARCHIVAL.md / .github/release-archival.yml) or "
                ".oss-policy-kit/evidence/release-archival-policy.json."
            ),
            remediation=(
                "Document the team's release artifact retention policy and archival destination "
                "(github-releases / S3 / Software Heritage). EU CRA expects retention_years >= 10."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_release_archival_policy_schema,
        evidence_name="Release archival policy",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-release-archival-policy.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    retention = data.get("retention_years")
    archive_dest = str(data.get("archive_destination", "")).strip()
    vuln_doc = str(data.get("vulnerability_handling_doc", "")).strip()
    if not isinstance(retention, int) or retention < 0:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="release-archival-policy.json has missing or invalid retention_years.",
            remediation="Set retention_years to a non-negative integer (>= 10 aligns with EU CRA).",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if not archive_dest:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="release-archival-policy.json reports an empty archive_destination.",
            remediation="Set archive_destination to a real location (github-releases, s3://, swh:archive, etc.).",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if not vuln_doc:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="release-archival-policy.json does not reference a vulnerability_handling_doc.",
            remediation="Point vulnerability_handling_doc at SECURITY.md (or equivalent).",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if retention < 10:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"retention_years={retention} is below EU CRA's 10-year expectation. "
                "Acceptable for non-EU products; review for CRA-affected scopes."
            ),
            remediation="Increase retention_years to >= 10 if you place products on the EU market.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Release archival policy: retention_years={retention} (>= 10), "
            f"archive_destination={archive_dest}, vulnerability_handling_doc={vuln_doc}."
        ),
        remediation="Re-attest periodically and keep retention storage active.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_publish_oidc_001(ctx: EvalContext) -> EvalOutcome:
    """PUBLISH-OIDC-001: publish workflow declares ``permissions: id-token: write``."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows present.",
            remediation="No action required. This control activates when a publish workflow is defined.",
            evidence_sources=[],
            confidence="high",
        )
    publish = _publish_workflows(paths)
    if not publish:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No publish workflow detected (no PyPI / npm / RubyGems / crates keyword in any workflow).",
            remediation=(
                "If this repo publishes to a package registry, the publish workflow should declare "
                "``permissions: id-token: write`` so the registry can attest the build via OIDC."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    matched: list[Path] = []
    for p in publish:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if _OIDC_TOKEN_PATTERN.search(text):
                matched.append(p)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(publish)} publish workflow(s) detected but none declare ``permissions: id-token: write``. "
                "Trusted Publishing requires this permission for the runtime to mint the OIDC token."
            ),
            remediation=(
                "Add ``permissions: { id-token: write }`` at the workflow or job level. "
                "See PyPI Trusted Publishers docs / npm Trusted Publishers docs."
            ),
            evidence_sources=[str(p.resolve()) for p in publish],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(f"{len(matched)} of {len(publish)} publish workflow(s) declare ``permissions: id-token: write``."),
        remediation=(
            "Keep id-token: write scoped to the publish job, not the whole workflow, and pin the "
            "publish action by SHA per CI-PIN-008."
        ),
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="medium",
    )


def eval_publish_oidc_002(ctx: EvalContext) -> EvalOutcome:
    """PUBLISH-OIDC-002: publish step omits long-lived registry token / password."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows present.",
            remediation="No action required. This control activates when a publish workflow is defined.",
            evidence_sources=[],
            confidence="high",
        )
    publish = _publish_workflows(paths)
    if not publish:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No publish workflow detected.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="medium",
        )
    offenders: list[Path] = []
    for p in publish:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if _LONG_LIVED_PASSWORD_PATTERN.search(text):
                offenders.append(p)
    if offenders:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(offenders)} publish workflow(s) still reference a long-lived token "
                "(NPM_TOKEN / PYPI_TOKEN / TWINE_PASSWORD / RUBYGEMS_API_KEY / CARGO_REGISTRY_TOKEN / "
                "password: secrets.*). Trusted Publishing removes the need for these."
            ),
            remediation=(
                "Migrate to Trusted Publishing (PyPI / npm / RubyGems / crates) and remove the "
                "long-lived secret. Document the cut-over and rotate the legacy token out of the "
                "registry afterward."
            ),
            evidence_sources=[str(p.resolve()) for p in offenders],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"None of the {len(publish)} publish workflow(s) reference a long-lived registry token; "
            "Trusted Publishing posture is consistent."
        ),
        remediation="Confirm the legacy registry token was rotated out after the cut-over.",
        evidence_sources=[str(p.resolve()) for p in publish],
        confidence="medium",
    )


def eval_publish_oidc_003(ctx: EvalContext) -> EvalOutcome:
    """PUBLISH-OIDC-003: npm publish step uses ``--provenance`` (or registry-equivalent)."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows present.",
            remediation="No action required. This control activates when an npm publish workflow is defined.",
            evidence_sources=[],
            confidence="high",
        )
    npm_publish: list[Path] = []
    for p in paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if "npm publish" in text:
                npm_publish.append(p)
    if not npm_publish:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No npm publish step detected.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="medium",
        )
    with_provenance: list[Path] = []
    for p in npm_publish:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if _NPM_PROVENANCE_PATTERN.search(text):
                with_provenance.append(p)
    if not with_provenance:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(npm_publish)} npm publish workflow(s) found but none declare ``--provenance`` "
                "or ``provenance: true``. Trusted Publishing on npm requires the flag for the provenance "
                "attestation to be generated."
            ),
            remediation=(
                "Add ``--provenance`` to the ``npm publish`` command, or set ``provenance: true`` on the "
                "publish action input. See npm Trusted Publishers docs."
            ),
            evidence_sources=[str(p.resolve()) for p in npm_publish],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(f"{len(with_provenance)} of {len(npm_publish)} npm publish workflow(s) declare provenance."),
        remediation="Keep the provenance flag enabled; remove if migrating off npm-trusted-publishing only.",
        evidence_sources=[str(p.resolve()) for p in with_provenance],
        confidence="medium",
    )


def eval_osps_scorecard_v6_001(ctx: EvalContext) -> EvalOutcome:
    """OSPS-SCORECARD-V6-001: Scorecard v6 OSPS Baseline conformance evidence."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "scorecard-osps.json"
    if not evidence.is_file():
        legacy = ctx.repo_root / ".oss-policy-kit" / "evidence" / "scorecard.json"
        if legacy.is_file():
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=(
                    "Classic Scorecard result present but no OSPS Baseline conformance "
                    "(scorecard-osps.json). Scorecard v6 emits a PASS/FAIL/UNKNOWN conformance "
                    "verdict aligned to OSPS Baseline v2026.02.19."
                ),
                remediation="Run `scorecard --format=osps` once Scorecard v6 ships (writes scorecard-osps.json).",
                evidence_sources=[str(legacy.resolve())],
                confidence="medium",
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No Scorecard OSPS conformance evidence at .oss-policy-kit/evidence/scorecard-osps.json.",
            remediation=(
                "Run `scorecard --format=osps --repo=<url> > scorecard-osps.json` and drop it under "
                ".oss-policy-kit/evidence/. See docs/osps-baseline-2026-mapping.md."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(evidence.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            verdict = str(data.get("conformance") or data.get("result") or data.get("overall") or "").strip().lower()
            if verdict in {"pass", "passed", "conformant", "true"}:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="Scorecard v6 reports OSPS Baseline conformance (PASS).",
                    remediation="Re-run Scorecard on each release to keep the conformance verdict current.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                    evidence_collection_method=EvidenceCollectionMethod.LIVE,
                )
            if verdict in {"fail", "failed", "non-conformant", "false"}:
                return EvalOutcome(
                    status=ControlStatus.FAIL,
                    reason="Scorecard v6 reports OSPS Baseline non-conformance (FAIL).",
                    remediation="Address the failing OSPS Baseline checks reported by Scorecard.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                    evidence_collection_method=EvidenceCollectionMethod.LIVE,
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="scorecard-osps.json present but no recognisable conformance verdict (pass/fail).",
        remediation="Regenerate the OSPS conformance report with Scorecard v6 (`--format=osps`).",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_scanner_integrity_001(ctx: EvalContext) -> EvalOutcome:
    """SCANNER-INTEGRITY-001: scanner actions pinned by SHA (post-Trivy supply-chain defense)."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows detected; scanner integrity check does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    unpinned: list[str] = []
    pinned = 0
    seen_scanner = False
    for p in paths:
        for raw_line in _workflow_text(p).splitlines():
            line = raw_line.strip()
            if "uses:" not in line:
                continue
            low = line.lower()
            if not any(h in low for h in _SCANNER_ACTION_HINTS):
                continue
            seen_scanner = True
            ref = line.split("uses:", 1)[1].strip().strip("'\"")
            if _SHA_PIN_PATTERN.search(ref):
                pinned += 1
            else:
                unpinned.append(f"{p.name}: {ref}")
    if not seen_scanner:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No scanner actions referenced in workflows; scanner integrity check does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    if unpinned:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(unpinned)} scanner action reference(s) not pinned by full SHA "
                f"({unpinned[0]}). Trivy attack (2026-03) showed unpinned scanner actions are a supply-chain vector."
            ),
            remediation="Pin every scanner action to a full 40-char commit SHA; verify with `gh attestation verify`.",
            evidence_sources=[str(p.resolve()) for p in paths[:3]],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"All {pinned} scanner action reference(s) pinned by full commit SHA.",
        remediation="Keep scanner actions SHA-pinned and re-verify attestations on each bump.",
        evidence_sources=[str(p.resolve()) for p in paths[:3]],
        confidence="medium",
    )
