"""supply_chain control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import (
    _COMMIT_SIGNATURE_HINTS,
    _DISTROLESS_MARKERS,
    _DOCKER_FROM_RE,
    _IMAGE_SCAN_TOKENS,
    _KEYWORD_CI_SIGNAL_WARN,
    _OSV_SARIF_RELPATH,
    _POSTINSTALL_DANGER_HINTS,
    _ROOT_USER_RE,
    _USER_RE,
    Any,
    ControlStatus,
    EvalContext,
    EvalOutcome,
    EvidenceCollectionMethod,
    Path,
    _branch_protection_evidence,
    _find_dockerfiles,
    _parse_branch_protection_evidence,
    _parts_within_repo,
    _scan_sarif_epss_kev,
    cast,
    contextlib,
    json,
)

# SLSA-SRC-005 / SLSA-SRC-008 delegate to the AUDIT-STREAM-060 evaluator, which lives
# in the governance family. Explicit cross-family import (governance does not import
# back, so no cycle).
from oss_policy_kit.application.evaluators.governance import eval_audit_stream_060

_NO_ACTION_REQUIRED = "No action required."
_PACKAGE_JSON = "package.json"


def _unpinned_from_refs(dockerfiles: list[Path]) -> list[str]:
    """Return ``<file>: <ref>`` entries for FROM base images not pinned by digest (excluding scratch)."""

    unpinned: list[str] = []
    for df in dockerfiles:
        with contextlib.suppress(OSError):
            content = df.read_text(encoding="utf-8", errors="replace")
            for ref in _DOCKER_FROM_RE.findall(content):
                if ref.lower() != "scratch" and "@sha256:" not in ref:
                    unpinned.append(f"{df.name}: {ref}")
    return unpinned


def eval_cont_image_001(ctx: EvalContext) -> EvalOutcome:
    """CONT-IMAGE-001: Dockerfile base images pinned to immutable digest (@sha256:...)."""
    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile detected at repository root or common paths.",
            remediation="Not applicable until a Dockerfile is added to the repository.",
            evidence_sources=[],
            confidence="high",
        )
    unpinned = _unpinned_from_refs(dockerfiles)
    if not unpinned:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="All Dockerfile FROM instructions use digest-pinned base images.",
            remediation="Keep base image digest pins updated via Dependabot or Renovate.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles],
            confidence="medium",
        )
    sample = unpinned[:3]
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=(
            "Dockerfile FROM instruction(s) without digest pin: "
            + "; ".join(sample)
            + (" (and more)" if len(unpinned) > 3 else "")
            + "."
        ),
        remediation=(
            "Pin base images to immutable SHA-256 digests: "
            "FROM ubuntu:22.04@sha256:<digest>. "
            "Use 'docker pull --quiet <image>' to resolve the digest."
        ),
        evidence_sources=[str(p.resolve()) for p in dockerfiles],
        confidence="medium",
    )


def eval_cont_image_002(ctx: EvalContext) -> EvalOutcome:
    """CONT-IMAGE-002: Dockerfile declares a non-root USER instruction."""
    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile detected at repository root or common paths.",
            remediation="Not applicable until a Dockerfile is added to the repository.",
            evidence_sources=[],
            confidence="high",
        )
    root_user: list[Path] = []
    missing_user: list[Path] = []
    for df in dockerfiles:
        with contextlib.suppress(OSError):
            content = df.read_text(encoding="utf-8", errors="replace")
            if _ROOT_USER_RE.search(content):
                root_user.append(df)
            elif not _USER_RE.search(content):
                missing_user.append(df)
    if root_user:
        names = ", ".join(p.name for p in root_user[:3])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Dockerfile(s) explicitly set USER root or USER 0: {names}.",
            remediation="Create a dedicated non-root user and switch to it before CMD/ENTRYPOINT.",
            evidence_sources=[str(p.resolve()) for p in root_user],
            confidence="medium",
        )
    if missing_user:
        names = ", ".join(p.name for p in missing_user[:3])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Dockerfile(s) do not declare a non-root USER instruction: {names}.",
            remediation=(
                "Add 'RUN useradd -r -u 1001 appuser && USER appuser' before CMD/ENTRYPOINT "
                "to avoid running the process as root inside the container."
            ),
            evidence_sources=[str(p.resolve()) for p in missing_user],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Dockerfile(s) declare a non-root USER instruction ({len(dockerfiles)} file(s) checked).",
        remediation="Verify the declared user has the minimum filesystem permissions needed.",
        evidence_sources=[str(p.resolve()) for p in dockerfiles],
        confidence="medium",
    )


def eval_cont_image_003(ctx: EvalContext) -> EvalOutcome:
    """CONT-IMAGE-003: Container image scanning signal in CI workflows."""
    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile detected — image scanning is not applicable.",
            remediation="Not applicable until a Dockerfile is added.",
            evidence_sources=[],
            confidence="high",
        )
    all_ci_paths = (
        list(ctx.workflows.workflow_paths) + list(ctx.azure_pipelines.pipeline_paths) + list(ctx.aws_ci.buildspec_paths)
    )
    for p in all_ci_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(tok in text for tok in _IMAGE_SCAN_TOKENS):
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=(
                        f"Container image scanning tool signal detected in {p.name}. "
                        "(keyword signal in CI config — scan execution and policy thresholds not validated)"
                    ),
                    remediation="Keep image scanning on push and PR triggers; enforce severity thresholds.",
                    evidence_sources=[str(p.resolve())],
                    confidence="low",
                    operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
                )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No container image scanning signal detected in CI (Trivy, Grype, Snyk, Anchore, or equivalent).",
        remediation=(
            "Add an image scanning step to your CI pipeline. "
            "Example: uses: aquasecurity/trivy-action@<sha> with image-ref: <your-image>."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def _discover_aibom_files(repo_root: Path) -> list[Path]:
    """Find AIBOM JSON files under the evidence dir, or any ML-BOM marker file repo-wide."""

    candidates: list[Path] = []
    for rel in (".oss-policy-kit/evidence/aibom", "aibom"):
        d = repo_root / rel
        if d.is_dir():
            with contextlib.suppress(OSError):
                candidates.extend(p for p in d.glob("*.json") if p.is_file())
    if candidates:
        return candidates
    # Cycle 2 (PR-26): also recognise a CycloneDX 1.7 ML-BOM anywhere in the
    # repo via the machine-learning-model component marker.
    with contextlib.suppress(OSError):
        for p in list(repo_root.rglob("*.cdx.json")) + list(repo_root.rglob("bom.json")):
            if _is_ml_bom_marker_file(p, repo_root):
                candidates.append(p)
    return candidates


def _is_ml_bom_marker_file(p: Path, repo_root: Path) -> bool:
    """True when a non-.git JSON file carries an ML-BOM / model-card marker in its head."""

    if not p.is_file() or ".git" in _parts_within_repo(p, repo_root):
        return False
    sample = p.read_text(encoding="utf-8", errors="replace")[:8000].lower()
    return "machine-learning-model" in sample or "modelcard" in sample or "ml-bom" in sample


def eval_aibom_present_001(ctx: EvalContext) -> EvalOutcome:
    """AIBOM-PRESENT-001: AI Bill of Materials present in evidence directory."""
    candidates = _discover_aibom_files(ctx.repo_root)
    if not candidates:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No AIBOM file found at .oss-policy-kit/evidence/aibom/*.json or aibom/*.json. "
                "CycloneDX ML-BOM and SPDX 3.0 AI components are the two recognised formats."
            ),
            remediation=(
                "Generate an AIBOM (CycloneDX ML-BOM via cdxgen with ML profile, or SPDX 3.0 AI "
                "components) and drop the JSON at .oss-policy-kit/evidence/aibom/."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"AIBOM detected: {len(candidates)} file(s) under the evidence directory.",
        remediation="Re-generate the AIBOM on every model release.",
        evidence_sources=[str(p.resolve()) for p in candidates],
        confidence="medium",
    )


def eval_worm_postinstall_001(ctx: EvalContext) -> EvalOutcome:
    """WORM-POSTINSTALL-001: package.json postinstall script lacks credential-harvest primitives."""
    pkg = ctx.repo_root / _PACKAGE_JSON
    if not pkg.is_file():
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No package.json present; postinstall worm pattern does not apply.",
            remediation=_NO_ACTION_REQUIRED,
            evidence_sources=[],
            confidence="high",
        )
    with contextlib.suppress(OSError, UnicodeDecodeError, json.JSONDecodeError):
        data = json.loads(pkg.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            raw_scripts = data.get("scripts")
            scripts = cast(dict[str, Any], raw_scripts) if isinstance(raw_scripts, dict) else {}
            postinstall = str(scripts.get("postinstall", "")).lower()
            if not postinstall:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="No postinstall script declared in package.json.",
                    remediation="Continue avoiding postinstall hooks unless strictly required.",
                    evidence_sources=[str(pkg.resolve())],
                    confidence="high",
                )
            hits = [h for h in _POSTINSTALL_DANGER_HINTS if h in postinstall]
            if hits:
                return EvalOutcome(
                    status=ControlStatus.FAIL,
                    reason=(
                        f"package.json postinstall contains credential-harvest primitives "
                        f"({', '.join(hits[:3])}). Pattern observed in Shai-Hulud / TeamPCP attacks 2026."
                    ),
                    remediation=(
                        "Audit the postinstall script; remove network egress + env-var dumps. "
                        "See docs/shai-hulud-defense.md."
                    ),
                    evidence_sources=[str(pkg.resolve())],
                    confidence="high",
                )
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="package.json postinstall present but no credential-harvest primitive detected.",
                remediation="Periodically audit postinstall content; pin it via a separate version-controlled file.",
                evidence_sources=[str(pkg.resolve())],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="package.json present but unparseable.",
        remediation="Fix package.json JSON syntax.",
        evidence_sources=[str(pkg.resolve())],
        confidence="low",
    )


def eval_worm_lockfile_drift_001(ctx: EvalContext) -> EvalOutcome:
    """WORM-LOCKFILE-DRIFT-001: manifest not modified more recently than lockfile."""
    pairs: list[tuple[Path, Path]] = []
    for manifest, lockfile in (
        (_PACKAGE_JSON, "package-lock.json"),
        (_PACKAGE_JSON, "yarn.lock"),
        ("pyproject.toml", "poetry.lock"),
        ("pyproject.toml", "uv.lock"),
        ("requirements.txt", "requirements.lock"),
    ):
        m = ctx.repo_root / manifest
        lk = ctx.repo_root / lockfile
        if m.is_file() and lk.is_file():
            pairs.append((m, lk))
    if not pairs:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No manifest + lockfile pair detected; lockfile drift check does not apply.",
            remediation="Adopt a lockfile (package-lock.json, poetry.lock, uv.lock) to enable this check.",
            evidence_sources=[],
            confidence="high",
        )
    drifted: list[tuple[Path, Path]] = []
    for m, lk in pairs:
        with contextlib.suppress(OSError):
            if m.stat().st_mtime > lk.stat().st_mtime + 60:
                drifted.append((m, lk))
    if drifted:
        sample = ", ".join(f"{m.name}>{lk.name}" for m, lk in drifted[:3])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Manifest modified more recently than lockfile ({sample}). "
                "Shai-Hulud worm rewrites manifests; verify the diff is intentional."
            ),
            remediation=(
                "Regenerate the lockfile (npm install, poetry lock, uv lock) and commit it together "
                "with the manifest change. Investigate any unexplained drift."
            ),
            evidence_sources=[str(p.resolve()) for pair in drifted for p in pair],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Lockfile is at least as fresh as the manifest for {len(pairs)} pair(s).",
        remediation="Keep lockfile updates atomic with manifest changes.",
        evidence_sources=[str(p.resolve()) for pair in pairs for p in pair],
        confidence="medium",
    )


def eval_worm_publish_scope_001(ctx: EvalContext) -> EvalOutcome:
    """WORM-PUBLISH-SCOPE-001: publish workflow scoped to main/release branches."""
    publish_paths: list[Path] = []
    for p in ctx.workflows.workflow_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if "npm publish" in text or "twine upload" in text or "pypi-publish" in text or "cargo publish" in text:
                publish_paths.append(p)
    if not publish_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No publish workflow detected.",
            remediation=_NO_ACTION_REQUIRED,
            evidence_sources=[],
            confidence="high",
        )
    risky: list[Path] = []
    for p in publish_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            # Look for tag-only or branch-restricted triggers.
            has_branch_restriction = any(
                pat in text
                for pat in (
                    "branches: [main",
                    "branches: [master",
                    "branches: ['main'",
                    'branches: ["main"',
                    "branches: [release",
                    "tags:",
                    "tags: ['v",
                    'tags: ["v',
                )
            )
            if not has_branch_restriction:
                risky.append(p)
    if risky:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(risky)} publish workflow(s) lack explicit branch / tag scope. "
                "Shai-Hulud-style worms exploit unscoped publish triggers to push poisoned versions."
            ),
            remediation=(
                "Restrict the publish workflow to `on: { push: { tags: ['v*'] } }` or "
                "`on: { push: { branches: [main] } }` plus an environment with required approvers."
            ),
            evidence_sources=[str(p.resolve()) for p in risky],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(publish_paths)} publish workflow(s) scoped to main/release branches or tags.",
        remediation="Keep the scope tight; require environment approvals for production publishes.",
        evidence_sources=[str(p.resolve()) for p in publish_paths],
        confidence="medium",
    )


def eval_slsa_src_001(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-001: Version-controlled source (.git present)."""
    if (ctx.repo_root / ".git").exists():
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Repository is under git version control (.git present).",
            remediation="Continue using git for source versioning.",
            evidence_sources=[str((ctx.repo_root / ".git").resolve())],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No .git directory detected; source is not under version control.",
        remediation="Initialise a git repository and push to a hosted SCM.",
        evidence_sources=[],
        confidence="high",
    )


def eval_slsa_src_002(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-002: Commit-signature enforcement signal."""
    workflow_paths = ctx.workflows.workflow_paths
    # Look in workflow files and known ruleset hint locations.
    candidates: list[Path] = list(workflow_paths)
    for rel in (
        ".github/rulesets",
        ".github/branch-protection.yml",
        ".github/branch-protection.yaml",
        ".oss-policy-kit/evidence/branch-protection.json",
    ):
        p = ctx.repo_root / rel
        if p.exists():
            if p.is_dir():
                with contextlib.suppress(OSError):
                    candidates.extend(c for c in p.rglob("*") if c.is_file())
            else:
                candidates.append(p)
    matched: list[Path] = []
    for p in candidates:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(h in text for h in _COMMIT_SIGNATURE_HINTS):
                matched.append(p)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No commit-signature enforcement signal detected (no required_signatures or "
                "equivalent in workflows / rulesets / branch-protection evidence)."
            ),
            remediation=(
                "Enable required signatures via repository ruleset (GitHub: Settings → Rules → "
                "Rulesets → Require signed commits), or document the enforcement in the "
                "branch-protection.json evidence file."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Commit-signature enforcement signal detected in {len(matched)} location(s) "
            "(workflows, rulesets, or branch-protection evidence)."
        ),
        remediation="Audit the rule periodically; ensure it stays attached to protected branches.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="medium",
    )


# SLSA-SRC-003/004/006/007 and PLAT-BRPROT-015 read one file, so they must read it one way.
# They did not: these four read top-level `required_status_checks`,
# `required_approving_review_count` and `required_signatures`, which
# evidence-branch-protection.schema.json forbids outright (`additionalProperties: false`, and
# the flags live under `protections`), while PLAT-BRPROT-015 validated against that schema. No
# file `scaffold-evidence` writes, no file `collect-evidence` writes, and no file the schema
# accepts could satisfy both readers at once. Validation now happens in exactly one place --
# `_shared._parse_branch_protection_evidence`, the reader PLAT-BRPROT-015 already uses -- so
# the two cannot drift apart again.
def _slsa_branch_protections(ctx: EvalContext) -> tuple[dict[str, Any] | None, Path, EvalOutcome | None]:
    """Return ``(protections, path, refusal)`` for the branch-protection evidence file.

    ``protections`` is the block of a file that passes the packaged schema. ``refusal`` is the
    shared reader's own outcome, verbatim, when the file exists but cannot be used -- unreadable,
    non-object root, schema violation (manual-review-required, ADR-045) or an unfilled scaffold
    template (not-evaluated). Both are ``None`` when there is no file at all, because "absent" is
    a different sentence per control.

    Only ``pass`` and ``fail`` mean the shared reader got as far as reading the flags, so those
    two are what makes the block usable. A schema-valid file whose flags are merely *off* is
    usable: each control below answers for its own dimension, so the aggregate ``fail`` that
    PLAT-BRPROT-015 reports is not a refusal here.
    """

    data, p = _branch_protection_evidence(ctx)
    if data is None:
        return None, p, (_parse_branch_protection_evidence(p) if p.is_file() else None)
    verdict = _parse_branch_protection_evidence(p)
    if verdict.status not in (ControlStatus.PASS, ControlStatus.FAIL):
        return None, p, verdict
    return cast(dict[str, Any], data["protections"]), p, None


def eval_slsa_src_003(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-003: Branch protection present (same evidence and reader as PLAT-BRPROT-015)."""
    protections, p, refusal = _slsa_branch_protections(ctx)
    if refusal is not None:
        return refusal
    if protections is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No branch-protection.json evidence file present. SLSA Source L1 requires "
                "documented protected branches."
            ),
            remediation=(
                "Run `oss-policy-kit collect-evidence --platform github` (or the equivalent for "
                "your SCM) to populate .oss-policy-kit/evidence/branch-protection.json."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    if protections.get("require_status_checks") is True:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Branch protection documented in branch-protection.json: protections.require_status_checks is on.",
            remediation="Keep the evidence file current with the live ruleset.",
            evidence_sources=[str(p.resolve())],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=(
            "branch-protection.json attests protections.require_status_checks is off; the "
            "protected branch merges with no required check."
        ),
        remediation="Require at least one status check on the protected branch, then refresh the evidence file.",
        evidence_sources=[str(p.resolve())],
        confidence="high",
    )


def eval_slsa_src_004(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-004: Two-party review on protected branches."""
    protections, p, refusal = _slsa_branch_protections(ctx)
    if refusal is not None:
        return refusal
    if protections is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No branch-protection.json evidence; two-party review cannot be verified.",
            remediation=(
                "Run `oss-policy-kit collect-evidence --platform github` and ensure the resulting "
                "evidence file sets protections.require_pull_request_reviews to true."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    if protections.get("require_pull_request_reviews") is True:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "branch-protection.json attests protections.require_pull_request_reviews is on "
                "(at least one required reviewer before merge)."
            ),
            remediation="SLSA Source L4 requires 2+ approving reviews; consider raising the threshold.",
            evidence_sources=[str(p.resolve())],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="branch-protection.json attests protections.require_pull_request_reviews is off; merges need no review.",
        remediation="Require pull-request review on the protected branch, then refresh the evidence file.",
        evidence_sources=[str(p.resolve())],
        confidence="high",
    )


def eval_slsa_src_005(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-005: Audit log of source-changing events (delegates to AUDIT-STREAM-060)."""
    return eval_audit_stream_060(ctx)


def eval_sca_kev_001(ctx: EvalContext) -> EvalOutcome:
    """SCA-KEV-001: no dependency CVE present in CISA KEV (SARIF kev property)."""
    evidence = ctx.repo_root / _OSV_SARIF_RELPATH
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"No OSV-Scanner SARIF at {_OSV_SARIF_RELPATH}; KEV status cannot be verified.",
            remediation="Run OSV-Scanner v2+ with KEV enrichment, attach the SARIF. See docs/triage-cvss-epss-kev.md.",
            evidence_sources=[],
            confidence="medium",
        )
    scan = _scan_sarif_epss_kev(evidence)
    kev, err = scan.kev, scan.error
    if err is not None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=err,
            remediation="Regenerate the OSV-Scanner SARIF.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if kev:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(kev)} dependency CVE(s) present in the CISA KEV catalog "
                f"({', '.join(sorted(set(kev))[:3])}). KEV = confirmed active exploitation."
            ),
            remediation="Patch or remove KEV-listed dependencies immediately; KEV overrides standard severity.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    if not scan.saw_kev_property:
        # No result in this SARIF carries a `kev` property, so the scan cannot tell
        # "enrichment ran and flagged nothing" from "there is no KEV data here". It used
        # to answer the first at confidence=high, assurance=evidence-backed -- on a file
        # containing Log4Shell, because plain `osv-scanner --format sarif` emits no such
        # property and this control's own remediation says so. A policy kit asserting a
        # security fact it did not check is the one thing it must never do.
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "The OSV-Scanner SARIF carries no KEV enrichment (no result has a "
                "`properties.kev` field), so KEV status cannot be verified."
            ),
            remediation=(
                "Re-run OSV-Scanner v2+ with KEV enrichment so each result carries "
                "`properties.kev`. See docs/triage-cvss-epss-kev.md."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No dependency CVE flagged as CISA KEV in the OSV-Scanner SARIF.",
        remediation="Keep dependencies current; re-scan on each release with KEV enrichment.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_sca_epss_001(ctx: EvalContext) -> EvalOutcome:
    """SCA-EPSS-001: no high-EPSS high-severity dependency CVE unaddressed."""
    evidence = ctx.repo_root / _OSV_SARIF_RELPATH
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"No OSV-Scanner SARIF at {_OSV_SARIF_RELPATH}; EPSS prioritization cannot be verified.",
            remediation="Run OSV-Scanner v2+ with EPSS enrichment, attach the SARIF. See docs/triage-cvss-epss-kev.md.",
            evidence_sources=[],
            confidence="medium",
        )
    scan = _scan_sarif_epss_kev(evidence)
    high_epss, err = scan.high_epss, scan.error
    if err is not None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=err,
            remediation="Regenerate the OSV-Scanner SARIF.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if high_epss:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(high_epss)} dependency CVE(s) with EPSS >= 0.5 and CVSS >= 7.0 "
                f"({', '.join(sorted(set(high_epss))[:3])}). High exploit probability."
            ),
            remediation="Prioritise patching high-EPSS high-severity CVEs ahead of the standard backlog.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    if not scan.saw_epss_property:
        # Same reasoning as SCA-KEV-001: an empty high-EPSS list over a SARIF with no
        # EPSS data at all is not evidence that exploit probability is low.
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "The OSV-Scanner SARIF carries no EPSS enrichment (no result has a "
                "`properties.epss_score` field), so exploit probability cannot be verified."
            ),
            remediation=(
                "Re-run OSV-Scanner v2+ with EPSS enrichment so each result carries "
                "`properties.epss_score`. See docs/triage-cvss-epss-kev.md."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No high-EPSS high-severity dependency CVE detected in the OSV-Scanner SARIF.",
        remediation="Re-evaluate EPSS scores periodically; they change as exploit telemetry evolves.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_slsa_src_006(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-006: signed commits required (SLSA Source L2)."""
    protections, p, refusal = _slsa_branch_protections(ctx)
    if refusal is not None:
        return refusal
    if protections is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No branch-protection.json evidence; required-signed-commits enforcement cannot be verified.",
            remediation=(
                "Run `oss-policy-kit collect-evidence --platform github`; ensure "
                "protections.require_signed_commits is true."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    signed = protections.get("require_signed_commits")
    if signed is True:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="branch-protection.json attests protections.require_signed_commits is on (SLSA Source L2).",
            remediation="Keep required signatures attached to all protected branches.",
            evidence_sources=[str(p.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    if signed is None:
        # `require_signed_commits` is optional in branch-protection/v1, so its absence is a gap
        # in the attestation, not a statement that signing is unenforced (ADR-045).
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "branch-protection.json records no protections.require_signed_commits flag, so "
                "signed-commit enforcement cannot be verified from this evidence."
            ),
            remediation=(
                "Add protections.require_signed_commits to the evidence file (it is optional in "
                "branch-protection/v1) once the repository ruleset requires signed commits."
            ),
            evidence_sources=[str(p.resolve())],
            confidence="medium",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=(
            "branch-protection.json attests protections.require_signed_commits is off "
            "(SLSA Source L2 needs signed commits)."
        ),
        remediation="Enable required signed commits via repository ruleset and refresh the evidence file.",
        evidence_sources=[str(p.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_slsa_src_007(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-007: two-party review threshold enforced (SLSA Source L2)."""
    protections, p, refusal = _slsa_branch_protections(ctx)
    if refusal is not None:
        return refusal
    if protections is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No branch-protection.json evidence; two-party L2 review threshold cannot be verified.",
            remediation=(
                "Run `collect-evidence --platform github`, then confirm out of band that the "
                "protected branch requires >= 2 approving reviews."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    if protections.get("require_pull_request_reviews") is not True:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "branch-protection.json attests protections.require_pull_request_reviews is off; "
                "zero required approvals cannot meet the SLSA Source L2 threshold of >= 2."
            ),
            remediation="Require pull-request review with >= 2 approvers, then refresh the evidence file.",
            evidence_sources=[str(p.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    # branch-protection/v1 records *whether* review is required, never how many approvers --
    # `protections` is closed (`additionalProperties: false`) and carries no count. Reading the
    # >= 1 boolean as proof of >= 2 would turn unknown into clean, so the threshold stays a
    # human check until the schema gains a field for it.
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "branch-protection.json attests that pull-request review is required, but "
            "branch-protection/v1 records no approver count, so the SLSA Source L2 threshold of "
            ">= 2 cannot be verified from this evidence."
        ),
        remediation=(
            "Confirm the protected branch requires >= 2 approving reviews on the platform and "
            "record that check outside this control (or waive it) until the evidence schema can "
            "carry the threshold."
        ),
        evidence_sources=[str(p.resolve())],
        confidence="medium",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_slsa_src_008(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-008: source-change audit log streamed externally (delegates to AUDIT-STREAM-060)."""
    return eval_audit_stream_060(ctx)


def _discover_dockerfiles(repo_root: Path) -> list[Path]:
    """Return root Dockerfile/Containerfile plus any nested Dockerfiles (excluding .git)."""

    dockerfiles: list[Path] = []
    for name in ("Dockerfile", "Containerfile"):
        p = repo_root / name
        if p.is_file():
            dockerfiles.append(p)
    with contextlib.suppress(OSError):
        for p in repo_root.glob("**/Dockerfile"):
            if p not in dockerfiles and ".git" not in _parts_within_repo(p, repo_root):
                dockerfiles.append(p)
    return dockerfiles


def _collect_dockerfile_from_lines(dockerfiles: list[Path]) -> list[str]:
    """Return all lowercased ``FROM ...`` lines across the given Dockerfiles."""

    from_lines: list[str] = []
    for p in dockerfiles:
        with contextlib.suppress(OSError):
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("from "):
                    from_lines.append(stripped)
    return from_lines


def eval_cont_distroless_001(ctx: EvalContext) -> EvalOutcome:
    """CONT-DISTROLESS-001: container base image is distroless / minimal."""
    dockerfiles = _discover_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile / Containerfile detected; distroless base check does not apply.",
            remediation=_NO_ACTION_REQUIRED,
            evidence_sources=[],
            confidence="high",
        )
    from_lines = _collect_dockerfile_from_lines(dockerfiles)
    if not from_lines:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Dockerfile present but no FROM line parsed.",
            remediation="Ensure the Dockerfile declares a base image.",
            evidence_sources=[str(dockerfiles[0].resolve())],
            confidence="low",
        )
    final_from = from_lines[-1]
    if any(m in line for line in from_lines for m in _DISTROLESS_MARKERS):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Container build uses a distroless / minimal base image (Chainguard, Wolfi, distroless, scratch).",
            remediation="Keep using minimal bases; rebuild regularly to inherit upstream CVE fixes.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles[:2]],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=f"Final base image does not appear distroless/minimal ({final_from[:80]}).",
        remediation="Consider a distroless / Chainguard / Wolfi / scratch base to reduce attack surface.",
        evidence_sources=[str(p.resolve()) for p in dockerfiles[:2]],
        confidence="low",
    )
