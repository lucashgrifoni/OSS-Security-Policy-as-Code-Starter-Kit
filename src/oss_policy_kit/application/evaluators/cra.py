"""cra control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import (
    ControlStatus,
    EvalContext,
    EvalOutcome,
    Path,
    _read_first_existing,
    _scan_readme_for_section,
    contextlib,
    insights_self_attested_outcome,
    json,
)


def eval_cra_art13_sbd_001(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART13-SBD-001: security-by-design intent declared."""
    p, _ = _read_first_existing(ctx.repo_root, ("SECURITY.md", "README.md", "docs/security.md"))
    section = _scan_readme_for_section(
        ctx.repo_root, ("security by design", "secure by design", "security-by-design", "secure-by-design")
    )
    adr_hit = (
        any(adr.is_file() for adr in (ctx.repo_root / "docs" / "decisions").glob("*.md"))
        if (ctx.repo_root / "docs" / "decisions").is_dir()
        else False
    )
    if section is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Security-by-design intent documented in {section.name} (CRA Article 13).",
            remediation="Keep the security-by-design statement aligned with the threat model.",
            evidence_sources=[str(section.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "No explicit security-by-design statement found in SECURITY.md / README"
            + (" (ADR directory present — document the intent there)." if adr_hit else ".")
        ),
        remediation="Add a 'Security by design' section to SECURITY.md or an ADR (CRA Art. 13). See cra-readiness.md.",
        evidence_sources=[str(p.resolve())] if p else [],
        confidence="medium",
    )


def eval_cra_art13_defaults_002(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART13-DEFAULTS-002: secure-by-default configuration documented."""
    section = _scan_readme_for_section(
        ctx.repo_root, ("secure default", "secure-by-default", "default configuration", "hardened default")
    )
    if section is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Secure-by-default configuration documented in {section.name} (CRA Article 13).",
            remediation="Review defaults each release; ensure ship-secure (no permissive fallback).",
            evidence_sources=[str(section.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No secure-by-default configuration statement found in SECURITY.md / README.",
        remediation="Document the secure default configuration (CRA Article 13). See docs/cra-readiness.md.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_cra_art14_csaf_001(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART14-CSAF-001: CSAF advisory feed present."""
    candidates = (
        ".well-known/csaf",
        ".well-known/csaf/provider-metadata.json",
        "csaf",
        "advisories.json",
        "security/advisories.json",
    )
    for rel in candidates:
        p = ctx.repo_root / rel
        if p.exists():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"CSAF advisory feed signal present ({rel}) — CRA Article 14 reporting readiness.",
                remediation="Keep the CSAF feed populated with machine-readable advisories per release.",
                evidence_sources=[str(p.resolve())],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No CSAF advisory feed detected (.well-known/csaf, csaf/, or advisories.json).",
        remediation=(
            "Publish CSAF advisories (.well-known/csaf/provider-metadata.json) to support CRA Article 14 "
            "machine-readable reporting. See docs/cra-readiness.md."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def eval_cra_art14_coord_002(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART14-COORD-002: coordinated vulnerability disclosure policy documented."""
    disclosure = ctx.repo_root / ".oss-policy-kit" / "evidence" / "disclosure-policy.json"
    if disclosure.is_file():
        with contextlib.suppress(OSError, UnicodeDecodeError, json.JSONDecodeError):
            data = json.loads(disclosure.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and data.get("coordinated_disclosure") is True:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="disclosure-policy.json declares coordinated_disclosure: true (CRA Article 14).",
                    remediation="Keep the disclosure SLA and contact current.",
                    evidence_sources=[str(disclosure.resolve())],
                    confidence="high",
                )
    section = _scan_readme_for_section(
        ctx.repo_root, ("coordinated disclosure", "coordinated vulnerability disclosure", "responsible disclosure")
    )
    if section is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Coordinated disclosure policy documented in {section.name} (CRA Article 14).",
            remediation="Mirror the policy into disclosure-policy.json (coordinated_disclosure: true) for machine use.",
            evidence_sources=[str(section.resolve())],
            confidence="medium",
        )
    lifted = insights_self_attested_outcome(
        ctx,
        control_label="Coordinated vulnerability disclosure policy (CRA Art. 14, CRA-ART14-COORD-002)",
        remediation="Document a coordinated disclosure policy (CRA Article 14). See docs/cra-readiness.md.",
    )
    if lifted is not None:
        return lifted
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No coordinated vulnerability disclosure policy found in SECURITY.md or disclosure-policy.json.",
        remediation="Document a coordinated disclosure policy (CRA Article 14). See docs/cra-readiness.md.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_cra_product_class_001(ctx: EvalContext) -> EvalOutcome:
    """CRA-PRODUCT-CLASS-001: CRA product classification declared."""
    p, text = _read_first_existing(
        ctx.repo_root, ("cra-classification.md", "docs/cra-classification.md", "docs/cra-readiness.md")
    )
    class_terms = (
        "important product",
        "critical product",
        "default category",
        "class i",
        "class ii",
        "annex iii",
        "annex iv",
    )
    if p is not None and any(t in text for t in class_terms):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"CRA product classification declared in {p.name} (Implementing Reg (EU) 2025/2392).",
            remediation="Re-check the classification when scope or features change.",
            evidence_sources=[str(p.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No CRA product classification declared (important / critical / default per Impl. Reg (EU) 2025/2392).",
        remediation="Add docs/cra-classification.md declaring the product class. See docs/cra-readiness.md.",
        evidence_sources=[],
        confidence="low",
    )


_SUPPORT_PERIOD_TERMS: tuple[str, ...] = (
    "support period",
    "support window",
    "support policy",
    "support lifecycle",
    "support timeline",
    "security support",
    "security updates until",
    "security updates for",
    "security update period",
    "supported until",
    "supported versions",
    "end of life",
    "end-of-life",
    "maintenance period",
)


def eval_cra_art13_support_003(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART13-SUPPORT-003: security-update support period declared (CRA Annex I).

    Clone-visible signal that the manufacturer has declared, somewhere in SECURITY.md / a
    support doc / README, the window during which the product receives security updates — a
    core CRA obligation (Annex I, Part I). A common honest signal is a SECURITY.md
    "Supported Versions" table. Signal only: a declared period is not proof it is honoured.
    Readiness, never CRA conformity.
    """
    p, text = _read_first_existing(
        ctx.repo_root,
        ("SECURITY.md", "docs/security.md", "SUPPORT.md", "docs/support.md", "docs/cra-readiness.md", "README.md"),
    )
    if p is not None and any(t in text for t in _SUPPORT_PERIOD_TERMS):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Security-update support period / supported-versions statement found in {p.name} (CRA Annex I).",
            remediation="Keep the declared support window current and aligned with the release cadence.",
            evidence_sources=[str(p.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No declared security-update support period (e.g. a 'Supported Versions' / support-window statement).",
        remediation=(
            "Declare the security-update support period (CRA Annex I): add a 'Supported Versions' or "
            "support-window section to SECURITY.md. See docs/cra-readiness.md."
        ),
        evidence_sources=[str(p.resolve())] if p else [],
        confidence="low",
    )


# --- v10 CISA Secure by Design Pledge readiness signals --------------------------------
# Honest, clone-observable subset of the (voluntary, 7-goal) CISA Secure by Design Pledge,
# cross-mapped to ISO/IEC 29147 (disclosure) + 30111 (handling). These are "readiness"
# signals, never "pledge fulfilled". The MFA goal is already covered by ORG-MFA-001
# (evidence-backed); patch-uptake and intrusion detection are runtime/telemetry and out of
# clone scope. The disclosure signals overlap the CRA Article 14 track above and are mapped,
# not duplicated (see docs/framework-alignment.md).


def eval_cisa_sbd_vdp_001(ctx: EvalContext) -> EvalOutcome:
    """CISA-SBD-VDP-001: published vulnerability disclosure policy signal (ISO/IEC 29147).

    CISA Secure by Design Pledge — Vulnerability Disclosure Policy goal. Primary new signal
    is the RFC 9116 ``security.txt`` (machine-readable, published VDP); a ``SECURITY.md``
    disclosure section is accepted as a fallback. Signal only: a published policy is not
    proof the intake process runs. Complements CRA-ART14-COORD-002 and GOV-SEC-001.
    """
    sec_txt_candidates = (
        ".well-known/security.txt",
        "security.txt",
        "public/.well-known/security.txt",
        "docs/.well-known/security.txt",
    )
    for rel in sec_txt_candidates:
        p = ctx.repo_root / rel
        if not p.is_file():
            continue
        text = ""
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
        if "contact:" in text:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Published security.txt with a Contact field detected ({rel}) — RFC 9116 VDP (ISO/IEC 29147).",
                remediation="Keep security.txt current (Contact, Expires) and mirror it into SECURITY.md.",
                evidence_sources=[str(p.resolve())],
                confidence="medium",
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"security.txt present ({rel}) but no 'Contact:' field — an RFC 9116 VDP requires one.",
            remediation="Add a 'Contact:' line (and 'Expires:') to security.txt per RFC 9116 (ISO/IEC 29147).",
            evidence_sources=[str(p.resolve())],
            confidence="medium",
        )
    section = _scan_readme_for_section(
        ctx.repo_root,
        (
            "vulnerability disclosure",
            "reporting a vulnerability",
            "report a vulnerability",
            "coordinated disclosure",
            "responsible disclosure",
            "security policy",
        ),
    )
    if section is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Vulnerability disclosure policy documented in {section.name} (ISO/IEC 29147 VDP signal).",
            remediation="Also publish a machine-readable .well-known/security.txt (RFC 9116) for automated intake.",
            evidence_sources=[str(section.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No published VDP signal found (.well-known/security.txt or a SECURITY.md disclosure section).",
        remediation="Publish a VDP: add .well-known/security.txt (RFC 9116) and a SECURITY.md disclosure section.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_cisa_sbd_cve_003(ctx: EvalContext) -> EvalOutcome:
    """CISA-SBD-CVE-003: published advisories carry CWE identifiers (ISO/IEC 30111 hygiene).

    CISA Secure by Design Pledge — CVEs/transparency goal. Where in-repo advisory metadata
    exists (CSAF feed, advisories.json, OSV), check that advisories reference a CWE so
    consumers can map the vulnerability class. NOT_APPLICABLE when no advisory metadata is
    present in the clone (it cannot be observed). Composes the CSAF detection used by
    CRA-ART14-CSAF-001 but assesses content, not mere presence.
    """
    advisory_files: list[Path] = []
    for rel in ("advisories.json", "security/advisories.json", ".well-known/csaf/provider-metadata.json"):
        p = ctx.repo_root / rel
        if p.is_file():
            advisory_files.append(p)
    for csaf_dir in (ctx.repo_root / ".well-known" / "csaf", ctx.repo_root / "csaf"):
        if csaf_dir.is_dir():
            with contextlib.suppress(OSError):
                advisory_files.extend(sorted(f for f in csaf_dir.glob("*.json") if f.is_file()))
    if not advisory_files:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No in-repo advisory metadata (CSAF / advisories.json / OSV) found; CWE hygiene cannot be observed.",
            remediation="No action required unless this project publishes its own advisories in the repository.",
            evidence_sources=[],
            confidence="high",
        )
    for f in advisory_files:
        with contextlib.suppress(OSError):
            if "cwe-" in f.read_text(encoding="utf-8", errors="replace").lower():
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"Advisory metadata references CWE identifiers ({f.name}) — ISO/IEC 30111 hygiene.",
                    remediation="Keep CWE (and CPE where applicable) identifiers on every published advisory.",
                    evidence_sources=[str(f.resolve())],
                    confidence="low",
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Advisory metadata present but no CWE identifier found; consumers cannot map the vulnerability class.",
        remediation="Add a CWE id (and CPE where applicable) to each published advisory (ISO/IEC 30111).",
        evidence_sources=[str(f.resolve()) for f in advisory_files[:3]],
        confidence="low",
    )


def eval_cisa_sbd_secrets_005(ctx: EvalContext) -> EvalOutcome:
    """CISA-SBD-SECRETS-005: default-credential / hardcoded-secret hygiene (composed evidence).

    CISA Secure by Design Pledge — default-passwords goal. Composes the existing secret-scan
    evidence produced for SAST-GITLEAKS-069 (gitleaks SARIF); it does NOT re-scan. PASS when a
    clean scan is evidenced, FAIL when the composed scan has findings, MANUAL_REVIEW when no
    secret-scan evidence is present to compose.
    """
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "sast" / "gitleaks.sarif.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No secret-scan evidence to compose (.oss-policy-kit/evidence/sast/gitleaks.sarif.json absent).",
            remediation="Run gitleaks and emit the SARIF evidence (see SAST-GITLEAKS-069); this control composes it.",
            evidence_sources=[],
            confidence="high",
        )
    with contextlib.suppress(OSError, UnicodeDecodeError, json.JSONDecodeError):
        data = json.loads(evidence.read_text(encoding="utf-8-sig"))
        if isinstance(data, dict):
            findings = 0
            for run in data.get("runs") or []:
                if isinstance(run, dict) and isinstance(run.get("results"), list):
                    findings += len(run["results"])
            if findings > 0:
                return EvalOutcome(
                    status=ControlStatus.FAIL,
                    reason=f"Composed secret-scan evidence reports {findings} secret finding(s) (default-cred risk).",
                    remediation="Rotate and remove the exposed secrets, then re-run gitleaks until the SARIF is clean.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                )
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Composed secret-scan evidence (gitleaks SARIF) reports no secret findings.",
                remediation="Keep secret scanning in CI so the evidence stays current each release.",
                evidence_sources=[str(evidence.resolve())],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Secret-scan evidence present but could not be parsed as gitleaks SARIF JSON.",
        remediation="Regenerate gitleaks.sarif.json with `gitleaks detect --report-format sarif`.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )
