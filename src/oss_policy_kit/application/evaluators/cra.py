"""cra control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import (
    ControlStatus,
    EvalContext,
    EvalOutcome,
    _read_first_existing,
    _scan_readme_for_section,
    contextlib,
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
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(disclosure.read_text(encoding="utf-8"))
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
