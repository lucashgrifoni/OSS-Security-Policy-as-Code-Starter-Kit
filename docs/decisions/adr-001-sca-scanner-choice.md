# ADR-001 — SCA scanner integration: OSV-Scanner v2 primary, Trivy / Gitleaks complementary

- **Status**: accepted
- **Date**: 2026-05-16
- **Context window**: planning Fase 4 / v5.9.0
- **Supersedes**: implicit choice in earlier roadmap planning that listed Trivy first

## Context

The Fase 4 roadmap in `STATUS-2026-05-11.md` originally listed:

- F4-01 Trivy adapter (`SAST-TRIVY-001..003`)
- F4-02 Gitleaks adapter (`SAST-GITLEAKS-001`)
- F4-03 ADR Trivy vs Grype for SCA

Between that plan and Q2 2026, two market signals changed the calculation:

1. **OSV-Scanner v2** (Google, Apr 2025) added reachability analysis for Java JAR and Go. Independent assessments report 70–90 % SCA noise reduction when reachability is enabled. The OSV database remains the broadest free vulnerability source.
2. **Trivy** maintained strong container scanning and IaC coverage but its SCA reachability story is weaker — Trivy's plugin model exposes scanners; it does not itself perform call-graph reachability.

The kit's role is policy-as-code, not scanner depth. Whichever scanner we adopt as the SCA primary, the kit will ingest its SARIF, not re-implement its detection. The choice is about which evidence is most defensible for adopters.

## Decision

**Adopt OSV-Scanner v2 as the SCA primary** in Fase 4 / v5.9.0. Trivy and Grype remain candidates for the **container scanning** adapter slot, not the SCA slot. Gitleaks remains the **secret scanning** adapter (separate category, not in this comparison).

Concretely:

| Slot | Tool | Control | Rationale |
|---|---|---|---|
| SCA SARIF | **OSV-Scanner v2** | `SAST-OSV-069` | Reachability-aware in JAR/Go; OSV vulnerability database; Google maintenance; free; native SARIF. |
| GitHub Actions SARIF | **zizmor** | `SAST-ZIZMOR-067` | Broad coverage; AST-level analysis; complements the kit's existing CI/CD checks. |
| GitHub Actions + GitLab CI SARIF | **poutine** | `SAST-POUTINE-068` | Conservative reporting; native GitLab CI support, which the kit currently does not provide; complements zizmor. |
| Secrets SARIF | **Gitleaks** | `SAST-GITLEAKS-070` | De facto OSS secret scanner; native SARIF; explicit allowlist semantics. |
| Container scanning (deferred) | Trivy or Grype | TBD post v5.9.0 | Out of scope for Fase 4; revisit when container hardening profiles need a scanner-evidence ingestion path. |

The kit will accept SARIF from each tool, count findings by severity, and surface a result in line with the existing `SAST-SEMGREP-064` pattern. The adopter chooses which adapters to wire; profiles bundle the choice.

## Alternatives considered

### Trivy as SCA primary

Pros: well known; broad coverage (SCA + container + IaC + secrets); single-binary install; strong CI/CD integrations.

Cons: SCA reachability is not native to Trivy. Its SCA accuracy comes mostly from accurate manifest parsing, which OSV-Scanner v2 also has, plus reachability that Trivy lacks. Recommending Trivy as SCA primary in 2026 means recommending the higher-noise option.

Verdict: keep Trivy in the kit's surface area as a **container scanning** option (post-v5.9.0), not as the SCA primary.

### Grype as SCA primary

Pros: solid SBOM-based SCA; Anchore Syft integration; native SBOM input (good fit for SBOM-first workflows); decent reachability work in progress.

Cons: smaller institutional backing than OSV-Scanner v2; reachability is not yet at OSV-Scanner v2's level for the languages we care about most.

Verdict: defer. May become the container-image scanning option if Trivy positioning shifts.

### Snyk OSS

Pros: strong reachability; well-known.

Cons: not OSS for the parts that matter (registration / API throttling / commercial dependency); brand-tied to a single vendor. Not a stable foundation for a vendor-neutral OSS starter kit.

Verdict: rejected. The kit may accept Snyk SARIF as evidence in a separate adapter if an adopter requests it, but it will not be the recommended path.

### Multiple SCA scanners simultaneously

Pros: defense-in-depth; cross-validation.

Cons: each new adapter is maintenance surface, separate evidence schema, separate test fixtures, and another control id that profiles must reason about. The kit's existing pattern is "one adapter per scanner family"; multiplying SCA scanners would invite control-count inflation without proportional value.

Verdict: rejected for v5.9.0. A future RFC may revisit this if reachability landscape diverges sharply between OSV-Scanner and a peer.

## Consequences

- The Fase 4 roadmap is reorganized: `SAST-OSV-069` replaces the original `SAST-TRIVY-001..003` slot.
- Trivy is **not** dropped from the project's mental model — it remains a candidate for a future container scanning adapter, separate from SCA.
- The kit's `framework-alignment.md` will document this choice in the OWASP CICD-SEC-3 / OpenSSF Scorecard Vulnerabilities / NIST SSDF RV.1 mappings once the adapter ships.
- New evidence schemas: `evidence-sca-scan.schema.json` (OSV-Scanner v2 SARIF), `evidence-actions-sast.schema.json` (zizmor / poutine SARIF), `evidence-secrets-scan.schema.json` (Gitleaks SARIF). All packaged + mirror.
- Profiles that reference these controls (TBD when controls are added) must consume the SARIF evidence files from `.oss-policy-kit/evidence/sast/` or equivalent — directory convention to be decided when the first adapter lands.

## Reversibility

This ADR is reversible until v5.9.0 ships externally. After v5.9.0 release the choice carries:

- Public control IDs (`SAST-OSV-069`, etc.) — irrevocable without deprecation cycle.
- Evidence schemas (`disclosure-policy/v1`-style schema_versions) — additive change is fine; breaking change requires major release.
- Adopter integrations wiring SARIF — adopter-visible coupling.

The decision is graded **medium-reversibility** for v5.9.0 and **low-reversibility** post-release.

## References

- [OSV-Scanner V2 announcement (Google, 2025)](https://blog.google/security/announcing-osv-scanner-v2-vulnerability/)
- [OSV-Scanner repo](https://github.com/google/osv-scanner)
- [Trivy repo](https://github.com/aquasecurity/trivy)
- [Grype repo](https://github.com/anchore/grype)
- [Gitleaks repo](https://github.com/gitleaks/gitleaks)
- [zizmor repo](https://github.com/zizmorcore/zizmor)
- [poutine repo](https://github.com/boostsecurityio/poutine)
- Arxiv 2026: *Unpacking Security Scanners for GitHub Actions Workflows*
- Project-local planning artifact (gitignored, not part of the public repository).
