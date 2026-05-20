# ADR-025 - GitHub Actions 2026, distroless, scanner integrity, Rekor v2, CycloneDX 1.7

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-24 / PR-26 / PR-29 / PR-30 / PR-31 / PR-32
- **Related**: ADR-007 (`GH-PROV-023`), `PROV-VERIFY-061`, `BUILD-SBOM-QUAL-003`

## Context

Several smaller 2026 ecosystem signals are individually low-risk but worth a
clone-visible check: GitHub Actions native egress firewall and workflow lockfile
(2026 roadmap, preview), distroless/minimal base images, post-Trivy scanner
action SHA pinning, Sigstore Rekor v2 tile-based inclusion, and CycloneDX 1.7 /
ML-BOM. Grouping them in one ADR keeps the decision record proportionate.

## Decision

- **PR-29** `GH-EGRESS-NATIVE-001` (signal) — native egress firewall policy in a
  workflow; parallel to `GH-EGRESS-HRN-001` (Harden-Runner).
- **PR-30** `GH-WF-LOCKFILE-001` (signal) — workflow lockfile present.
- **PR-31** `CONT-DISTROLESS-001` (signal) — final base image is
  distroless / Chainguard / Wolfi / scratch.
- **PR-32** `SCANNER-INTEGRITY-001` (signal) — scanner actions pinned by full SHA
  (Trivy 2026-03 supply-chain attack lesson).
- **PR-24** extend the `verification.source` enum in the three provenance evidence
  schemas with `rekor-v2-tile-inclusion`; no new control.
- **PR-26** CycloneDX 1.7 is already recognised by the SBOM version detector and
  passes the BSI TR-03183-2 v2.1.0 gate (1.6+); `AIBOM-PRESENT-001` now also
  recognises a repo-level CycloneDX ML-BOM via the `machine-learning-model`
  marker. No change to the BSI dict shape (preserves the contract).

`GH-EGRESS-NATIVE-001`, `GH-WF-LOCKFILE-001`, and `SCANNER-INTEGRITY-001` are
bundled into the advisory `oss-publish-readiness-1` (not the strict
`github-release-hardening-*` tiers, which contract for zero manual-review on a
hardened repo — these preview-feature signals would always be manual-review
there). `CONT-DISTROLESS-001` is bundled into `container-baseline-1`.

## Alternatives considered

1. **One ADR per signal.** Rejected — these are small, related ecosystem-tracking
   signals; a combined record is proportionate.
2. **Add a TLP key to the BSI validation dict.** Rejected — it would break the
   existing exact-shape contract test; TLP is documented instead and can become a
   separate optional check later.

## Consequences

- The kit tracks 2026 platform features without overclaiming GA status.
- Rekor v2 verifications can be labelled distinctly from v1.
- Scanner integrity becomes a first-class publish-trust signal post-Trivy.

## References

- GitHub Actions 2026 security roadmap; Sigstore Rekor v2 GA; CycloneDX v1.7
- Chainguard / Wolfi; Trivy supply-chain attack (2026-03)
- v6.0.0 Cycle 2 plan, PR-24/26/29/30/31/32
