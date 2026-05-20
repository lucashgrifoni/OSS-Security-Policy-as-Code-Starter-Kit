# ADR-014 — `oss-publish-readiness-1` profile + `PUBLISH-OIDC-*` family for Trusted Publishing detection

- **Status**: proposed (v6.0.0, carve-out aceito)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 2 (PR-9)
- **Related**: existing `PROV-VERIFY-061`, ADR-007 (`GH-PROV-023` promotion)

## Context

Trusted Publishing — package-registry uploads authenticated via GitHub OIDC instead of long-lived API tokens — has shipped or moved out of preview across the major registries through 2025–2026:

- **PyPI** Trusted Publishing GA mid-2024; ~17% of new project uploads use it (PyPA stats, 2026).
- **npm** Trusted Publishing GA July 2025.
- **RubyGems** Trusted Publishing GA 2025.
- **crates.io** Trusted Publishing GA early 2026.
- **GitLab CI** OIDC-to-package-registry GA January 2026.

For OSS adopters using the kit, "did you adopt Trusted Publishing?" is one of the highest-value questions the kit can answer from clone-visible workflow files. The signal is well-bounded: a workflow that publishes to a registry **without** a long-lived token (no `password:` / `NPM_TOKEN` / `TWINE_PASSWORD`), with `permissions: id-token: write`, and using the canonical action (`pypa/gh-action-pypi-publish@v1`, `npm publish --provenance`, etc.) is almost certainly using Trusted Publishing.

The kit does not have a profile that asks this question today. Adopters end up with a gap between "release-hardening: provenance is signed" (already covered by `GH-PROV-023` / `PROV-VERIFY-061`) and "release-hardening: publish itself is identity-bound, not token-bound" (not covered).

## Decision

Ship a new profile **`oss-publish-readiness-1`** with **three new signal-grade controls** named `PUBLISH-OIDC-001..003`:

| Control | Signal |
|---|---|
| `PUBLISH-OIDC-001` | Workflow with `permissions: id-token: write` plus a publish step targeting a known registry (PyPI / npm / RubyGems / crates / Maven Central). |
| `PUBLISH-OIDC-002` | `pypa/gh-action-pypi-publish@v1` invoked without `password:` input (or equivalent for npm / RubyGems / crates). |
| `PUBLISH-OIDC-003` | `npm publish --provenance` flag or the registry-equivalent provenance trigger. |

The profile also bundles existing controls relevant to publish-time hardening: `CI-PERM-001` (token permissions), `CI-PIN-001` (action pinning), `PROV-VERIFY-061` (extended via the planned `verification.source` enum — see roadmap).

`oss-publish-readiness-1` is `framework-aligned advisory` (`--fail-on degraded`) at GA. The intent is positive reinforcement for adopters that have already switched, plus a concrete remediation pointer for those who have not.

The profile is a **carve-out candidate** if the 2026-08-02 window pressures v6.0.0 — it can ship in v6.1.0 without blocking AI-security profiles.

## Alternatives considered

1. **Bundle Trusted Publishing checks into `github-release-hardening-1`.** Rejected: would silently change pass/fail outcomes for current adopters of the release-hardening ladder. The kit's compatibility contract treats profile control lists as part of the public surface.
2. **One mega-control `PUBLISH-OIDC-001` covering all three signals.** Rejected for the same reason ADR-004 rejected a single combined webhook control — trust grading collapses.
3. **Wait until all major registries hit GA, then ship a stricter profile.** Rejected: all five target registries have shipped Trusted Publishing GA already; the gap is detection, not registry support.

## Consequences

**Positive**

- Adopters publishing to PyPI / npm / RubyGems / crates / Maven gain a concrete checklist they can run in CI.
- The kit's catalog gains a "supply chain at publish time" dimension that complements its existing "supply chain at build time" coverage (`PROV-VERIFY-061`, SBOM controls).
- Aligns the kit with the broader 2026 industry shift away from long-lived registry tokens.

**Negative / cost**

- Three new controls and one new profile. Test cost: hardened + vulnerable fixtures with realistic publish workflows.
- Some signals are heuristic (publishing-step detection across multiple registries); risk of false negatives if an adopter uses an unusual publish path.

**Mitigations**

- Profile is advisory at GA; promote later based on adopter signal.
- Profile README documents each control's detection heuristic and known limitations.
- Each control ships as `signal` grade explicitly; promotion to `evidence-backed` is a future task if Trusted Publishing platforms expose attestation evidence files the kit can consume.

## References

- v6.0.0 execution plan §4.5 PR-9
- v6.0.0 proposal §3 V6-06
- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/)
- [State of Package Registry Provenance 2026](https://zenn.dev/sqer/articles/e4df3d397f5651?locale=en)
- ADR-007 (`GH-PROV-023` promotion) — related publish-time provenance work
