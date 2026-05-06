# GitHub profiles

Pure GitHub family in this kit: **six** ids (`github-level-1..3`, `github-release-hardening-1..3`). The legacy alias `github-release-hardening` was **removed in v5.0.0** — use the canonical `github-release-hardening-1`. See [docs/v5.0.0-migration-guide.md](../v5.0.0-migration-guide.md).

## Usage classes

- **Daily baseline**: `github-level-1`, `github-level-2`, `github-release-hardening-1`, `github-release-hardening-2`.
- **Extreme hard-gate**: `github-level-3`, `github-release-hardening-3`.

## What each ladder means

- **level-1**: clone-visible baseline (governance files + workflow hygiene).
- **level-2**: stricter GitHub workflow posture (still signal-heavy in some areas).
- **level-3**: hard-gate with GitHub platform evidence (`rulesets`, environments, secret scanning), org MFA posture evidence, SBOM quality, and evidence freshness.

## Release ladder

- **release-hardening-1**: level-1 plus branch-protection/evidence discipline.
- **release-hardening-2**: level-2 style strictness with release-oriented evidence expectations.
- **release-hardening-3**: strictest GitHub release posture in this kit (extreme reference profile).

## `github-level-3` vs `github-release-hardening-3` — when to use which

Both are extreme hard-gate profiles for the GitHub family. They overlap heavily, but the operational fit differs:

- Use **`github-level-3`** for **repository-service hardening** — a steady-state gate that watches workflow posture, supply-chain hygiene, and platform evidence (`rulesets`, environment protection, secret scanning, org MFA). 4 of the 33 controls are evidence-backed; the rest are deterministic or signal.
- Use **`github-release-hardening-3`** when the bar of the run is the **release event itself** — branch protection evidence, merge queue, freshness of the evidence pack, and release-time discipline are first-class. 5 of the 32 controls are evidence-backed; the release-track controls (`*-REL-*`, `BUILD-SBOM-QUAL-*`, `GH-MERGEQ-*`) are present here and not in `github-level-3`.

Operational rule of thumb:

- For PR-time gates and steady-state CI on GitHub: `github-level-3`.
- For tag/release-time gates and post-merge release discipline on GitHub: `github-release-hardening-3`.
- Without `collect-evidence --platform github` (or hand-filled GitHub evidence files matching the bundled schemas), expect `manual-review-required` on the platform-evidence rows in either profile. That is honest — see [L3 evidence-heavy caveat](overview.md#l3-evidence-heavy-caveat-read-before-wiring-a-hard-gate).

## Practical maturity and fixture limits

GitHub is the most mature path in this kit (collector support, schema coverage, and profile ergonomics).  
Still, the hardened fixture is **not** expected to be universally green across all GitHub profiles:

- 2026-04-22 validation recorded fixture failures on `github-level-2` and `github-release-hardening-2` (`GH-PROV-023` / `SEC-SECRETS-050`).
- That reflects fixture representativity limits, not an automatic defect in those profiles.

## Legacy alias handling (v4.x → v5.0.0)

In v4.x, `github-release-hardening` was a supported alias for `github-release-hardening-1` and emitted a deprecation warning.

**v5.0.0 removes the alias.** Passing `--profile github-release-hardening` exits with code `2` and the migration message:

> Profile id 'github-release-hardening' was removed in v5.0.0. The canonical profile is 'github-release-hardening-1' (same control set). Update your scripts and CI workflows. See docs/v5.0.0-migration-guide.md.

Update CI workflows, scripts, and dashboards to use `github-release-hardening-1`. The control list is identical; only the id changed.

## See also

- [How `recommend-profile` reads `.oss-policy-kit/evidence/`](overview.md#how-recommend-profile-reads-oss-policy-kitevidence) — why a synthetic evidence pack alone can produce a `*-release-hardening-2` suggestion, and how to read it honestly.
