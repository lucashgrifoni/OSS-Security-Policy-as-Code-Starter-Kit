# Positioning — what this kit is, and what it deliberately is not

This page exists because the OSS security tooling landscape has multiple overlapping projects (Scorecard, zizmor, poutine, OSV-Scanner, Harden-Runner, Trivy, Syft) and adopters reasonably ask: *"why use this kit if `<other tool>` already covers part of this?"*

The honest answer is below. This page deliberately does not market the kit; it draws boundaries.

---

## What this kit is

A **policy-as-code starter kit** that evaluates clone-visible OSS repository governance plus GitHub Actions / Azure Pipelines / AWS CodeBuild–CodePipeline signals against **composable profiles** with explicit trust grading.

Concretely:

- **36 bundled profiles** organized in ladders (`*-level-1` to `*-level-3`), release-hardening tracks, regulatory advisories (`cra-eu-*`), framework-aligned advisories (`osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`), IaC posture profiles, Kubernetes / container baselines, and a webhook receiver hardening profile.
- **125 controls** each labelled `deterministic` (clone-truth, no inference), `signal` (directional, not verified), or `evidence-backed` (consumes a structured evidence file with a schema). The grade flows into the `reports/1.0` JSON and Markdown output so consumers can reason about proof strength.
- **Evidence model with explicit trust levels** — `static_clone`, `api_collected`, `user_supplied`, `derived`, `heuristic_signal`, `manual_review`, `not_observable` — and per-control collection metadata (`collected_at`, `collection_method`).
- **Waiver registry** with owner, reason, and expiry, integrated with the gating decision.
- **SARIF 2.1.0 output** for Code Scanning ingestion.
- **A composite GitHub Action and a CLI** that adopters wire into a CI gate with `--fail-on {fail,degraded,never}`.

---

## What this kit deliberately is not

It is **not** a:

- **Universal SAST/SCA/secret scanner.** It does not replace Semgrep, CodeQL, Trivy, OSV-Scanner, or Gitleaks — it can **ingest** their output and treat findings as evidence.
- **GitHub Actions deep static analyzer.** It does not replace [zizmor](https://github.com/zizmorcore/zizmor) or [poutine](https://github.com/boostsecurityio/poutine) — those are specialized AST-level scanners with broader workflow coverage. The kit performs targeted policy checks (token permissions, unsafe triggers, action pinning, danger patterns) but is intentionally narrower.
- **Runtime egress enforcement.** It does not replace [Harden-Runner](https://github.com/step-security/harden-runner) or the GitHub native egress firewall announced for 2026 — it can recommend the presence of runtime egress controls but cannot enforce them.
- **OSPS certification engine.** It documents alignment with the OpenSSF OSPS Baseline; it does not certify conformance. When OpenSSF Scorecard v6 ships its `--format=osps` conformance output, that will be the canonical OSPS conformance surface.
- **SBOM generator.** The kit consumes SBOMs (via `BUILD-SBOM-QUAL-003` and the artifact-bound `*-SBOM-*` controls) but does not produce one for the target under evaluation. Use [Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy), or your build-platform's native SBOM output.
- **Compliance guarantee.** No control here equals legal conformance to any framework or regulation (NIST SSDF, EU CRA, SOC 2, ISO 27001, etc.). The kit produces **technical alignment evidence**; the regulatory determination remains with the adopter and their notified body / auditor.

---

## How the kit composes with adjacent tools

The kit's value is **composition**, not replacement. The intended pipeline:

```
SCANNERS                    KIT                    GATE DECISION
─────────                   ───                    ─────────────
Scorecard JSON       ─┐
zizmor SARIF         ─┤
poutine SARIF        ─┤    evaluate
OSV-Scanner SARIF    ─┼──> with profile  ──>      pass / degraded / fail
Semgrep SARIF        ─┤    + waivers
Trivy SARIF (image)  ─┤    + evidence
Sigstore bundles     ─┘
```

Specifically:

- **Scorecard** — already accepted as supplemental evidence via `--scorecard-json`. Threshold gated by `OSS-SCORECARD-001`.
- **Semgrep** — `SAST-SEMGREP-064` accepts the Semgrep SARIF and grades the run.
- **zizmor / poutine / OSV-Scanner / Gitleaks / Trivy** — planned as additional SARIF-ingesting adapters (tracked under v5.9 in the project roadmap).
- **Sigstore / cosign / `gh attestation verify`** — `PROV-VERIFY-061` consumes a `verification:` block in the evidence file containing the verification outcome (issuer, transparency-log inclusion, freshness).

When Scorecard v6 ships its OSPS conformance engine, the kit's `osps-baseline-1` profile is expected to become a thinner wrapper that hands the conformance verdict back to Scorecard for the OSPS-specific question and continues to own the multi-platform / multi-profile / waiver / release-hardening surface that Scorecard does not address.

---

## When to use this kit, and when not to

**Use this kit when:**

- You want a **policy-as-code gate** that returns `pass / degraded / fail` based on a composed profile, not a list of independent scanner findings.
- You need to gate on **multi-platform** posture (GitHub + Azure DevOps + AWS) with a single artifact.
- You care about **evidence provenance and trust grading** in the report — knowing whether a `pass` is `deterministic`, `signal`, or `evidence-backed` matters to you.
- You need a **waiver registry with owner + expiry** that the gate respects.
- You want **release-hardening ladders** (`*-release-hardening-1/2/3`) and **CRA-aligned advisories** (`cra-eu-ready-1`, `cra-eu-strict-1`).

**Use a different tool, or use them alongside, when:**

- You need deep AST-level analysis of GitHub Actions workflows → **zizmor** or **poutine**.
- You need reachability-aware SCA → **OSV-Scanner v2** (Java JAR, Go), or commercial (Endor Labs, Snyk).
- You need runtime egress enforcement → **Harden-Runner** today, GitHub native firewall when GA.
- You need an OSPS Baseline conformance verdict → **Scorecard v6** when shipped.
- You need an SBOM for a target → **Syft** or **Trivy SBOM**.

---

## The honest trade-off

The kit prioritizes **composition, explainability, and gate semantics** over scanner depth. It will not find a novel injection pattern in a workflow that zizmor finds, and it will not compute call-graph reachability for a CVE the way OSV-Scanner v2 will. What it does instead is produce a **single, traceable, profile-driven gate decision** with documented trust per control and a waiver mechanism that survives release reviews.

If your AppSec program already has scanner depth and is missing a coherent gate-and-evidence layer, this kit fits. If you are starting from zero and want the broadest possible scanner output, run zizmor / poutine / OSV-Scanner / Scorecard first; come back to this kit when you need the gate-and-policy layer to put on top.

---

## Where this page sits

This is the public positioning page. For the per-framework mapping (Scorecard, OSPS, OWASP CI/CD Top 10, SLSA, SSDF, S2C2F, CIS, AWS Well-Architected, Azure DevOps, EU CRA) see [`framework-alignment.md`](framework-alignment.md). For the trust model and assurance taxonomy see [`profiles/overview.md`](profiles/overview.md). For the full control list see [`controls-catalog.md`](controls-catalog.md).
