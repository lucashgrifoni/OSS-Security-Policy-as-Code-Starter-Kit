# Positioning — what this kit is, and what it deliberately is not

This page exists because the OSS security tooling landscape has multiple overlapping projects (Scorecard, zizmor, poutine, OSV-Scanner, Harden-Runner, Trivy, Syft) and adopters reasonably ask: *"why use this kit if `<other tool>` already covers part of this?"*

The honest answer is below. This page deliberately does not market the kit; it draws boundaries. Everything described here as **shipped** is what the **v5.9.x build** actually does today. Items planned for v6.0.0 are listed at the end under [Roadmap (v6.0.0 — in development)](#roadmap-v600--in-development) and are explicitly **not** present in the current build.

---

## What this kit is

A **policy-as-code starter kit** that evaluates clone-visible OSS repository governance plus GitHub Actions / Azure Pipelines / AWS CodeBuild–CodePipeline / GitLab CI signals against **composable profiles** with explicit trust grading.

Concretely, in v5.9.x:

- **38 bundled profiles** organized in ladders (`*-level-1` to `*-level-3`), release-hardening tracks (`*-release-hardening-1/2/3`), regulatory advisories (`cra-eu-ready-1`, `cra-eu-strict-1`, `cra-eu-reporting-1`), framework-aligned advisories (`osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`), IaC posture profiles (Terraform, CloudFormation, Pulumi, Bicep), Kubernetes / container baselines, webhook hardening (`webhook-security-1`), an AppSec SAST/SCA bundle (`appsec-sast-sca-1`), and a first GitLab CI baseline (`gitlab-level-1`).
- **136 controls** each labelled `deterministic` (clone-truth, no inference), `signal` (directional, not verified), or `evidence-backed` (consumes a structured evidence file with a schema). The grade flows into the `reports/1.0` JSON and Markdown output so consumers can reason about proof strength.
- **Evidence model with explicit trust levels** — `static_clone`, `api_collected`, `user_supplied`, `derived`, `heuristic_signal`, `manual_review`, `not_observable` — and per-control collection metadata (`collected_at`, `collection_method`).
- **Waiver registry** with owner, reason, and expiry, integrated with the gating decision.
- **SARIF 2.1.0 output** for Code Scanning ingestion and **CycloneDX VEX 1.6** emission via `emit-vex`.
- **A composite GitHub Action and a CLI** that adopters wire into a CI gate with `--fail-on {none,fail,degraded}`.

---

## What this kit deliberately is not

It is **not** a:

- **Universal SAST/SCA/secret scanner.** It does not replace Semgrep, CodeQL, Trivy, OSV-Scanner, or Gitleaks — it can **ingest SARIF** from several of them (see *How the kit composes* below) and treat findings as evidence.
- **GitHub Actions deep static analyzer.** It does not replace [zizmor](https://github.com/zizmorcore/zizmor) or [poutine](https://github.com/boostsecurityio/poutine) — those are specialized AST-level scanners with broader workflow coverage. The kit performs targeted policy checks (token permissions, unsafe triggers, action pinning, danger patterns) but is intentionally narrower; it does ingest their SARIF as evidence.
- **Runtime egress enforcement.** It does not replace [Harden-Runner](https://github.com/step-security/harden-runner) or GitHub's roadmapped native egress firewall after that feature becomes available. GitHub's March 26, 2026 Actions security roadmap targets public preview for the firewall 6-9 months after publication and does not state a GA date. The current build does not ship a dedicated Harden-Runner control; that work is tracked under the v6.0.0 roadmap.
- **OSPS certification engine.** It documents alignment with the OpenSSF OSPS Baseline; it does not certify conformance. When OpenSSF Scorecard v6 ships its `--format=osps` conformance output, that will be the canonical OSPS conformance surface.
- **SBOM generator.** The kit consumes SBOMs (via `BUILD-SBOM-QUAL-003` and the artifact-bound `*-SBOM-*` controls) but does not produce one for the target under evaluation. Use [Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy), or your build-platform's native SBOM output.
- **AIBOM generator or AI-security profile suite.** The current build does not detect or grade AIBOMs and does not ship an LLM-oriented profile. AI-security coverage (NIST SP 800-218A, EU AI Act Article 11) is tracked under the v6.0.0 roadmap and is not present today.
- **ASPM platform.** It does not replace [Apiiro](https://apiiro.com/product/aspm/), ArmorCode, Cycode, Snyk AppRisk, or other ASPM SaaS products that triage across sources, correlate runtime telemetry, and prioritize risk at portfolio scale. The kit is a **local-first emit layer**; ASPM platforms can ingest its SARIF and JSON reports today.
- **Evidence store.** It does not replace [Chainloop](https://chainloop.dev/) or [GUAC](https://guac.sh/). Those are server-side evidence platforms that aggregate attestations and policy verdicts across pipelines; this kit runs locally per commit and does not persist evidence across releases.
- **Compliance guarantee.** No control here equals legal conformance to any framework or regulation (NIST SSDF, NIST 800-218A, EU CRA, EU AI Act, SOC 2, ISO 27001, etc.). The kit produces **technical alignment evidence**; the regulatory determination, conformity assessment, and CE-marking decisions remain with the adopter and their notified body / auditor.

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
Gitleaks SARIF       ─┤    + evidence
Sigstore bundles     ─┘
```

Specifically, in v5.9.x:

- **Scorecard** — accepted as supplemental evidence via `--scorecard-json`. Threshold gated by `OSS-SCORECARD-001`.
- **Semgrep** — `SAST-SEMGREP-064` accepts a Semgrep SARIF and grades the run.
- **zizmor** — `SAST-ZIZMOR-066` parses zizmor SARIF (counts severities, surfaces presence/absence).
- **poutine** — `SAST-POUTINE-067` parses poutine SARIF analogously.
- **OSV-Scanner** — `SAST-OSV-068` parses OSV-Scanner SARIF for dependency CVE signals.
- **Gitleaks** — `SAST-GITLEAKS-069` parses Gitleaks SARIF for secret findings.
- **Sigstore / cosign / `gh attestation verify`** — `PROV-VERIFY-061` consumes a `verification:` block in the per-artifact provenance evidence file. The schema today defines: `method` (`gh-attestation-verify` | `cosign-verify-bundle` | `cosign-verify-attestation` | `in-toto-verify` | `other`), `verified_at` (date-time), `transparency_log_inclusion` (boolean), and the optional fields `issuer`, `subject_alternative_name`, `bundle_digest`, `tool_version`. A finer-grained "where did the verification come from" enum is roadmap, not current.

**Not currently shipped** as a dedicated adapter: Trivy SARIF ingestion. Trivy is referenced as an external adjacent tool (image scanning, SBOM emission) and is recommended for those workflows, but no `SAST-TRIVY-*` evaluator exists in v5.9.x.

When Scorecard v6 ships its OSPS conformance engine, the kit's `osps-baseline-1` profile is expected to become a thinner wrapper that hands the conformance verdict back to Scorecard for the OSPS-specific question and continues to own the multi-platform / multi-profile / waiver / release-hardening surface that Scorecard does not address.

---

## Where this kit sits in the 2026 AppSec stack

An [Invicti landing page for Gartner's 2025 ASPM Innovation Insight](https://www.invicti.com/clp/gartner-aspm-report) quotes Gartner's projection that **by 2027, ~80% of organizations in regulated verticals using AppSec testing will incorporate some form of ASPM** (up from ~29% today). Vendors are consolidating portfolios — Apiiro, ArmorCode, Cycode, CrowdStrike, Snyk, and Synopsys are the most cited.

This kit is **not** an ASPM. It is a local-first emit layer that ASPM SaaS platforms and evidence stores can ingest. Where it fits:

| Layer | Examples | What it does | Where this kit fits |
|---|---|---|---|
| **SAST** | Semgrep, CodeQL, SonarQube, Checkmarx | Source-code scanning | Consumes Semgrep SARIF as evidence (`SAST-SEMGREP-064`); does not replace |
| **SCA** | OSV-Scanner, Trivy, Snyk Open Source, Dependabot | Dependency CVE detection | Consumes OSV-Scanner SARIF as evidence (`SAST-OSV-068`); does not replace |
| **CI/CD hardening** | zizmor, poutine, Harden-Runner | Workflow analysis + runtime egress | Ingests zizmor and poutine SARIF (`SAST-ZIZMOR-066`, `SAST-POUTINE-067`) and performs targeted overlapping checks; does not replace deep AST analysis or runtime egress |
| **Secrets** | Gitleaks, TruffleHog | Secret detection | Consumes Gitleaks SARIF as evidence (`SAST-GITLEAKS-069`); does not replace |
| **Evidence store** | [Chainloop](https://chainloop.dev/), [GUAC](https://guac.sh/) | Server-side aggregation + query of attestations | Adopters can consume the kit's SARIF / JSON reports; the kit does not ship a dedicated Chainloop or GUAC exporter today |
| **ASPM** | Apiiro, ArmorCode, Cycode, Snyk AppRisk | Cross-source triage + runtime correlation + portfolio prioritization | Adopters can ingest the kit's SARIF and JSON reports; the kit does not triage or prioritize at portfolio scale |
| **Runtime IAST / RASP** | Datadog AAP, Contrast | In-process runtime detection and blocking | Out of scope (architectural) |
| **Policy-as-code gate** *(this kit)* | OSS Security Policy as Code Starter Kit | Profile-driven `pass / degraded / fail` decision with explicit trust grading and waiver discipline | **This is the layer the kit owns** |

The kit answers: *"given this commit, this profile, and this evidence, does the gate pass or fail, and how trustworthy is each control's verdict?"* — without claiming runtime coverage, triage across organizational portfolios, or evidence persistence across releases.

---

## On scanner trust and defense in depth

Scanner output is not inherently trustworthy. The 2026 supply-chain attack against a major scanner distribution (publicly reported in March 2026, see references at the end) is a reminder that if a scanner itself is tampered with, downstream gates that treat its output as ground truth inherit the compromise.

This kit's posture is **policy gate as defense in depth**, not scanner replacement. Specifically:

- The kit consumes scanner SARIF as **evidence**, not as a final verdict. Evidence flows through a control with an `assurance` label (`signal` or `evidence-backed`).
- A scanner-only verdict can be downgraded to `signal` (or treated as missing) when the expected evidence package — for example, a per-artifact provenance evidence file consumed by `PROV-VERIFY-061` — is absent.
- The kit's profile-driven gate independently enforces clone-visible controls (token permissions, branch protection, signed releases, SBOM presence, waiver hygiene, etc.) that do not depend on any external scanner.
- For high-stakes profiles (release-hardening ladders, CRA advisories), the kit deliberately prefers evidence-backed controls (for example, `PROV-VERIFY-061` consuming a `verification:` block recorded after `gh attestation verify` or `cosign verify-bundle`) over scanner output alone.

A gate that evaluates multiple independent evidence sources (clone-truth, scanner SARIF, attestation verification, waiver registry) survives the compromise of any single source. That is the design intent and the reason `--fail-on degraded` exists as a separate posture from `--fail-on fail`.

References for the 2026 incident and broader scanner-trust context: [GitHub Advisory Database GHSA-69fq-xp46-6x23](https://github.com/advisories/GHSA-69fq-xp46-6x23), [Aqua Security incident disclosure](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/), [Chainloop post-mortem](https://chainloop.dev/blog/trivy-supply-chain-attack-best-practices/), [Resilience-Sec analysis](https://www.resilience-sec.com/post/the-trivy-supply-chain-attack-a-wake-up-call-for-every-organization-running-ci-cd-pipelines).

---

## When to use this kit, and when not to

**Use this kit when:**

- You want a **policy-as-code gate** that returns `pass / degraded / fail` based on a composed profile, not a list of independent scanner findings.
- You need to gate on **multi-platform** posture (GitHub + Azure DevOps + AWS + GitLab) with a single artifact.
- You care about **evidence provenance and trust grading** in the report — knowing whether a `pass` is `deterministic`, `signal`, or `evidence-backed` matters to you.
- You need a **waiver registry with owner + expiry** that the gate respects.
- You want **release-hardening ladders** (`*-release-hardening-1/2/3`) and **CRA-aligned advisories** (`cra-eu-ready-1`, `cra-eu-strict-1`).
- You need a **local-first emit layer** that ASPM platforms or evidence stores can ingest, without standing up server-side infrastructure first.

**Use a different tool, or use them alongside, when:**

- You need deep AST-level analysis of GitHub Actions workflows → **zizmor** or **poutine** (the kit ingests their SARIF; it does not duplicate the analysis).
- You need reachability-aware SCA → **OSV-Scanner v2** (Java JAR, Go), or commercial (Endor Labs, Snyk).
- You need runtime egress enforcement → **Harden-Runner** today, or GitHub's native egress firewall after it becomes available. As of GitHub's [March 26, 2026 Actions security roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/), the firewall is targeted for public preview 6-9 months after publication; no GA date is stated.
- You need workflow lockfiles or native scoped secrets → GitHub's [Actions 2026 security roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) tracks those primitives; the kit does not currently emit controls that depend on them.
- You need an OSPS Baseline conformance verdict → **Scorecard v6** when shipped with `--format=osps`.
- You need an SBOM (or AIBOM) for a target → **Syft**, **Trivy SBOM**, or build-platform-native emitters.
- You need **cross-source triage and portfolio prioritization** across many repos plus runtime telemetry → **ASPM SaaS** (Apiiro, ArmorCode, Cycode, Snyk AppRisk, etc.). The kit emits the evidence; the ASPM correlates and prioritizes.
- You need **server-side evidence storage and cross-artifact query** → **Chainloop** or **GUAC**. The kit emits per-commit; those platforms persist and aggregate.
- You need **runtime IAST or RASP** → out of scope for this kit (architectural). Datadog AAP, Contrast, and similar are the canonical options.
- You need a **conformity assessment** for CE-marking under EU CRA or EU AI Act → the kit produces technical alignment evidence; the assessment itself remains with a notified body.

---

## The honest trade-off

The kit prioritizes **composition, explainability, and gate semantics** over scanner depth, evidence persistence, or portfolio triage. It will not find a novel injection pattern in a workflow that zizmor finds, it will not compute call-graph reachability for a CVE the way OSV-Scanner v2 will, it will not store evidence across releases the way Chainloop does, and it will not triage cross-repo risk the way an ASPM SaaS does. What it does instead is produce a **single, traceable, profile-driven gate decision** with documented trust per control and a waiver mechanism that survives release reviews — at a price point of `pip install` and one composite Action.

If your AppSec program already has scanner depth, evidence storage, and ASPM coverage, this kit fits as the **policy gate layer** on top. If you are starting from zero and want the broadest possible scanner output, run zizmor / poutine / OSV-Scanner / Scorecard first; come back to this kit when you need the gate-and-policy layer to put on top.

---

## Roadmap (v6.0.0 — in development)

The following items are **planned for v6.0.0** and are explicitly **not** present in the current v5.9.x build. They are listed here so adopters can see direction without confusing roadmap with shipped capability.

- **AI security profiles**: `appsec-llm-ssdf-218a-1` (NIST SP 800-218A advisory) and `cra-eu-ai-act-art11-1` (EU AI Act Article 11 advisory), with a small `LLM-*` control family and an `AIBOM-PRESENT-001` signal.
- **Webhook hardening expansion**: `webhook-security-2` profile and a `SEC-WEBHOOK-*` family.
- **Source-track SLSA profile**: `slsa-source-l1-1` and a `SLSA-SRC-*` family.
- **Additional S2C2F levels**: `s2c2f-l2-1` and `s2c2f-l3-1` (recomposition of existing controls).
- **OSS publish readiness**: `oss-publish-readiness-1` profile and a `PUBLISH-OIDC-*` family covering Trusted Publishing detection.
- **Harden-Runner control**: `GH-EGRESS-HRN-001` advisory presence check.
- **New CLI subcommands**: `emit-insights` (OpenSSF Security Insights 1.0 YAML) and `export-evidence --format chainloop` (experimental).
- **New report contract**: `reports/2.0` aligned to a five-state vocabulary (`PASS / FAIL / UNKNOWN / NOT_APPLICABLE / ATTESTED`). `reports/1.0` remains available during the v6.0.x line under `--report-json-contract=1.0`.
- **`PROV-VERIFY-061` extension**: an optional `verification.source` enum (`npm-trusted-publishing`, `pypi-trusted-publishing`, `rubygems-trusted-publishing`, `crates-trusted-publishing`, `github-attestation`, `sigstore-bundle`, `manual`) to record where a verification came from. Schema is unchanged in v5.9.x.
- **Doc updates**: `framework-alignment.md` will gain columns for NIST 218A, EU AI Act, and OpenSSF Insights; an `eu-ai-act-readiness.md` page will be added with explicit caveats about conformity assessment being out of scope.

Target window: v6.0.0 GA before **2026-08-02** (EU AI Act Article 11 effective date), so the `cra-eu-ai-act-art11-1` advisory ships before adopters need it.

---

## Where this page sits

This is the public positioning page. For the per-framework mapping (Scorecard, OSPS, OWASP CI/CD Top 10, SLSA, SSDF, S2C2F, CIS, AWS Well-Architected, Azure DevOps, EU CRA) see [`framework-alignment.md`](framework-alignment.md). For the trust model and assurance taxonomy see [`profiles/overview.md`](profiles/overview.md). For the full control list see [`controls-catalog.md`](controls-catalog.md).
