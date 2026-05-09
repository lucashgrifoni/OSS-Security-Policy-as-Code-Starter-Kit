# Framework alignment

This page maps the **65 controls** and **20 profiles** bundled with v5.0.0 to the AppSec /
DevSecOps frameworks operators most often have to defend against. It is a **mapping**, not a
**certification claim**. The kit does not assert conformance to any of these frameworks; it
documents how its honest signals align with each framework's expectations so operators can
navigate from a framework requirement back to a concrete control or evidence file.

> **Honesty contract**: A `pass` on a control here does not equal a `pass` against the framework
> requirement it maps to. Several frameworks include items the kit deliberately does **not**
> evaluate from a clone (live runtime behavior, organization-wide policy, two-party review on
> every commit, etc.). Coverage is documented per framework; gaps are documented explicitly.

The authoritative source for control identifiers is
[`src/oss_policy_kit/data/controls/catalog.yaml`](../src/oss_policy_kit/data/controls/catalog.yaml).
The authoritative profile lists are under [`src/oss_policy_kit/data/profiles/`](../src/oss_policy_kit/data/profiles/).
For one-page reference of every control see [controls-catalog.md](controls-catalog.md). For the
specific evidence each platform collector retrieves see [collector-parity.md](collector-parity.md).

## Frameworks covered

The mapping below covers nine industry references that overlap with the kit's scope (OSS
governance, CI/CD security, supply-chain assurance). Frameworks the kit deliberately does not
attempt to map (because they are out of scope, not because they are unimportant) are listed at
the end under **Out of scope**.

| Framework | Type | Year | Why it appears here |
|---|---|---|---|
| OpenSSF Scorecard v4 | Automated checks | 2020+ rolling | Industry-standard automated baseline for OSS repos; the kit accepts Scorecard JSON as supplemental evidence |
| OpenSSF OSPS Baseline | Maturity baseline | 2024+ | Open Source Project Security baseline aimed at maintainers; aligns with `*-level-1`/`-2` |
| OWASP CI/CD Top 10 | Threat list | 2022 | Concrete CI/CD attacker-vs-defender model; aligns with the kit's CI/CD focus |
| SLSA v1.0 (Build track) | Supply-chain levels | 2023 | Build-platform integrity ladder (L1/L2/L3); aligns with `*-release-hardening-*` |
| NIST SSDF SP 800-218 | Process framework | 2022 (rev 1.1) | Federal-aligned secure SDLC reference; broader than CI/CD |
| Microsoft S2C2F | OSS consumption framework | 2022+ | 8 practices for ingesting upstream OSS safely; aligns with dependency hygiene |
| CIS Software Supply Chain Security Benchmark | Hardening guide | 2022 | CIS-format benchmark for source/build/deps/artifacts/deploy |
| AWS Well-Architected — Security Pillar (DevOps) | Cloud reference architecture | rolling | AWS-side practices for `aws-*` profiles |
| Azure DevOps Security Best Practices | Vendor guidance | rolling | Microsoft-side practices for `azure-*` profiles |

The summaries below use the **stated** framework intent at the time of writing (training cutoff
January 2026). Operators should always consult the upstream framework page for the canonical
text.

## How to read this doc

For each framework the table maps the framework requirement to the kit control(s) that exercise
it, plus a coverage label:

- **YES** — at least one bundled control exercises this requirement deterministically or via
  evidence-backed projection; PASS is meaningful proof.
- **PARTIAL** — a control exists but is `signal` grade (directional, not verified) or only a
  subset of the requirement.
- **GAP** — no bundled control exercises this requirement today. Either intentional (out of
  scope) or registered as future work in [profiles/deferred-followups.md](profiles/deferred-followups.md).
- **OUT** — outside the kit's scope by design (not a gap).

## OpenSSF Scorecard v4 (~19 checks)

| Scorecard check | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| Binary-Artifacts | (none) | OUT | The kit focuses on policy / CI signals, not committed-binary scans. Scorecard JSON can be passed via `--scorecard-json` to surface this externally. |
| Branch-Protection | `PLAT-BRPROT-015` | YES | Evidence-backed via `branch-protection.json`; collected by `collect-evidence --platform github`. |
| CI-Tests | `CI-WF-005`, `AZ-PIPE-027`, `AWS-CI-037` | PARTIAL | We confirm CI files exist; Scorecard separately checks test-run history, which is platform-side. |
| CII-Best-Practices | (none) | OUT | The OpenSSF Best Practices Badge is a separate program; not modeled here. |
| Code-Review | `GH-PLAT-024`, `PLAT-BRPROT-015`, `GH-PLAT-026` | YES | GitHub rulesets + branch-protection cover required reviewers, status checks, environment approvals. |
| Contributors | (none) | OUT | The kit does not analyze commit history or contributor breadth. |
| Dangerous-Workflow | `CI-DANGER-007`, `GH-WF-019`, `GH-WF-020`, `AZ-PIPE-029` | YES | Multiple deterministic checks against unsafe workflow patterns. |
| Dependency-Update-Tool | `DEP-UPDATE-001`, `SEC-DEPREV-011` | YES | Detects Dependabot / Renovate config plus dependency-review-action. |
| Fuzzing | (none) | OUT | The kit does not require fuzzing; Scorecard JSON can surface it. |
| License | `GOV-LIC-004` | YES | LICENSE file presence (deterministic). |
| Maintained | (none) | OUT | The kit does not infer maintenance from commit cadence. |
| Packaging | (none) | OUT | Packaging publication signals are not modeled. |
| Pinned-Dependencies | `CI-PIN-008`, `SEC-PINLOCK-052`, `CI-WFCALLSHA-055`, `CONT-IMAGE-001` | YES | Four deterministic angles: third-party actions, lockfiles, reusable workflow SHAs, container base images. |
| SAST | `SEC-CODEQL-010` | PARTIAL | `signal` grade — we detect the SAST tool's presence in CI YAML; Scorecard can confirm tool runs. |
| Security-Policy | `GOV-SEC-001`, `GOV-DISC-013` | YES | SECURITY.md presence + responsible disclosure heuristic. |
| Signed-Releases | `GH-PROV-023`, `AZ-ARTPRV-059`, `AWS-PROVART-059` | PARTIAL | `signal` grade for in-workflow detection; `evidence-backed` for artifact-bound provenance. Sigstore/cosign verification is not performed. |
| Token-Permissions | `CI-PERM-006`, `GH-WF-020`, `CI-LEAST-009` | YES | Three angles: top-level perms, job-level write scopes, breadth heuristic. |
| Vulnerabilities | `OSS-SCORECARD-001` | INDIRECT | The kit accepts the Scorecard JSON; it does not query OSV directly. |
| Webhooks | (none) | OUT | Repository-webhook posture is not modeled. |

**Coverage**: 11 YES, 3 PARTIAL, 5 OUT, 0 GAP. The 5 OUT items are intentional design choices,
documented above.

## OpenSSF OSPS Baseline

The OSPS Baseline groups expectations into **maturity levels**: starter, advanced, mature.
Many items overlap with Scorecard. The kit's `*-level-1` profiles align with OSPS starter; `*-level-2`
aligns with advanced; `*-level-3` aligns with mature plus platform evidence. See
[osps-mapping.md](osps-mapping.md) for the per-control mapping. No GAPs added beyond those
already listed under Scorecard above.

## OWASP CI/CD Top 10 (2022)

| Risk | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| CICD-SEC-1: Insufficient Flow Control | `PLAT-BRPROT-015`, `GH-PLAT-024`, `AZ-PLAT-034`, `AWS-CP-044` | YES | Branch protection / rulesets / Azure branch policies / CodePipeline approvals. |
| CICD-SEC-2: Inadequate IAM | `GH-DEPLOY-022`, `AZ-IDENT-036`, `AZ-WIFEV-057`, `AZ-SCONN-056`, `AWS-CBIDENT-057`, `AWS-PIPEIAM-056`, `ORG-MFA-001` | YES | Federated identity preferred; OIDC enforced; org MFA evidenced. |
| CICD-SEC-3: Dependency Chain Abuse | `CI-PIN-008`, `SEC-DEPREV-011`, `SEC-PINLOCK-052`, `DEP-UPDATE-001`, `CI-WFCALLSHA-055` | YES | Multiple deterministic angles. |
| CICD-SEC-4: Poisoned Pipeline Execution | `CI-DANGER-007`, `GH-WF-019`, `AZ-PIPE-029`, `PLAT-BRPROT-015` | YES | `pull_request_target` hardening + branch protection. |
| CICD-SEC-5: Insufficient PBAC | `GH-PLAT-026`, `AZ-PLAT-035`, `AWS-CP-044` | YES | Environment approvals, manual approvals on CodePipeline. |
| CICD-SEC-6: Insufficient Credential Hygiene | `GH-PLAT-025`, `AZ-SEC-031`, `AWS-SECRET-038`, `SEC-SECRETS-050` | YES | Secret scanning + plaintext-secret avoidance. |
| CICD-SEC-7: Insecure System Configuration | `GH-WF-019` | PARTIAL | We discourage self-hosted runners on PR-triggered workflows but do not deeply analyze runner posture. |
| CICD-SEC-8: Ungoverned Use of 3rd-Party Services | `CI-PIN-008`, `CI-WFCALLSHA-055` | YES | Third-party action SHA pinning + reusable workflow SHA pinning. |
| CICD-SEC-9: Improper Artifact Integrity Validation | `GH-PROV-023`, `AZ-ARTSBOM-058`, `AZ-ARTPRV-059`, `AWS-SBOMART-058`, `AWS-PROVART-059`, `BUILD-SBOM-QUAL-003`, `PROV-VERIFY-061` | YES | SBOM + provenance attestation against artifact digest; v5.1.0 adds independent verification (sigstore / `gh attestation verify`). |
| CICD-SEC-10: Insufficient Logging and Visibility | `AUDIT-STREAM-060` | YES | v5.1.0 closes this with audit log streaming evidence (signal fallback + evidence-backed). |

**Coverage**: 9 YES, 1 PARTIAL, 0 GAP (since v5.1.0 — `AUDIT-STREAM-060` closes CICD-SEC-10).
Older releases (v5.0.0) had this as a GAP; the v5.1.0 control closes the audit-log-streaming
expectation honestly via an evidence schema, with a signal-grade fallback for clone-only repos.

## SLSA v1.0 — Build track

| SLSA item | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| Build L1: Build process | `CI-WF-005`, `AZ-PIPE-027`, `AWS-CI-037`, `AWS-PIPE-042` | YES | Build files exist in supported paths. |
| Build L1: Provenance generated (basic) | `GH-PROV-023`, `AWS-PROV-043` | PARTIAL | We detect provenance signal in CI YAML; verifying the provenance document is signed is not done. |
| Build L2: Hosted build platform | `GH-WF-019` | PARTIAL | We discourage self-hosted runners on PR-triggered workflows but do not enumerate the platform's hosted/managed posture. |
| Build L2: Provenance signed | `AZ-ARTPRV-059`, `AWS-PROVART-059`, `PROV-VERIFY-061` | YES (since v5.1.0) | v5.0.0 had this as PARTIAL because we required an artifact-bound provenance evidence file but did not verify the signature. v5.1.0 adds `PROV-VERIFY-061` which consumes a `verification:` block with sigstore / `gh attestation verify` results (issuer, transparency-log inclusion, freshness). |
| Build L3: Hardened build platform (isolation) | `GH-DEPLOY-022`, `AZ-WIFEV-057`, `AZ-IDENT-036`, `AWS-CBIDENT-057` | PARTIAL | OIDC / federated identity controls cover identity hardening; runtime build isolation is platform-side. |
| Build L3: Parameterized builds | `GH-PLAT-024`, `PLAT-BRPROT-015` | PARTIAL | Branch protection enforces review; parameter-injection prevention at the build layer is platform-specific. |

**Coverage** (v5.1.0): **2 YES, 4 PARTIAL, 0 GAP**. Build L2 "Provenance signed" upgrades to YES via `PROV-VERIFY-061`. Full SLSA L3 attestation still requires runtime build platform telemetry that this kit does not collect. The kit's `*-release-hardening-3` profiles are aligned with **SLSA Build L2 evidence expectations** when their evidence files are filled, and now include the verification step.

## SLSA v1.2 — Source Track (RC2 active May 2026)

SLSA v1.2 reintroduces a **Source Track** alongside the Build Track. It defines four levels for source-side integrity. Coverage in this kit:

| SLSA Source level | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| Source L1: Version control in use | `CI-WF-005`, `AZ-PIPE-027`, `AWS-CI-037` (presence implies VCS) | YES | A repo with CI files inherently has VCS. |
| Source L2: History & provenance (branch protection, signed commits, complete history) | `PLAT-BRPROT-015`, `GH-PLAT-024`, `AZ-PLAT-034` | PARTIAL | Branch protection covered; signed-commit policy is enforceable via GitHub rulesets but the kit only confirms ruleset presence, not commit-signature posture per merged PR. |
| Source L3: Source provenance attestations | (none) | GAP | Verifiable source-history attestations are not yet emitted by mainstream SCMs at scale. Tracked as future work in `docs/profiles/deferred-followups.md`. |
| Source L4: Two-party review on every merged PR | `PLAT-BRPROT-015` (with `required_approving_review_count >= 2`), `GH-PLAT-024` | PARTIAL | Existing branch-protection evidence accepts an optional `required_approving_review_count` field. When set to ≥2, the result `extra` records L4 alignment; otherwise the `evidence.limitations` array notes "single-reviewer policy; SLSA Source L4 not satisfied." |

**Coverage** (v5.1.0): 1 YES, 2 PARTIAL, 1 GAP. This is the first iteration of Source Track mapping; ranking the remaining items in the post-v5.x backlog.

## NIST SSDF SP 800-218 (Rev 1.1)

The four practice groups in the SSDF (PO, PS, PW, RV) align as follows:

| SSDF practice | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| PO.1 Define security requirements | `GOV-SEC-001`, `GOV-CON-002`, `GOV-DISC-013` | YES | Repo-level governance docs. |
| PO.2 Define roles & responsibilities | `GOV-COWN-003` | YES | CODEOWNERS. |
| PO.3 Implement supporting toolchains | `CI-WF-005`, `AZ-PIPE-027`, `AWS-CI-037` | YES | Toolchain presence. |
| PO.4 Define criteria for software security checks | `GOV-WAIV-014`, `OSS-SCORECARD-001` | YES | Versioned waiver policy + scorecard threshold. |
| PS.1 Protect all forms of code | `PLAT-BRPROT-015`, `GH-PLAT-024`, `AZ-PLAT-034` | YES | Branch protection / rulesets / Azure policies. |
| PS.2 Provide a mechanism for verifying release integrity | `GH-PROV-023`, `AZ-ARTPRV-059`, `AWS-PROVART-059`, `BUILD-SBOM-QUAL-003` | YES | Provenance + SBOM. |
| PS.3 Archive & protect each release | (none) | GAP | Archival policy is out of clone scope. |
| PW.1 Design with security in mind | `GOV-SEC-001` (proxy) | PARTIAL | Threat-model artifacts are out of scope. |
| PW.4 Reuse existing well-secured software | `CI-PIN-008`, `SEC-PINLOCK-052`, `DEP-UPDATE-001` | YES | Dependency hygiene controls. |
| PW.5 Create source code by adhering to secure coding practices | `SEC-CODEQL-010`, `SEC-DEPREV-011`, `AZ-SEC-031`, `AWS-SEC-039` | PARTIAL | SAST / SCA detection in CI; secure-coding practice itself is process. |
| PW.6 Configure compilation, interpreter, and build processes | `CI-PERM-006`, `GH-WF-020`, `CI-LEAST-009`, `AWS-SECRET-038` | YES | Token-perms + secret hygiene at build. |
| PW.7 Review and/or analyze human-readable code | `GH-PLAT-024` (rulesets) | PARTIAL | Required-review enforcement; automated review is process. |
| PW.8 Test executable code | `CI-WF-005` | PARTIAL | We confirm CI presence; not test outcomes. |
| PW.9 Configure the software to have secure settings by default | OUT | OUT | Application-runtime concern. |
| RV.1 Identify and confirm vulnerabilities on an ongoing basis | `OSS-SCORECARD-001`, `SEC-CODEQL-010`, `SEC-SECRETS-050`, `GH-PLAT-026`, `CONT-IMAGE-003`, `AUDIT-STREAM-060` | YES | SAST + secret scanning + container scanning + audit-log streaming for incident detection (v5.1.0). |
| RV.2 Assess, prioritize, and remediate vulnerabilities | `DEP-UPDATE-001` | PARTIAL | Auto-update tooling; prioritization is process. |
| RV.3 Analyze vulnerabilities to identify root causes | OUT | OUT | Process, not artifact. |

**Coverage**: 8 YES, 7 PARTIAL, 1 GAP, 2 OUT. SSDF is broader than this kit's scope by design;
items marked OUT are application/runtime concerns that belong elsewhere in an AppSec program.

## Microsoft S2C2F (OSS consumption)

| S2C2F practice | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| Ingest | (none) | OUT | Registry-allowlist policy is org-side. |
| Inventory (SBOM) | `AZ-SBOM-033`, `AWS-SBOM-041`, `AZ-ARTSBOM-058`, `AWS-SBOMART-058`, `BUILD-SBOM-QUAL-003` | YES | SBOM generation signal + artifact-bound SBOM evidence. |
| Update | `DEP-UPDATE-001` | YES | Dependabot / Renovate. |
| Enforce (pin / version locks) | `CI-PIN-008`, `SEC-PINLOCK-052`, `CI-WFCALLSHA-055`, `CONT-IMAGE-001` | YES | Multiple pin-or-lock angles. |
| Audit | `SEC-DEPREV-011`, `AZ-SCA-032`, `AWS-SCA-040` | YES | Dependency review / SCA signals. |
| Scan | `SEC-CODEQL-010`, `AZ-SEC-031`, `AWS-SEC-039`, `CONT-IMAGE-003` | YES | SAST + container scan signals. |
| Rebuild | (none) | OUT | Reproducible-build infrastructure is build-platform side. |
| Fix Upstream | (none) | OUT | Process, not artifact. |

**Coverage**: 5 YES, 0 PARTIAL, 0 GAP, 3 OUT.

## CIS Software Supply Chain Security Benchmark

CIS SSCS organizes recommendations into five sections. High-level alignment:

| CIS section | Coverage | Mapped controls (sample) |
|---|---|---|
| Source Code | YES | `GOV-COWN-003`, `PLAT-BRPROT-015`, `GH-PLAT-024`, `AZ-PLAT-034` |
| Build Pipelines | YES | `CI-PERM-006`, `CI-DANGER-007`, `GH-WF-019`, `AZ-PIPE-029`, `AWS-SECRET-038` |
| Dependencies | YES | `CI-PIN-008`, `SEC-PINLOCK-052`, `DEP-UPDATE-001`, `SEC-DEPREV-011` |
| Artifacts | YES | `BUILD-SBOM-QUAL-003`, `AZ-ARTSBOM-058`, `AZ-ARTPRV-059`, `AWS-SBOMART-058`, `AWS-PROVART-059` |
| Deployment | PARTIAL | `GH-DEPLOY-022`, `GH-PLAT-026`, `AZ-WIFEV-057`, `AWS-PIPEIAM-056` |

The Deployment section's PARTIAL grade reflects that runtime infrastructure-as-code review is
out of scope for this kit (Terraform / Bicep IaC scanning belongs in dedicated tools).

## AWS Well-Architected — Security Pillar (DevOps lens)

| AWS practice | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| Identify and validate control objectives | `GOV-SEC-001`, `GOV-WAIV-014` | YES | Repo-level policy. |
| Use IAM federation, avoid long-lived credentials | `AWS-CBIDENT-057`, `AWS-PIPEIAM-056`, `GH-DEPLOY-022` | YES | OIDC + federated identity controls. |
| Encrypt data at rest and in transit | OUT | OUT | Application/infra concern. |
| Implement strong identity foundation | `ORG-MFA-001`, `AWS-PIPEIAM-056` | YES | Org-MFA evidence + pipeline IAM boundary. |
| Enable traceability | `AUDIT-STREAM-060` | PARTIAL | v5.1.0 records audit-log streaming destinations (CloudTrail forwarding) via evidence; deeper account-side telemetry is still out of scope. |
| Apply security at all layers | mixed | PARTIAL | Multiple kit controls touch this; full coverage requires runtime tooling. |
| Automate security best practices | `CI-WF-005`, `AWS-CI-037`, `AWS-PIPE-042` | YES | CI/build pipeline presence. |
| Protect data in transit / at rest | OUT | OUT | Application concern. |
| Prepare for security events | (none) | GAP | Incident response automation is process. |

## Azure DevOps Security Best Practices

| Azure practice | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| Branch policies (min reviewers, build validation) | `AZ-PLAT-034`, `PLAT-BRPROT-015` | YES | Evidence-backed via `azure-branch-policies.json`. |
| Pipeline approvals & gates | `AZ-PLAT-035`, `AZ-IDENT-036` | YES | Evidence-backed. |
| Service connections (least privilege, federated identity) | `AZ-SCONN-056`, `AZ-WIFEV-057` | YES | Decomposed into separate evidence-backed controls. |
| Secret management (Variable Groups, Key Vault) | `AZ-SEC-031`, `SEC-SECRETS-050` | PARTIAL | Signal-grade detection of scanning; deep variable-group ACL is org-side. |
| YAML pipeline structure (extends, restricted templates) | `AZ-PIPE-030` | YES | Deterministic. |
| Avoid persistCredentials true | `AZ-PIPE-029` | YES | Deterministic. |
| Audit logs / SIEM | `AUDIT-STREAM-060` | YES (since v5.1.0) | Audit-log streaming evidence (Azure DevOps `auditstreams` API) closes this. Older releases had this as a GAP. |

## EU Cyber Resilience Act (CRA)

Regulatory pressure with concrete artifact requirements. Key dates:

- **2026-09-11**: vulnerability/incident reporting obligations begin (enforceable).
- **2027-12-11**: full obligations apply.

| CRA expectation | Kit control(s) | Coverage | Notes |
|---|---|---|---|
| SBOM in machine-readable format (CycloneDX or SPDX) | `BUILD-SBOM-QUAL-003`, `AZ-ARTSBOM-058`, `AWS-SBOMART-058`, `AZ-SBOM-033`, `AWS-SBOM-041` | YES | The kit emits a CycloneDX SBOM at build time and evaluates SBOM-quality controls. |
| SBOM lists at least top-level dependencies | `BUILD-SBOM-QUAL-003` | YES | Bundled SBOM-quality control flags incomplete CycloneDX/SPDX shapes. |
| SBOM and security documentation retained 10 years | `RELEASE-ARCHIVE-063` | YES (since v5.2.0) | Retention/archival policy evidence is evaluated through `.oss-policy-kit/evidence/release-archival-policy.json`. |
| Documented vulnerability handling | `GOV-SEC-001`, `GOV-DISC-013`, `SEC-DEPREV-011`, `DEP-UPDATE-001` | YES | SECURITY.md + responsible disclosure + dependency review/auto-update. |
| Centralized incident reporting / audit trail | `AUDIT-STREAM-060` | YES (since v5.1.0) | Audit-log streaming evidence is the trail an incident report needs. |
| Build provenance for shipped artifacts | `GH-PROV-023`, `AZ-ARTPRV-059`, `AWS-PROVART-059`, `PROV-VERIFY-061` | YES (since v5.1.0) | Provenance attestation independently verified. |

> **Honesty contract**: this kit does **not** certify CRA compliance. The legal side (notified bodies, market-placement timing, retention storage destinations) is out of scope. The advisory profile `cra-eu-ready-1`, introduced in v5.2.0, bundles the technical-readiness controls into a single discovery surface.

## NIST SP 800-218A — AI / Generative AI (out of scope for v5.x)

NIST finalized SP 800-218A as an SSDF *Community Profile* augmenting SP 800-218 with practices specific to generative AI / dual-use foundation model development (model cards, training-data provenance, prompt-injection / jailbreak testing, dual-use risk).

**Coverage in this kit**: out of scope for the v5.x line. AI-specific evaluators (model card detection from clone, training-data provenance evidence schema, prompt-injection guardrail signal) are real new product surface, not a re-grouping of existing controls. Tracked for v6.0.0 in `docs/profiles/deferred-followups.md`.

## Decisions taken on this iteration

After mapping the catalog to all nine frameworks above, the explicit decisions are:

### Decision 1 — No new profiles in v5.0.0

**Reasoning**:

1. The 20 bundled profiles cover the full ladder for 3 platforms × 3 levels × 2 tracks + 2
   advisory hybrids. No threat model identified during the framework mapping is unrepresented
   in this matrix.
2. A "scorecard-aligned" or "slsa-l2-aligned" profile would be a curated **subset** of the
   existing catalog. Subsets serve operators better as **mapping documentation** (this page)
   than as additional profiles, because:
   - Profiles compete for operator mind-share; 20 is already a heavy menu.
   - Framework versions move; profile content cannot easily move with them without breaking
     the wire contract.
   - Mapping docs evolve cheaply; profiles add wire-stability obligations.
3. The kit already exposes per-control `assurance` metadata and per-profile `posture`
   metadata, so consumers can filter to a framework-aligned subset on the consumer side
   without the kit owning the framework's evolution.
4. The user-facing artifact that would benefit from a framework-aligned profile (a "what does
   this kit prove for SLSA L2?" view) is more honestly served by the **mapping table** above
   than by re-grouping the same controls under a new id.

### Decision 2 — No new controls in v5.0.0

**Reasoning**:

1. The two clearest gaps identified by the mapping are **CICD-SEC-10 (logging/visibility)**
   and **AWS Well-Architected "Enable traceability" / "Prepare for security events"**. Both
   require **org-scoped audit log access** that:
   - Is not retrievable from a clone alone.
   - Requires new collector endpoints with org-scope tokens (broader scope than today's repo-
     level tokens).
   - Has organization-policy implications that vary per company (retention duration, storage
     destination, who can read).
2. Adding a `signal`-grade control just to "tick the box" would inflate maturity without
   adding evidentiary value. The kit's design philosophy is to keep `signal` controls
   directional and to refuse `verified` projection on them — adding more `signal` controls
   weakens the average control's strength.
3. The most defensible path for these gaps is to surface them as **conceptual future work**
   (registered in [profiles/deferred-followups.md](profiles/deferred-followups.md)) and
   address them only when a real collector path exists.

### Decision 3 — Mature the **profile metadata** to reference frameworks

**Action taken in this iteration**:

- Profile descriptions (`description:` field in each profile YAML) gain a one-line reference
  to the most relevant framework alignment so an operator reading `profiles --format detailed`
  immediately sees which framework the profile aligns with.
- This mapping page is linked from `docs/README.md`, `docs/profiles/overview.md`,
  `docs/scorecard-mapping.md` and `docs/osps-mapping.md`.
- The catalog YAML and profile control lists are **byte-equivalent** before/after this
  iteration; only documentation surfaces change.

### Decision 4 — Concrete future work ranked by framework leverage

When the v5.0.0 line is published and a future minor (5.1+) opens, the **highest-leverage**
framework-driven additions, ranked by impact:

1. **Audit log evidence** (`<platform>-audit-log.json` collected via org-scope endpoint).
   Closes CICD-SEC-10, NIST SSDF RV.1 partial, AWS Enable-Traceability, Azure SIEM.
2. **Sigstore/cosign signature verification** (verify `provenance` evidence is signed).
   Closes SLSA L2 PARTIAL (provenance signed). Requires new dependency.
3. **OpenSSF Best Practices badge ingestion** (`openssf-best-practices.json`). Closes
   Scorecard CII-Best-Practices OUT → INDIRECT.
4. **Reusable runner posture evaluator** (deeper analysis of self-hosted runner config).
   Closes CICD-SEC-7 PARTIAL.
5. **Container hardening evaluator** (extending `CONT-IMAGE-001..003` with seccomp /
   capabilities checks). Closes CIS SSCS Deployment PARTIAL.

Each item above requires either a new evaluator, a new evidence schema, or both. None are in
scope for v5.0.0 release.

## Out of scope (intentional)

Frameworks the kit does not attempt to map. Listing them here is the honest move:

- **OWASP ASVS** — Application Security Verification Standard targets the application layer,
  not CI/CD policy.
- **NIST 800-53** — Federal control catalog far broader than CI/CD scope.
- **PCI DSS 4.0** — Payment-industry compliance has its own audit pipeline.
- **ISO 27001 / SOC 2** — Organizational compliance frameworks, not source-repo gates.
- **SAFECode practices** — Process-heavy guidance overlapping mostly with NIST SSDF (already
  mapped above).
- **MITRE ATT&CK for CI/CD** — Adversary-emulation reference; useful for red-team but not for
  policy gates today.

The kit can be **complementary** to all of these (a `pass` on `*-level-3` reduces the surface
area an ASVS / 800-53 audit needs to cover), but it does not claim to **prove** them.

## How operators use this page

1. **Operator coming from Scorecard**: open the Scorecard table, find your check, click the
   linked control id, run `evaluate` against the profile that includes it.
2. **Operator coming from OWASP CICD Top 10**: open the CICD table, identify whether your gap
   is a YES (covered), PARTIAL (treat as directional), or GAP (out of scope).
3. **Operator coming from SLSA L2/L3 procurement**: read the SLSA section. The kit's
   `*-release-hardening-*` profiles align with L2 evidence expectations directionally; full
   L3 attestation requires runtime build platform telemetry beyond this kit.
4. **Operator coming from NIST SSDF**: use the SSDF table to identify which practice areas
   the kit covers (PS / PW are deepest; PO / RV are shallower); use complementary tools for
   the rest.

## See also

- [controls-catalog.md](controls-catalog.md) — full catalog of 65 controls with profile
  membership.
- [collector-parity.md](collector-parity.md) — what each platform collector retrieves today.
- [scorecard-mapping.md](scorecard-mapping.md) — Scorecard-specific mapping detail.
- [osps-mapping.md](osps-mapping.md) — OSPS-specific mapping detail.
- [profiles/overview.md](profiles/overview.md) — profile maturity tier discussion.
- [profiles/deferred-followups.md](profiles/deferred-followups.md) — conceptual future work.
- [results-guide.md](results-guide.md) — how to interpret report statuses.

## v5.4.0 framework alignment profiles

Seven multi-platform profiles introduced in v5.4.0 bundle existing controls into framework-specific mappings, plus one **AppSec native bundle** (`appsec-sast-sca-1`) that combines SAST + SCA + secret scanning + dependency hygiene. None of them adds new controls; they reuse the existing 70-control catalog. Below is a one-paragraph mapping per profile. Detailed per-control rationale lives inside the corresponding `profile.yaml` `description:` and `audience:` fields.

### `osps-baseline-1` — OpenSSF OSPS Baseline

Maps the kit's controls to the four areas of the OpenSSF Open Source Project Security Baseline (Linux Foundation, 2025): Access Control, Build & Release, Documentation, and Quality & Security Assessment. 18 controls, advisory mapping. Not a compliance certification. Recommended `--fail-on degraded` only. Typical audience: OSS maintainers and small-to-medium projects declaring OSPS Baseline alignment in README, RFP responses, or grant applications.

### `slsa-build-l2-1` — SLSA v1.1 Build Track Level 2

Maps the kit's controls to SLSA v1.1 Build Track Level 2 expectations: build automation + provenance signed. 14 controls, hard-gate-capable when `PROV-VERIFY-061` evidence is present (sigstore / GitHub Artifact Attestations) and verifiable. Recommended `--fail-on fail` paired with a real attestation; without evidence, expect `manual-review-required` on `PROV-VERIFY-061` (this is by design — SLSA L2 cannot be claimed without verifiable provenance). Typical audience: maintainers publishing artifacts (wheels, containers, binaries) who must declare "SLSA Build L2" to downstream consumers. Note: the kit does **not** verify the actual cryptographic signature; the verification expectation is that the build pipeline runs `cosign verify` / `gh attestation verify` and writes the result into the evidence file.

### `ssdf-baseline-1` — NIST SP 800-218 (Secure Software Development Framework)

Maps the kit's controls to the four practice groups of NIST SSDF SP 800-218: Prepare Organization (PO), Protect Software (PS), Produce Well-Secured Software (PW), Respond to Vulnerabilities (RV). 22 controls, advisory mapping. Federal suppliers under OMB M-22-18 / EO 14028 should treat this as discovery-grade evidence, **not** as the formal SSDF self-attestation form (which remains a manual process outside the kit's scope). Recommended `--fail-on degraded` only. Coverage is deepest in PS and PW (the kit's natural strengths); PO and RV are shallower because they cover organizational and incident-response practices that go beyond what a clone-side tool can verify.

### `cis-supply-chain-1` — CIS Software Supply Chain Security Benchmark v1.0

Maps the kit's controls to the five areas of the CIS Software Supply Chain Security Benchmark v1.0: Source Code, Build Pipelines, Dependencies, Artifacts, and Deployment. 24 controls, advisory mapping. Recommended `--fail-on degraded` only. Typical audience: enterprise teams adopting CIS guidance. Use as a scorecard before or alongside the platform-specific `*-release-hardening-3` profiles; do not use as the only gate for a release because CIS benchmark items related to runtime, network, and observability are out of the kit's clone-side scope.

### `owasp-cicd-top10-1` — OWASP Top 10 CI/CD Security Risks (2022)

Maps the kit's controls to all 10 OWASP CI/CD security risks: each risk has at least one control mapped. 23 controls, advisory mapping. Recommended `--fail-on degraded` only. The strongest coverage is on CICD-SEC-1 (Insufficient Flow Control), CICD-SEC-3 (Dependency Chain Abuse), CICD-SEC-4 (Poisoned Pipeline Execution), and CICD-SEC-5 (Insufficient PBAC) — all directly addressable from clone-visible artifacts. CICD-SEC-2 (Inadequate Identity), CICD-SEC-7 (Insecure System Configuration), and CICD-SEC-10 (Insufficient Logging and Visibility) lean on evidence files because they require platform truth.

### `s2c2f-l1-1` — Microsoft S2C2F Level 1 (Secure Supply Chain Consumption Framework)

Maps the kit's controls to Microsoft S2C2F Level 1, focusing on Ingest, Inventory, Update, and Audit areas (the four lowest-maturity areas of the eight-area framework). 9 controls (deliberately small), advisory mapping. Recommended `--fail-on degraded` only. Typical audience: teams that **consume** OSS at scale and need a baseline for secure intake. Pair with a platform-specific profile (`*-level-1` or `*-level-2`) for full producer-side coverage. This profile complements the kit's existing producer-focused emphasis by surfacing consumption discipline.

### `cra-eu-strict-1` — EU Cyber Resilience Act, full-obligations track (2027-12-11)

Stricter version of `cra-eu-ready-1`, aimed at the EU CRA full-obligations deadline (2027-12-11) when CE marking is required. 19 controls (12 from `cra-eu-ready-1` + 7 strict-track additions: `GH-PROV-023`, `GH-PLAT-024`, `GH-PLAT-025`, `GH-PLAT-026`, `ORG-MFA-001`, `CI-PIN-008`, `SEC-SECRETS-050`). Hard-gate-capable when evidence files are filled; recommended `--fail-on fail` paired with `collect-evidence --platform github` and artifact-bound SBOM/provenance evidence. Without evidence, expect `manual-review-required` (honest gap, not a crash). **Critical caveat:** this profile is **not** a CRA conformity assessment. Conformity assessment requires a competent authority and is outside the kit's scope. Use this as a clone-side posture indicator; the formal CE-marking process is external.

### `appsec-sast-sca-1` — AppSec native bundle (SAST + SCA + secret scanning + dependency hygiene)

Multi-platform profile aimed at AppSec teams using the kit as part of pipeline AppSec, not just as OSS governance. 11 controls grouped in four areas: **SAST** (`SEC-CODEQL-010`, `SAST-SEMGREP-064`), **SCA** (`SEC-DEPREV-011`, `DEP-UPDATE-001`, `SEC-PINLOCK-052`), **secret scanning** (`SEC-SECRETS-050`, `SEC-GITIGNORE-051`, `GH-PLAT-026`), and **dependency integrity** (`CI-PIN-008`, `CI-WFCALLSHA-055`), plus governance sustaining (`GOV-WAIV-014`). Hard-gate-capable when paired with `oss-policy-kit scan-sast`: that command produces the Semgrep evidence file consumed by `SAST-SEMGREP-064`. Without that evidence, the SAST control returns `manual-review-required` (does not trip `--fail-on fail`); with it, the profile reaches deterministic + evidence-backed posture suitable for `--fail-on fail`. Recommended workflow: `oss-policy-kit scan-sast --target . && oss-policy-kit evaluate --target . --profile appsec-sast-sca-1 --fail-on fail`. This is the first bundled profile to consume `SAST-SEMGREP-064` (promoted from `experimental` to `stable` alongside this profile).

## Versioning of this doc

This page is regenerated manually when the catalog or profiles change. The training cutoff
referenced for the framework summaries is **January 2026**; framework owners should always be
consulted upstream for the current canonical text. Prior framework releases (Scorecard v3,
SLSA v0.1, SSDF SP 800-218 1.0, etc.) are not listed; only current major-line text is mapped.
