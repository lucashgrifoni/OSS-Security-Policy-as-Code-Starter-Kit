# OSPS Baseline mapping (concrete)

The [OpenSSF Open Source Project Security (OSPS) Baseline](https://baseline.openssf.org/) is a
maturity baseline aimed at OSS maintainers. This project **does not** claim OSPS certification,
**does not** certify OSPS conformance, and **does not** track OSPS revisions automatically. It
documents how its bundled controls align with OSPS expectations so operators coming from OSPS
can navigate the kit.

For the master cross-framework mapping (Scorecard, OWASP CICD Top 10, SLSA v1.0, NIST SSDF,
S2C2F, CIS SSCS, AWS Well-Architected, Azure DevOps Security), see
[framework-alignment.md](framework-alignment.md).

## OSPS maturity ladder ↔ kit profile ladder

OSPS organizes expectations into three levels — **starter / advanced / mature** — that align
roughly with the kit's `*-level-1` / `*-level-2` / `*-level-3` ladder. The kit's
`release-hardening-*` track adds release-discipline expectations on top of each ladder step.

| OSPS level | Aligned kit profiles | What the kit can prove deterministically | What still needs evidence or external attestation |
|---|---|---|---|
| Starter | `github-level-1`, `azure-level-1`, `aws-level-1` | Governance docs (SECURITY, CONTRIBUTING, LICENSE, CODEOWNERS), CI presence, basic workflow hygiene, license, dependency lockfile | Maintenance cadence, contributor diversity (out of scope) |
| Advanced | `*-level-2`, `*-release-hardening-1` / `-2` | Stricter workflow hardening (SHA pinning, no `pull_request_target` abuse, narrow token perms), SAST/SCA detection in CI, SBOM signal, branch protection evidence (light) | Signal-grade rows are directional; `release-hardening-2` requires evidence JSONs filled |
| Mature | `*-level-3`, `*-release-hardening-3` | Evidence-backed branch protection / rulesets / environment protection / secret scanning (GitHub) or branch policies / pipeline governance / federated identity / service connections (Azure) or CodeBuild posture / CodePipeline posture / IAM boundaries (AWS) | API-collected evidence (`collect-evidence`) for `verified` trust; artifact-bound SBOM/provenance still self-attested by design (digests come from release pipeline) |

## OSPS theme ↔ kit control (concrete)

The OSPS Baseline is organized around themes (governance, vulnerability management, access
control, build & release, etc.). The table below maps OSPS themes to **specific** bundled
controls so operators can navigate from a baseline expectation to a concrete pass/fail row.

| OSPS theme | Kit control(s) | Assurance class |
|---|---|---|
| Project governance — `SECURITY.md` | `GOV-SEC-001` | deterministic |
| Project governance — `CONTRIBUTING` | `GOV-CON-002` | deterministic |
| Project governance — Code review ownership | `GOV-COWN-003` | deterministic |
| Project governance — License declared | `GOV-LIC-004` | deterministic |
| Vulnerability disclosure | `GOV-DISC-013` | signal |
| Versioned waiver / exception policy | `GOV-WAIV-014` | deterministic |
| Build pipelines (GitHub) | `CI-WF-005`, `CI-PERM-006`, `CI-DANGER-007`, `GH-WF-018..020`, `GH-REL-021`, `CI-LEAST-009` | deterministic / signal |
| Build pipelines (Azure) | `AZ-PIPE-027..030` | deterministic |
| Build pipelines (AWS) | `AWS-CI-037`, `AWS-SECRET-038`, `AWS-PIPE-042` | deterministic |
| Dependency hygiene (pin) | `CI-PIN-008`, `SEC-PINLOCK-052`, `CI-WFCALLSHA-055`, `CONT-IMAGE-001` | deterministic |
| Dependency hygiene (auto-update) | `DEP-UPDATE-001` | deterministic |
| Dependency review on PR | `SEC-DEPREV-011` | deterministic |
| SAST / static analysis signal | `SEC-CODEQL-010`, `AZ-SEC-031`, `AWS-SEC-039`, `CONT-IMAGE-003` | signal |
| SCA signal | `AZ-SCA-032`, `AWS-SCA-040` | signal |
| SBOM signal | `AZ-SBOM-033`, `AWS-SBOM-041`, `BUILD-SBOM-QUAL-003` | signal |
| Provenance signal | `GH-PROV-023`, `AWS-PROV-043` | signal |
| Branch protection (evidence) | `PLAT-BRPROT-015` | evidence-backed |
| GitHub rulesets / env protection / secret scanning | `GH-PLAT-024`, `GH-PLAT-025`, `GH-PLAT-026` | evidence-backed |
| Azure branch policies / pipeline governance | `AZ-PLAT-034`, `AZ-PLAT-035`, `AZ-IDENT-036`, `AZ-SCONN-056`, `AZ-WIFEV-057` | evidence-backed |
| Azure artifact-bound SBOM / provenance | `AZ-ARTSBOM-058`, `AZ-ARTPRV-059` | evidence-backed |
| AWS CodePipeline / CodeBuild platform evidence | `AWS-CP-044`, `AWS-CB-045`, `AWS-CC-046`, `AWS-PIPEIAM-056`, `AWS-CBIDENT-057` | evidence-backed |
| AWS artifact-bound SBOM / provenance | `AWS-SBOMART-058`, `AWS-PROVART-059` | evidence-backed |
| OIDC federation (deployment identity) | `GH-DEPLOY-022` | signal |
| Org-level MFA enforcement | `ORG-MFA-001` | evidence-backed |
| Release notes / changelog | `REL-CHANGE-012` | deterministic |
| Concurrency on release workflows | `GH-REL-021` | signal |
| Merge queue (advanced) | `GH-MERGEQ-053` | signal |
| Evidence freshness | `GOV-EVIDFRESH-054` | deterministic |
| Container hardening — base image digest pin | `CONT-IMAGE-001` | deterministic |
| Container hardening — non-root user | `CONT-IMAGE-002` | deterministic |
| Container hardening — image scan signal | `CONT-IMAGE-003` | signal |
| `.gitignore` minimum hygiene | `SEC-GITIGNORE-051` | deterministic |
| Secret scanning tool detection | `SEC-SECRETS-050` | signal |

## What OSPS expects that the kit **does not** evaluate

These are deliberate out-of-scope items, not gaps. Operators using OSPS as a procurement gate
should pair this kit with the indicated complementary tooling.

| OSPS expectation | Why not modeled here | Suggested complementary path |
|---|---|---|
| Project maintenance cadence (commit frequency, release cadence) | Not deterministic from a single clone snapshot | Scorecard `Maintained` check, GitHub Insights API |
| Contributor diversity / two-party review on every commit | Out of clone scope | Branch protection / rulesets review enforcement (already covered) plus org policy |
| Reproducible builds | Build-platform-side concern | SLSA build platform of choice, `slsa-verifier` |
| Threat model document presence | Process artifact, not a CI gate | OWASP Threat Dragon / pytm, internal review process |
| Incident response runbook | Process artifact | `docs/secret-leak-response.md` covers the leak path; broader IR is out of repo scope |
| Cryptographic signing verification | Beyond clone-visible YAML | sigstore `cosign verify`, SLSA verifier |

## How to use this document

Use it to explain **alignment** and **coverage gaps** to stakeholders. Specifically:

- Read the OSPS expectation row.
- Identify which kit control (or "not modeled") covers it.
- For evidence-backed rows, decide whether to fill the JSON manually
  ([scaffold-evidence](cli-reference.md)) or via API
  ([collect-evidence](cli-reference.md)).
- For signal-grade rows, treat PASS as directional and confirm via the upstream framework's
  own attestation.

## See also

- [framework-alignment.md](framework-alignment.md) — master cross-framework mapping.
- [controls-catalog.md](controls-catalog.md) — full catalog of 65 controls.
- [profiles/overview.md](profiles/overview.md) — profile maturity tier discussion.
