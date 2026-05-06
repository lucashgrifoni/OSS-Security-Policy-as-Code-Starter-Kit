# Controls Catalog (65 controls)

Single-page reference for the bundled control catalog. The authoritative source is
[`src/oss_policy_kit/data/controls/catalog.yaml`](../src/oss_policy_kit/data/controls/catalog.yaml). This page is regenerated manually when the catalog changes.

As of v5.0.0 there are **65 controls** across **20 bundled profiles**. All controls are currently `lifecycle: stable`.

## By category

| Category | Count |
|---|---|
| `ci_cd` | 17 |
| `governance` | 8 |
| `platform` | 16 |
| `release` | 2 |
| `supply_chain` | 16 |
| `vulnerability_management` | 6 |

## By assurance

| Assurance | Count | Meaning |
|---|---|---|
| `deterministic` | 28 | Structural YAML parse or file presence/absence -- high confidence. |
| `evidence-backed` | 19 | Depends on a local JSON evidence file or API-collected attestation. |
| `signal` | 18 | Heuristic textual match in YAML or docs -- directional, false-positive risk. PASS on a `signal` control never projects `trust_level: verified` (see [signal-controls-audit.md](signal-controls-audit.md)). |

## Full catalog

Profile counts in the **Profiles** column reflect how many bundled profiles include the control. See [profiles/overview.md](profiles/overview.md) for the bundled profile ladder.

| Control ID | Category | Assurance | Weight | Profiles | Title |
|---|---|---|---|---|---|
| `GOV-SEC-001` | governance | deterministic | 3 | 20 | SECURITY.md present |
| `GOV-CON-002` | governance | deterministic | 1 | 20 | CONTRIBUTING guide present |
| `GOV-COWN-003` | governance | deterministic | 2 | 20 | CODEOWNERS configured |
| `GOV-LIC-004` | governance | deterministic | 1 | 20 | LICENSE file present |
| `CI-WF-005` | ci_cd | deterministic | 2 | 8 | GitHub Actions workflows exist |
| `CI-PERM-006` | ci_cd | deterministic | 3 | 8 | Workflows declare explicit top-level permissions |
| `CI-DANGER-007` | ci_cd | deterministic | 3 | 8 | No pull_request_target without strong justification |
| `CI-PIN-008` | supply_chain | deterministic | 3 | 8 | Third-party actions pinned to immutable references |
| `CI-LEAST-009` | ci_cd | signal | 2 | 8 | Workflow permissions are not obviously over-broad |
| `SEC-CODEQL-010` | vulnerability_management | signal | 2 | 8 | CodeQL or equivalent security scanning in CI |
| `SEC-DEPREV-011` | supply_chain | deterministic | 2 | 8 | Dependency review in pull requests |
| `REL-CHANGE-012` | release | deterministic | 1 | 20 | Changelog or documented release notes |
| `GOV-DISC-013` | governance | signal | 2 | 20 | Responsible disclosure channel documented |
| `GOV-WAIV-014` | governance | deterministic | 1 | 20 | Versioned waiver policy file present in repository (not CLI-only waivers) |
| `PLAT-BRPROT-015` | platform | evidence-backed | 3 | 3 | Default branch protection / rulesets (evidence-backed) |
| `GH-WF-018` | ci_cd | deterministic | 2 | 6 | Reusable workflows avoid secrets inherit |
| `GH-WF-019` | ci_cd | deterministic | 2 | 6 | PR-triggered workflows avoid self-hosted runners |
| `GH-WF-020` | ci_cd | deterministic | 2 | 6 | Job-level permissions avoid broad write scopes |
| `GH-REL-021` | release | signal | 1 | 6 | Release/deploy workflows declare concurrency controls |
| `GH-DEPLOY-022` | platform | signal | 2 | 4 | Cloud deployment workflows show OIDC posture |
| `GH-PROV-023` | supply_chain | signal | 2 | 4 | Build provenance or artifact attestation signal in workflows |
| `GH-PLAT-024` | platform | evidence-backed | 3 | 3 | GitHub rulesets posture evidenced |
| `GH-PLAT-025` | platform | evidence-backed | 3 | 3 | GitHub environment protection posture evidenced |
| `GH-PLAT-026` | platform | evidence-backed | 2 | 3 | GitHub secret scanning posture evidenced |
| `AZ-PIPE-027` | ci_cd | deterministic | 2 | 7 | Azure Pipelines definitions exist in supported paths |
| `AZ-PIPE-028` | ci_cd | deterministic | 2 | 7 | Azure Pipelines include pull request validation trigger posture |
| `AZ-PIPE-029` | ci_cd | deterministic | 2 | 7 | Azure checkout avoids persistCredentials true |
| `AZ-PIPE-030` | ci_cd | deterministic | 1 | 5 | Azure pipelines use secure template extension posture |
| `AZ-SEC-031` | vulnerability_management | signal | 1 | 6 | Azure pipeline security scan signal detected |
| `AZ-SCA-032` | supply_chain | signal | 1 | 6 | Azure pipeline dependency audit or SCA signal detected |
| `AZ-SBOM-033` | supply_chain | signal | 1 | 6 | Azure pipeline SBOM generation signal detected |
| `AZ-PLAT-034` | platform | evidence-backed | 3 | 4 | Azure Repos branch policy posture evidenced |
| `AZ-PLAT-035` | platform | evidence-backed | 3 | 4 | Azure pipeline governance posture evidenced |
| `AZ-IDENT-036` | platform | evidence-backed | 2 | 5 | Azure deployment identity federation posture |
| `AZ-SCONN-056` | platform | evidence-backed | 3 | 2 | Azure DevOps service connection authentication posture evidenced |
| `AZ-WIFEV-057` | platform | evidence-backed | 2 | 2 | Azure DevOps workload identity federation posture evidenced |
| `AZ-ARTSBOM-058` | supply_chain | evidence-backed | 2 | 2 | Azure DevOps SBOM attested against a concrete release artifact digest |
| `AZ-ARTPRV-059` | supply_chain | evidence-backed | 2 | 2 | Azure DevOps provenance or attestation attested against a concrete release artifact digest |
| `AWS-CI-037` | ci_cd | deterministic | 2 | 7 | AWS CodeBuild buildspec or committed CodePipeline file exists |
| `AWS-SECRET-038` | ci_cd | deterministic | 3 | 7 | CodeBuild buildspec avoids inline secret anti-patterns and prefers managed secret sources |
| `AWS-SEC-039` | vulnerability_management | signal | 1 | 6 | Security scanning signal in CodeBuild buildspec |
| `AWS-SCA-040` | supply_chain | signal | 1 | 6 | Dependency audit or SCA signal in CodeBuild buildspec |
| `AWS-SBOM-041` | supply_chain | signal | 1 | 6 | SBOM generation signal in CodeBuild buildspec |
| `AWS-PIPE-042` | ci_cd | deterministic | 2 | 5 | Committed CodePipeline export under pipelines/aws/ with minimal useful structure |
| `AWS-PROV-043` | supply_chain | signal | 1 | 4 | Provenance or attestation signal in CodeBuild buildspec |
| `AWS-CP-044` | platform | evidence-backed | 3 | 4 | CodePipeline promotion and artifact governance evidenced |
| `AWS-CB-045` | platform | evidence-backed | 3 | 4 | CodeBuild project posture evidenced |
| `AWS-CC-046` | platform | evidence-backed | 1 | 0 | CodeCommit approval-rule review posture evidenced (optional) |
| `AWS-PIPEIAM-056` | platform | evidence-backed | 3 | 2 | CodePipeline service role / IAM execution boundary evidenced |
| `AWS-CBIDENT-057` | platform | evidence-backed | 3 | 2 | CodeBuild project identity and credential boundary evidenced |
| `AWS-SBOMART-058` | supply_chain | evidence-backed | 2 | 2 | SBOM attested against a concrete release artifact digest |
| `AWS-PROVART-059` | supply_chain | evidence-backed | 2 | 2 | Provenance or attestation attested against a concrete release artifact digest |
| `SEC-SECRETS-050` | vulnerability_management | signal | 2 | 3 | Secret scanning tool in CI |
| `SEC-GITIGNORE-051` | governance | deterministic | 1 | 14 | .gitignore present with basic secret protection patterns |
| `SEC-PINLOCK-052` | supply_chain | deterministic | 2 | 14 | Dependency lockfile or pinned dependencies present |
| `GH-MERGEQ-053` | ci_cd | signal | 1 | 5 | GitHub merge queue or merge_group trigger posture |
| `GOV-EVIDFRESH-054` | governance | deterministic | 2 | 9 | Collected evidence under .oss-policy-kit/evidence is not stale |
| `CI-WFCALLSHA-055` | ci_cd | deterministic | 3 | 2 | Reusable workflow calls pinned to immutable commit SHAs |
| `DEP-UPDATE-001` | supply_chain | deterministic | 2 | 14 | Automated dependency update tool configured (Dependabot or Renovate) |
| `OSS-SCORECARD-001` | vulnerability_management | signal | 1 | 4 | OpenSSF Scorecard score meets minimum threshold |
| `CONT-IMAGE-001` | supply_chain | deterministic | 2 | 14 | Dockerfile base images pinned to immutable digest |
| `CONT-IMAGE-002` | ci_cd | deterministic | 2 | 14 | Dockerfile declares non-root USER |
| `CONT-IMAGE-003` | vulnerability_management | signal | 1 | 14 | Container image scanning signal in CI |
| `ORG-MFA-001` | platform | evidence-backed | 3 | 6 | Organization MFA enforcement posture evidenced |
| `BUILD-SBOM-QUAL-003` | supply_chain | signal | 2 | 6 | SBOM format validity and completeness signal |

## Per-control profile membership

Each control entry below lists which bundled profiles include it. Controls not present in any profile are excluded from this section.

### `GOV-SEC-001` -- SECURITY.md present

- **Category**: `governance`
- **Assurance**: `deterministic` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (20): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `GOV-CON-002` -- CONTRIBUTING guide present

- **Category**: `governance`
- **Assurance**: `deterministic` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (20): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `GOV-COWN-003` -- CODEOWNERS configured

- **Category**: `governance`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (20): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `GOV-LIC-004` -- LICENSE file present

- **Category**: `governance`
- **Assurance**: `deterministic` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (20): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `CI-WF-005` -- GitHub Actions workflows exist

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (8): `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `CI-PERM-006` -- Workflows declare explicit top-level permissions

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (8): `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `CI-DANGER-007` -- No pull_request_target without strong justification

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (8): `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `CI-PIN-008` -- Third-party actions pinned to immutable references

- **Category**: `supply_chain`
- **Assurance**: `deterministic` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (8): `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `CI-LEAST-009` -- Workflow permissions are not obviously over-broad

- **Category**: `ci_cd`
- **Assurance**: `signal` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (8): `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `SEC-CODEQL-010` -- CodeQL or equivalent security scanning in CI

- **Category**: `vulnerability_management`
- **Assurance**: `signal` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (8): `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `SEC-DEPREV-011` -- Dependency review in pull requests

- **Category**: `supply_chain`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (8): `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `REL-CHANGE-012` -- Changelog or documented release notes

- **Category**: `release`
- **Assurance**: `deterministic` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (20): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `GOV-DISC-013` -- Responsible disclosure channel documented

- **Category**: `governance`
- **Assurance**: `signal` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (20): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `GOV-WAIV-014` -- Versioned waiver policy file present in repository (not CLI-only waivers)

- **Category**: `governance`
- **Assurance**: `deterministic` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `human_or_policy`
- **Profiles** (20): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `PLAT-BRPROT-015` -- Default branch protection / rulesets (evidence-backed)

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (3): `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `GH-WF-018` -- Reusable workflows avoid secrets inherit

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (6): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `GH-WF-019` -- PR-triggered workflows avoid self-hosted runners

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (6): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `GH-WF-020` -- Job-level permissions avoid broad write scopes

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (6): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `GH-REL-021` -- Release/deploy workflows declare concurrency controls

- **Category**: `release`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `GH-DEPLOY-022` -- Cloud deployment workflows show OIDC posture

- **Category**: `platform`
- **Assurance**: `signal` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (4): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-release-hardening-2`

### `GH-PROV-023` -- Build provenance or artifact attestation signal in workflows

- **Category**: `supply_chain`
- **Assurance**: `signal` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (4): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-release-hardening-2`

### `GH-PLAT-024` -- GitHub rulesets posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (3): `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `GH-PLAT-025` -- GitHub environment protection posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (3): `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `GH-PLAT-026` -- GitHub secret scanning posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (3): `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `AZ-PIPE-027` -- Azure Pipelines definitions exist in supported paths

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (7): `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-PIPE-028` -- Azure Pipelines include pull request validation trigger posture

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (7): `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-PIPE-029` -- Azure checkout avoids persistCredentials true

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (7): `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-PIPE-030` -- Azure pipelines use secure template extension posture

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (5): `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-SEC-031` -- Azure pipeline security scan signal detected

- **Category**: `vulnerability_management`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `azure-level-1`, `azure-level-2`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-SCA-032` -- Azure pipeline dependency audit or SCA signal detected

- **Category**: `supply_chain`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `azure-level-1`, `azure-level-2`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-SBOM-033` -- Azure pipeline SBOM generation signal detected

- **Category**: `supply_chain`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `azure-level-1`, `azure-level-2`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-PLAT-034` -- Azure Repos branch policy posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (4): `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`

### `AZ-PLAT-035` -- Azure pipeline governance posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (4): `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`

### `AZ-IDENT-036` -- Azure deployment identity federation posture

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (5): `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`

### `AZ-SCONN-056` -- Azure DevOps service connection authentication posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (2): `azure-level-3`, `azure-release-hardening-3`

### `AZ-WIFEV-057` -- Azure DevOps workload identity federation posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (2): `azure-level-3`, `azure-release-hardening-3`

### `AZ-ARTSBOM-058` -- Azure DevOps SBOM attested against a concrete release artifact digest

- **Category**: `supply_chain`
- **Assurance**: `evidence-backed` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (2): `azure-level-3`, `azure-release-hardening-3`

### `AZ-ARTPRV-059` -- Azure DevOps provenance or attestation attested against a concrete release artifact digest

- **Category**: `supply_chain`
- **Assurance**: `evidence-backed` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (2): `azure-level-3`, `azure-release-hardening-3`

### `AWS-CI-037` -- AWS CodeBuild buildspec or committed CodePipeline file exists

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (7): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`

### `AWS-SECRET-038` -- CodeBuild buildspec avoids inline secret anti-patterns and prefers managed secret sources

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (7): `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`

### `AWS-SEC-039` -- Security scanning signal in CodeBuild buildspec

- **Category**: `vulnerability_management`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `aws-level-1`, `aws-level-2`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`

### `AWS-SCA-040` -- Dependency audit or SCA signal in CodeBuild buildspec

- **Category**: `supply_chain`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `aws-level-1`, `aws-level-2`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`

### `AWS-SBOM-041` -- SBOM generation signal in CodeBuild buildspec

- **Category**: `supply_chain`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `aws-level-1`, `aws-level-2`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`

### `AWS-PIPE-042` -- Committed CodePipeline export under pipelines/aws/ with minimal useful structure

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (5): `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`

### `AWS-PROV-043` -- Provenance or attestation signal in CodeBuild buildspec

- **Category**: `supply_chain`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (4): `aws-level-2`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`

### `AWS-CP-044` -- CodePipeline promotion and artifact governance evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (4): `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`

### `AWS-CB-045` -- CodeBuild project posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (4): `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`

### `AWS-PIPEIAM-056` -- CodePipeline service role / IAM execution boundary evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (2): `aws-level-3`, `aws-release-hardening-3`

### `AWS-CBIDENT-057` -- CodeBuild project identity and credential boundary evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (2): `aws-level-3`, `aws-release-hardening-3`

### `AWS-SBOMART-058` -- SBOM attested against a concrete release artifact digest

- **Category**: `supply_chain`
- **Assurance**: `evidence-backed` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (2): `aws-level-3`, `aws-release-hardening-3`

### `AWS-PROVART-059` -- Provenance or attestation attested against a concrete release artifact digest

- **Category**: `supply_chain`
- **Assurance**: `evidence-backed` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (2): `aws-level-3`, `aws-release-hardening-3`

### `SEC-SECRETS-050` -- Secret scanning tool in CI

- **Category**: `vulnerability_management`
- **Assurance**: `signal` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (3): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`

### `SEC-GITIGNORE-051` -- .gitignore present with basic secret protection patterns

- **Category**: `governance`
- **Assurance**: `deterministic` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (14): `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`

### `SEC-PINLOCK-052` -- Dependency lockfile or pinned dependencies present

- **Category**: `supply_chain`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (14): `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`

### `GH-MERGEQ-053` -- GitHub merge queue or merge_group trigger posture

- **Category**: `ci_cd`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (5): `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-3`

### `GOV-EVIDFRESH-054` -- Collected evidence under .oss-policy-kit/evidence is not stale

- **Category**: `governance`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (9): `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`

### `CI-WFCALLSHA-055` -- Reusable workflow calls pinned to immutable commit SHAs

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (2): `github-level-3`, `github-release-hardening-3`

### `DEP-UPDATE-001` -- Automated dependency update tool configured (Dependabot or Renovate)

- **Category**: `supply_chain`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (14): `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `OSS-SCORECARD-001` -- OpenSSF Scorecard score meets minimum threshold

- **Category**: `vulnerability_management`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (4): `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `CONT-IMAGE-001` -- Dockerfile base images pinned to immutable digest

- **Category**: `supply_chain`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (14): `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `CONT-IMAGE-002` -- Dockerfile declares non-root USER

- **Category**: `ci_cd`
- **Assurance**: `deterministic` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `automated`
- **Profiles** (14): `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `CONT-IMAGE-003` -- Container image scanning signal in CI

- **Category**: `vulnerability_management`
- **Assurance**: `signal` · **Weight**: 1 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (14): `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`

### `ORG-MFA-001` -- Organization MFA enforcement posture evidenced

- **Category**: `platform`
- **Assurance**: `evidence-backed` · **Weight**: 3 · **Lifecycle**: `stable` · **Automation**: `not_observable_locally`
- **Profiles** (6): `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`, `github-level-3`, `github-release-hardening-3`

### `BUILD-SBOM-QUAL-003` -- SBOM format validity and completeness signal

- **Category**: `supply_chain`
- **Assurance**: `signal` · **Weight**: 2 · **Lifecycle**: `stable` · **Automation**: `partially_observable`
- **Profiles** (6): `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`, `github-level-3`, `github-release-hardening-3`
