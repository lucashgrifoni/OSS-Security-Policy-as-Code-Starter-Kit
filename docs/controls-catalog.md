# Controls Catalog (212 controls)

Single-page reference generated from the bundled control catalog and profiles. The authoritative source is [`src/oss_policy_kit/data/controls/catalog.yaml`](../src/oss_policy_kit/data/controls/catalog.yaml).

Current bundled state: **212 controls** across **56 bundled profiles**. Regenerate this page whenever the catalog or profile membership changes (`python scripts/generate-controls-catalog.py`).

> **Tip:** for an interactive, filterable view of this same catalog (filter by family, assurance, lifecycle, or profile membership, plus text search) see the **Control catalog** section of the project landing page: <https://lucashgrifoni.github.io/OSS-Security-Policy-as-Code-Starter-Kit/#catalog>.

## By Category

| Category | Count |
|---|---:|
| `ci_cd` | 41 |
| `container` | 7 |
| `governance` | 15 |
| `iac` | 30 |
| `kubernetes` | 16 |
| `platform` | 15 |
| `release` | 3 |
| `secure_development` | 45 |
| `supply_chain` | 31 |
| `vulnerability_management` | 9 |

## By Assurance

| Assurance | Count | Meaning |
|---|---:|---|
| `deterministic` | 31 | Structural parse or file presence/absence with high confidence. |
| `evidence-backed` | 89 | Depends on a local JSON evidence file or API-collected attestation. |
| `signal` | 92 | Heuristic or directional signal; PASS is not proof of runtime behavior. |

## Full Catalog

Profile counts in the **Profiles** column reflect how many bundled profiles include the control. See [profiles/overview.md](profiles/overview.md) for the bundled profile ladder.

| Control ID | Category | Assurance | Weight | Profiles | Title |
|---|---|---|---:|---:|---|
| `GOV-SEC-001` | governance | deterministic | 3 | 45 | SECURITY.md present |
| `GOV-CON-002` | governance | deterministic | 1 | 29 | CONTRIBUTING guide present |
| `GOV-COWN-003` | governance | deterministic | 2 | 31 | CODEOWNERS configured |
| `GOV-LIC-004` | governance | deterministic | 1 | 32 | LICENSE file present |
| `CI-WF-005` | ci_cd | deterministic | 2 | 12 | GitHub Actions workflows exist |
| `CI-PERM-006` | ci_cd | deterministic | 3 | 14 | Workflows declare explicit top-level permissions |
| `CI-DANGER-007` | ci_cd | deterministic | 3 | 10 | No pull_request_target without strong justification |
| `CI-PIN-008` | supply_chain | deterministic | 3 | 20 | Third-party actions pinned to immutable references |
| `CI-LEAST-009` | ci_cd | signal | 2 | 10 | Workflow permissions are not obviously over-broad |
| `SEC-CODEQL-010` | vulnerability_management | signal | 2 | 12 | CodeQL or equivalent security scanning in CI |
| `SEC-DEPREV-011` | supply_chain | deterministic | 2 | 26 | Dependency review in pull requests |
| `REL-CHANGE-012` | release | deterministic | 1 | 34 | Changelog or documented release notes |
| `GOV-DISC-013` | governance | signal | 2 | 44 | Responsible disclosure channel documented |
| `GOV-WAIV-014` | governance | deterministic | 1 | 42 | Versioned waiver policy file present in repository (not CLI-only waivers) |
| `PLAT-BRPROT-015` | platform | evidence-backed | 3 | 14 | Default branch protection / rulesets (evidence-backed) |
| `GH-WF-018` | ci_cd | deterministic | 2 | 9 | Reusable workflows avoid secrets inherit |
| `GH-WF-019` | ci_cd | deterministic | 2 | 9 | PR-triggered workflows avoid self-hosted runners |
| `GH-WF-020` | ci_cd | deterministic | 2 | 8 | Job-level permissions avoid broad write scopes |
| `GH-REL-021` | release | signal | 1 | 7 | Release/deploy workflows declare concurrency controls |
| `GH-DEPLOY-022` | platform | signal | 2 | 5 | Cloud deployment workflows show OIDC posture |
| `GH-PROV-023` | supply_chain | evidence-backed | 2 | 12 | Build provenance or artifact attestation signal in workflows (with optional verification-block confirmation) |
| `GH-PLAT-024` | platform | evidence-backed | 3 | 9 | GitHub rulesets posture evidenced |
| `GH-PLAT-025` | platform | evidence-backed | 3 | 7 | GitHub environment protection posture evidenced |
| `GH-PLAT-026` | platform | evidence-backed | 2 | 8 | GitHub secret scanning posture evidenced |
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
| `AWS-PIPEIAM-056` | platform | evidence-backed | 3 | 2 | CodePipeline service role / IAM execution boundary evidenced |
| `AWS-CBIDENT-057` | platform | evidence-backed | 3 | 2 | CodeBuild project identity and credential boundary evidenced |
| `AWS-SBOMART-058` | supply_chain | evidence-backed | 2 | 2 | SBOM attested against a concrete release artifact digest |
| `AWS-PROVART-059` | supply_chain | evidence-backed | 2 | 2 | Provenance or attestation attested against a concrete release artifact digest |
| `SEC-SECRETS-050` | vulnerability_management | signal | 2 | 11 | Secret scanning tool in CI |
| `SEC-GITIGNORE-051` | governance | deterministic | 1 | 18 | .gitignore present with basic secret protection patterns |
| `SEC-PINLOCK-052` | supply_chain | deterministic | 2 | 23 | Dependency lockfile or pinned dependencies present |
| `GH-MERGEQ-053` | ci_cd | signal | 1 | 6 | GitHub merge queue or merge_group trigger posture |
| `GOV-EVIDFRESH-054` | governance | deterministic | 2 | 23 | Collected evidence under .oss-policy-kit/evidence is not stale |
| `CI-WFCALLSHA-055` | ci_cd | deterministic | 3 | 9 | Reusable workflow calls pinned to immutable commit SHAs |
| `DEP-UPDATE-001` | supply_chain | deterministic | 2 | 32 | Automated dependency update tool configured (Dependabot or Renovate) |
| `OSS-SCORECARD-001` | vulnerability_management | signal | 1 | 7 | OpenSSF Scorecard score meets minimum threshold |
| `CONT-IMAGE-001` | supply_chain | deterministic | 2 | 17 | Dockerfile base images pinned to immutable digest |
| `CONT-IMAGE-002` | ci_cd | deterministic | 2 | 17 | Dockerfile declares non-root USER |
| `CONT-IMAGE-003` | vulnerability_management | signal | 1 | 17 | Container image scanning signal in CI |
| `ORG-MFA-001` | platform | evidence-backed | 3 | 14 | Organization MFA enforcement posture evidenced |
| `BUILD-SBOM-QUAL-003` | supply_chain | signal | 2 | 24 | SBOM format validity and completeness signal |
| `AUDIT-STREAM-060` | governance | evidence-backed | 2 | 14 | Audit log streaming to centralized SIEM/object store |
| `PROV-VERIFY-061` | supply_chain | evidence-backed | 3 | 16 | Build provenance attestation is verifiable (sigstore / Artifact Attestations) |
| `GH-RUNNER-062` | ci_cd | signal | 3 | 7 | Self-hosted runners are ephemeral and restricted from PR-triggered workflows |
| `RELEASE-ARCHIVE-063` | release | signal | 2 | 7 | Release artifacts have an explicit archival/retention policy |
| `SAST-SEMGREP-064` | ci_cd | evidence-backed | 3 | 1 | SAST scan evidence (Semgrep) is present and current |
| `GOV-DISC-065` | governance | evidence-backed | 2 | 5 | Disclosure channel SLA documented (CRA reporting readiness) |
| `SAST-ZIZMOR-066` | ci_cd | evidence-backed | 2 | 1 | zizmor SARIF findings (GitHub Actions security AST analysis) |
| `SAST-POUTINE-067` | ci_cd | evidence-backed | 2 | 2 | poutine SARIF findings (GitHub Actions / GitLab CI pipeline scanner) |
| `SAST-OSV-068` | supply_chain | evidence-backed | 3 | 6 | OSV-Scanner v2 SARIF findings (reachability-aware SCA) |
| `SAST-GITLEAKS-069` | secure_development | evidence-backed | 3 | 2 | Gitleaks SARIF findings (secret leak detection) |
| `GL-PIPE-001` | ci_cd | deterministic | 1 | 6 | GitLab CI pipeline files present and parseable |
| `GL-PIPE-002` | ci_cd | signal | 2 | 6 | GitLab CI image references pinned to a tag or digest |
| `GL-PIPE-003` | ci_cd | signal | 3 | 6 | GitLab CI scripts do not pipe network downloads to a shell |
| `GL-PIPE-004` | ci_cd | deterministic | 2 | 6 | GitLab CI jobs do not declare broad `inherit: secrets: true` |
| `GL-PIPE-005` | ci_cd | signal | 2 | 6 | GitLab CI `include:` does not reference unpinned remote URLs |
| `GL-PIPE-006` | ci_cd | signal | 1 | 6 | GitLab CI jobs use trigger restrictions (`rules:` / `only:` / `except:`) |
| `IAC-TF-001` | iac | evidence-backed | 3 | 1 | Terraform - object storage configured for public access |
| `IAC-TF-002` | iac | evidence-backed | 3 | 1 | Terraform - security group exposes management port to 0.0.0.0/0 |
| `IAC-TF-003` | iac | evidence-backed | 3 | 1 | Terraform - IAM grants AdministratorAccess or Action=* + Resource=* |
| `IAC-TF-004` | iac | evidence-backed | 2 | 1 | Terraform - storage / RDS / EBS resource without encryption-at-rest |
| `IAC-TF-005` | iac | evidence-backed | 2 | 1 | Terraform - audit / access logging disabled on sensitive resources |
| `IAC-TF-006` | iac | evidence-backed | 2 | 1 | Terraform - default VPC / subnet / security group used in declarations |
| `IAC-TF-007` | iac | evidence-backed | 2 | 1 | Terraform - workload assigned a public IP without explicit intent |
| `IAC-TF-008` | iac | evidence-backed | 1 | 1 | Terraform - AWS resources without owner / cost_center tags |
| `IAC-TF-009` | iac | evidence-backed | 1 | 1 | Terraform - provider versions not pinned in required_providers |
| `IAC-TF-010` | iac | evidence-backed | 1 | 1 | Terraform - local backend used (no remote + encryption + locking) |
| `IAC-TF-011` | iac | evidence-backed | 2 | 1 | Terraform - production-naming data store missing lifecycle.prevent_destroy |
| `IAC-TF-012` | iac | evidence-backed | 1 | 1 | Terraform - data.aws_iam_policy_document uses wildcard principal '*' |
| `SEC-FUZZ-001` | vulnerability_management | signal | 2 | 8 | Fuzzing presence (OSS-Fuzz / cifuzz / atheris / Scorecard Fuzzing) |
| `CONT-RUNTIME-001` | container | signal | 2 | 1 | Container - multi-stage Dockerfile build |
| `CONT-RUNTIME-002` | container | signal | 1 | 1 | Container - Dockerfile HEALTHCHECK declared |
| `CONT-RUNTIME-003` | container | signal | 2 | 1 | Container - no curl|bash / wget|sh patterns in Dockerfile RUN |
| `CONT-RUNTIME-004` | container | signal | 1 | 1 | Container - .dockerignore present |
| `CONT-RUNTIME-005` | container | signal | 2 | 1 | Container - apt-get hygiene (--no-install-recommends or cache cleanup) |
| `CONT-RUNTIME-006` | container | signal | 1 | 1 | Container - OS package versions pinned in apt/apk install |
| `CONT-SIGN-001` | supply_chain | signal | 3 | 1 | Container - image signed via cosign or GitHub artifact attestations |
| `K8S-PSS-001` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - privileged container detected |
| `K8S-PSS-002` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - pod uses hostPID=true |
| `K8S-PSS-003` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - pod uses hostNetwork=true |
| `K8S-PSS-004` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - pod mounts hostPath volume |
| `K8S-PSS-005` | kubernetes | evidence-backed | 2 | 1 | Kubernetes - container adds Linux capabilities |
| `K8S-PSS-006` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - container may run as root (runAsNonRoot/runAsUser not pinned) |
| `K8S-PSS-007` | kubernetes | evidence-backed | 2 | 1 | Kubernetes - allowPrivilegeEscalation not set to false |
| `K8S-PSS-008` | kubernetes | evidence-backed | 2 | 1 | Kubernetes - readOnlyRootFilesystem not true |
| `K8S-PSS-009` | kubernetes | evidence-backed | 1 | 1 | Kubernetes - automountServiceAccountToken not pinned |
| `K8S-PSS-010` | kubernetes | evidence-backed | 2 | 1 | Kubernetes - container image uses latest / unpinned tag |
| `K8S-RBAC-001` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - Role / ClusterRole grants wildcard verb '*' |
| `K8S-RBAC-002` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - RoleBinding / ClusterRoleBinding binds to cluster-admin |
| `K8S-RBAC-003` | kubernetes | evidence-backed | 1 | 1 | Kubernetes - workload uses default ServiceAccount in default namespace |
| `K8S-RBAC-004` | kubernetes | evidence-backed | 2 | 1 | Kubernetes - ClusterRole grants wildcard resource '*' |
| `K8S-RBAC-005` | kubernetes | evidence-backed | 3 | 1 | Kubernetes - Role / ClusterRole grants broad read on secrets |
| `K8S-NETPOL-001` | kubernetes | evidence-backed | 2 | 1 | Kubernetes - namespace with workloads but no NetworkPolicy |
| `IAC-CFN-001` | iac | evidence-backed | 3 | 1 | CloudFormation - S3 bucket configured for public access |
| `IAC-CFN-002` | iac | evidence-backed | 3 | 1 | CloudFormation - security group exposes management port to 0.0.0.0/0 |
| `IAC-CFN-003` | iac | evidence-backed | 3 | 1 | CloudFormation - IAM grants AdministratorAccess or Action=* + Resource=* |
| `IAC-CFN-004` | iac | evidence-backed | 2 | 1 | CloudFormation - storage / RDS / EBS resource without encryption-at-rest |
| `IAC-CFN-005` | iac | evidence-backed | 2 | 1 | CloudFormation - audit / access logging disabled on sensitive resources |
| `IAC-CFN-006` | iac | evidence-backed | 2 | 1 | CloudFormation - workload assigned a public IP without explicit intent |
| `IAC-PUL-001` | iac | evidence-backed | 3 | 1 | Pulumi - object storage configured for public access |
| `IAC-PUL-002` | iac | evidence-backed | 3 | 1 | Pulumi - security group exposes management port to 0.0.0.0/0 |
| `IAC-PUL-003` | iac | evidence-backed | 3 | 1 | Pulumi - IAM grants AdministratorAccess or Action=* + Resource=* |
| `IAC-PUL-004` | iac | evidence-backed | 2 | 1 | Pulumi - storage / RDS / EBS resource without encryption-at-rest |
| `IAC-PUL-005` | iac | evidence-backed | 2 | 1 | Pulumi - default VPC / subnet / security group used in declarations |
| `IAC-PUL-006` | iac | evidence-backed | 2 | 1 | Pulumi - workload assigned a public IP without explicit intent |
| `IAC-BICEP-001` | iac | evidence-backed | 3 | 1 | Bicep - storage account configured for public access |
| `IAC-BICEP-002` | iac | evidence-backed | 3 | 1 | Bicep - NSG rule allows management port inbound from '*' |
| `IAC-BICEP-003` | iac | evidence-backed | 3 | 1 | Bicep - role assignment grants Owner / Contributor / User Access Admin |
| `IAC-BICEP-004` | iac | evidence-backed | 2 | 1 | Bicep - storage / SQL / disk resource without encryption-at-rest |
| `IAC-BICEP-005` | iac | evidence-backed | 1 | 1 | Bicep - sensitive resource has no diagnosticSettings paired |
| `IAC-BICEP-006` | iac | evidence-backed | 2 | 1 | Bicep - direct public IP declared without documented intent |
| `SEC-WEBHOOK-001` | secure_development | signal | 3 | 2 | Webhook receiver verifies inbound signature |
| `SEC-WEBHOOK-002` | secure_development | signal | 2 | 2 | Webhook receiver implements replay defense (timestamp / nonce / idempotency) |
| `GH-EGRESS-HRN-001` | ci_cd | signal | 2 | 0 | GitHub Actions workflows declare Harden-Runner egress controls |
| `SEC-WEBHOOK-HMAC-001` | secure_development | signal | 3 | 1 | Webhook receiver invokes an HMAC verification helper |
| `SEC-WEBHOOK-TIMING-002` | secure_development | signal | 2 | 1 | Webhook signature comparison uses a timing-safe primitive |
| `SEC-WEBHOOK-REPLAY-003` | secure_development | signal | 2 | 1 | Webhook receiver enforces a timestamp tolerance or nonce window |
| `SEC-WEBHOOK-BODY-004` | secure_development | signal | 1 | 1 | Webhook receiver caps request-body size at the framework or proxy layer |
| `SEC-WEBHOOK-IDEMP-005` | secure_development | signal | 2 | 1 | Webhook receiver extracts an idempotency key and dedupes per delivery |
| `SEC-WEBHOOK-ROTATE-006` | secure_development | signal | 2 | 1 | Webhook secret sourced from env/vault and supports rotation window |
| `PUBLISH-OIDC-001` | ci_cd | signal | 3 | 1 | Publish workflow declares OIDC id-token permission |
| `PUBLISH-OIDC-002` | ci_cd | signal | 2 | 1 | PyPI / RubyGems / crates publish step omits long-lived password |
| `PUBLISH-OIDC-003` | ci_cd | signal | 2 | 1 | npm publish step uses --provenance (or registry-equivalent flag) |
| `SLSA-SRC-001` | supply_chain | deterministic | 1 | 2 | Version-controlled source (SLSA Source Track L1 baseline) |
| `SLSA-SRC-002` | supply_chain | signal | 2 | 2 | Commit-signature enforcement signal detected (SLSA Source verified history) |
| `SLSA-SRC-003` | supply_chain | signal | 2 | 2 | Branch protection present (SLSA Source protected branches) |
| `SLSA-SRC-004` | supply_chain | signal | 2 | 2 | Two-party review required on protected branches (SLSA Source) |
| `SLSA-SRC-005` | supply_chain | signal | 2 | 2 | Audit log of source-changing events (SLSA Source auditability) |
| `GL-PIPE-007` | ci_cd | signal | 3 | 4 | GitLab CI workflow uses OIDC (id_tokens) for cloud / registry access |
| `GL-PIPE-008` | ci_cd | signal | 2 | 4 | GitLab CI restricts self-hosted runner usage via tags |
| `GL-PIPE-009` | ci_cd | signal | 2 | 4 | GitLab project documents audit-event streaming or external export |
| `GL-PIPE-010` | ci_cd | signal | 2 | 4 | GitLab CI environment approval rules declared for protected envs |
| `GL-PIPE-011` | ci_cd | signal | 2 | 4 | GitLab CI merge-request rules enforce code-review approvals |
| `GL-PIPE-012` | ci_cd | signal | 1 | 4 | GitLab CI artifact retention or signed-release posture documented |
| `AIBOM-PRESENT-001` | supply_chain | signal | 2 | 2 | AI Bill of Materials present in evidence directory |
| `LLM-218A-PO-001` | secure_development | signal | 2 | 4 | AI Security Considerations section present in SECURITY.md or README |
| `LLM-218A-PO-002` | secure_development | signal | 1 | 1 | Prompt / system-instruction registry directory present |
| `LLM-218A-PS-001` | secure_development | evidence-backed | 3 | 2 | LLM release-integrity evidence file populated |
| `LLM-218A-PS-002` | secure_development | signal | 1 | 1 | Model versioning artifacts (semver tags or release matching model/*) |
| `LLM-218A-PW-001` | secure_development | signal | 2 | 1 | LLM SDK dependencies declared (transformers / openai / anthropic / langchain) |
| `LLM-218A-PW-002` | secure_development | signal | 2 | 1 | Prompt-injection or adversarial test file present |
| `LLM-218A-RV-001` | secure_development | signal | 1 | 1 | Dependabot or Renovate config explicitly lists LLM SDKs |
| `LLM-AI-ACT-001` | secure_development | signal | 2 | 1 | Intended purpose / users / limitations documented (EU AI Act Annex IV §1) |
| `LLM-AI-ACT-002` | secure_development | signal | 2 | 1 | Output filtering / content moderation pattern detected (EU AI Act Annex IV §3) |
| `LLM-AI-ACT-003` | secure_development | signal | 2 | 1 | Risk management documentation present (EU AI Act Annex IV §5) |
| `WORM-POSTINSTALL-001` | supply_chain | signal | 3 | 1 | package.json postinstall script free of credential-harvest primitives (Shai-Hulud defense) |
| `WORM-LOCKFILE-DRIFT-001` | supply_chain | signal | 2 | 1 | package.json / pyproject.toml not modified more recently than lockfile (worm-rewrite signal) |
| `WORM-PUBLISH-SCOPE-001` | ci_cd | signal | 2 | 1 | Publish workflow restricted to main/release branches with explicit scope |
| `AI-AGENT-001` | secure_development | signal | 3 | 2 | MCP server authentication present |
| `AI-AGENT-002` | secure_development | signal | 3 | 2 | Agent tool allowlist explicitly defined |
| `AI-AGENT-003` | secure_development | signal | 2 | 1 | System prompt registry is versioned and code-reviewed |
| `AI-AGENT-004` | secure_development | signal | 2 | 1 | Prompt injection / adversarial agent tests present |
| `AI-AGENT-005` | secure_development | evidence-backed | 2 | 1 | Agent output sanitization layer documented |
| `AI-AGENT-006` | secure_development | signal | 2 | 1 | Agent rate limiting or quota configuration present |
| `AI-AGENT-007` | secure_development | evidence-backed | 3 | 1 | Agent tool-call audit logging configured |
| `AI-AGENT-008` | secure_development | signal | 2 | 1 | Dedicated agent identity or audience-bound authn configured |
| `AI-AGENT-009` | secure_development | evidence-backed | 2 | 1 | Sensitive context excluded from long-term agent memory |
| `AI-AGENT-010` | secure_development | signal | 3 | 1 | Model provider/version pinning enforced for agent runtime |
| `OSPS-SCORECARD-V6-001` | supply_chain | evidence-backed | 2 | 1 | OpenSSF Scorecard v6 OSPS Baseline conformance evidence present |
| `LLM-AI-ACT-DEV-002` | secure_development | evidence-backed | 2 | 1 | AI system development/design and training-data description documented (Annex IV section 2) |
| `LLM-AI-ACT-PERF-004` | secure_development | evidence-backed | 2 | 1 | AI system performance metrics and accuracy documented (Annex IV section 4) |
| `LLM-AI-ACT-CYBER-006` | secure_development | evidence-backed | 3 | 1 | AI system cybersecurity measures documented (Annex IV section 6) |
| `LLM-AI-ACT-CHANGE-007` | secure_development | evidence-backed | 2 | 1 | AI system lifecycle change record documented (Annex IV section 7) |
| `LLM-AI-ACT-STD-008` | secure_development | evidence-backed | 1 | 1 | Applied harmonised standards listed (Annex IV section 7) |
| `LLM-AI-ACT-PMM-009` | secure_development | evidence-backed | 2 | 1 | Post-market monitoring plan documented (Annex IV section 8) |
| `CRA-ART13-SBD-001` | governance | signal | 2 | 1 | Security-by-design intent declared (CRA Article 13) |
| `CRA-ART13-DEFAULTS-002` | governance | signal | 2 | 1 | Secure-by-default configuration documented (CRA Article 13) |
| `CRA-ART14-CSAF-001` | governance | signal | 2 | 1 | CSAF advisory feed present (CRA Article 14 reporting readiness) |
| `CRA-ART14-COORD-002` | governance | signal | 2 | 1 | Coordinated vulnerability disclosure policy documented (CRA Article 14) |
| `CRA-PRODUCT-CLASS-001` | governance | signal | 1 | 1 | CRA product classification declared (Implementing Reg (EU) 2025/2392) |
| `SCA-KEV-001` | vulnerability_management | evidence-backed | 3 | 1 | No dependency CVE present in the CISA KEV catalog (SARIF kev property) |
| `SCA-EPSS-001` | vulnerability_management | evidence-backed | 2 | 1 | No high-EPSS high-severity dependency CVE unaddressed (SARIF epss_score property) |
| `SLSA-SRC-006` | supply_chain | evidence-backed | 3 | 1 | Signed commits required (SLSA Source L2) |
| `SLSA-SRC-007` | supply_chain | evidence-backed | 2 | 1 | Two-party review threshold enforced (SLSA Source L2) |
| `SLSA-SRC-008` | supply_chain | evidence-backed | 2 | 1 | Source-change audit log streamed externally (SLSA Source L2) |
| `MCP-TOOL-HASH-001` | secure_development | signal | 3 | 2 | MCP tool descriptions hash-pinned (tool-poisoning defense) |
| `MCP-CONFIRM-001` | secure_development | signal | 2 | 2 | MCP destructive operations require explicit confirmation |
| `MCP-EGRESS-001` | secure_development | signal | 2 | 1 | MCP server egress allowlist documented |
| `MCP-INJECTION-TEST-001` | secure_development | signal | 1 | 1 | MCP prompt-injection / tool-poisoning tests present |
| `MCP-SCOPE-001` | secure_development | signal | 2 | 1 | MCP per-tool least-privilege scope documented |
| `AGENT-ASI-GOAL-001` | secure_development | signal | 2 | 1 | Agent goal/system-prompt version-controlled and integrity-checked (ASI01) |
| `AGENT-ASI-TOOL-002` | secure_development | signal | 2 | 1 | Agent tool allowlist with per-tool least privilege documented (ASI02) |
| `AGENT-ASI-MEMORY-006` | secure_development | signal | 2 | 1 | Agent persistent-memory purge / poisoning policy documented (ASI06) |
| `AGENT-ASI-INTER-007` | secure_development | signal | 2 | 1 | Inter-agent communication mutual authentication signal (ASI07) |
| `AGENT-ASI-CONFIRM-009` | secure_development | signal | 2 | 1 | Human checkpoint required for destructive agent operations (ASI09) |
| `GH-EGRESS-NATIVE-001` | ci_cd | signal | 2 | 1 | GitHub Actions native egress firewall policy declared |
| `GH-WF-LOCKFILE-001` | ci_cd | signal | 2 | 1 | GitHub Actions workflow lockfile present (action SHA pinning) |
| `CONT-DISTROLESS-001` | container | signal | 2 | 1 | Container base image is distroless / minimal (Chainguard, Wolfi, distroless, scratch) |
| `SCANNER-INTEGRITY-001` | ci_cd | signal | 2 | 1 | Scanner actions pinned by SHA (post-Trivy supply-chain defense) |

## Per-Control Profile Membership

Each control entry below lists which bundled profiles include it. Controls not present in any profile are marked `_not bundled in a profile_`.

- `GOV-SEC-001`: `appsec-agentic-asi-1`, `appsec-llm-ssdf-218a-1`, `appsec-mcp-server-1`, `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `cra-eu-ai-act-art11-1`, `cra-eu-ready-1`, `cra-eu-ready-2-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `oss-publish-readiness-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `slsa-build-l2-1`, `slsa-source-l1-1`, `slsa-source-l2-1`, `ssdf-baseline-1`, `webhook-security-2`
- `GOV-CON-002`: `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `ssdf-baseline-1`
- `GOV-COWN-003`: `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `ssdf-baseline-1`
- `GOV-LIC-004`: `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `slsa-build-l2-1`, `ssdf-baseline-1`
- `CI-WF-005`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `slsa-build-l2-1`
- `CI-PERM-006`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `oss-publish-readiness-1`, `owasp-cicd-top10-1`, `slsa-build-l2-1`
- `CI-DANGER-007`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`
- `CI-PIN-008`: `appsec-sast-sca-1`, `cis-supply-chain-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `oss-publish-readiness-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `slsa-build-l2-1`, `ssdf-baseline-1`
- `CI-LEAST-009`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`
- `SEC-CODEQL-010`: `appsec-sast-sca-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `ssdf-baseline-1`
- `SEC-DEPREV-011`: `appsec-sast-sca-1`, `cis-supply-chain-1`, `cra-eu-ready-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `ssdf-baseline-1`
- `REL-CHANGE-012`: `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `cra-eu-ai-act-art11-1`, `cra-eu-ready-1`, `cra-eu-ready-2-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `slsa-build-l2-1`
- `GOV-DISC-013`: `appsec-agentic-asi-1`, `appsec-llm-ssdf-218a-1`, `appsec-mcp-server-1`, `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `cra-eu-ai-act-art11-1`, `cra-eu-ready-1`, `cra-eu-ready-2-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `oss-publish-readiness-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `slsa-source-l1-1`, `slsa-source-l2-1`, `ssdf-baseline-1`, `webhook-security-2`
- `GOV-WAIV-014`: `appsec-agentic-asi-1`, `appsec-llm-ssdf-218a-1`, `appsec-mcp-server-1`, `appsec-sast-sca-1`, `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `cra-eu-ai-act-art11-1`, `cra-eu-ready-1`, `cra-eu-ready-2-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-1`, `github-level-2`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `oss-publish-readiness-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `slsa-source-l1-1`, `slsa-source-l2-1`, `ssdf-baseline-1`
- `PLAT-BRPROT-015`: `cis-supply-chain-1`, `cra-eu-ready-1`, `cra-eu-strict-1`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `ssdf-baseline-1`
- `GH-WF-018`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`, `slsa-build-l2-1`
- `GH-WF-019`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`, `slsa-build-l2-1`
- `GH-WF-020`: `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`, `slsa-build-l2-1`
- `GH-REL-021`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`
- `GH-DEPLOY-022`: `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-release-hardening-2`
- `GH-PROV-023`: `cis-supply-chain-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-release-hardening-2`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `s2c2f-l3-1`, `slsa-build-l2-1`, `ssdf-baseline-1`
- `GH-PLAT-024`: `cis-supply-chain-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `ssdf-baseline-1`
- `GH-PLAT-025`: `cis-supply-chain-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`, `ssdf-baseline-1`
- `GH-PLAT-026`: `appsec-sast-sca-1`, `cis-supply-chain-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`, `ssdf-baseline-1`
- `AZ-PIPE-027`: `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-PIPE-028`: `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-PIPE-029`: `azure-level-1`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-PIPE-030`: `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-SEC-031`: `azure-level-1`, `azure-level-2`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-SCA-032`: `azure-level-1`, `azure-level-2`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-SBOM-033`: `azure-level-1`, `azure-level-2`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-PLAT-034`: `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`
- `AZ-PLAT-035`: `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`
- `AZ-IDENT-036`: `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-azure-level-2`
- `AZ-SCONN-056`: `azure-level-3`, `azure-release-hardening-3`
- `AZ-WIFEV-057`: `azure-level-3`, `azure-release-hardening-3`
- `AZ-ARTSBOM-058`: `azure-level-3`, `azure-release-hardening-3`
- `AZ-ARTPRV-059`: `azure-level-3`, `azure-release-hardening-3`
- `AWS-CI-037`: `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`
- `AWS-SECRET-038`: `aws-level-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`
- `AWS-SEC-039`: `aws-level-1`, `aws-level-2`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`
- `AWS-SCA-040`: `aws-level-1`, `aws-level-2`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`
- `AWS-SBOM-041`: `aws-level-1`, `aws-level-2`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`
- `AWS-PIPE-042`: `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`
- `AWS-PROV-043`: `aws-level-2`, `aws-release-hardening-2`, `aws-release-hardening-3`, `github-aws-level-2`
- `AWS-CP-044`: `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`
- `AWS-CB-045`: `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`
- `AWS-PIPEIAM-056`: `aws-level-3`, `aws-release-hardening-3`
- `AWS-CBIDENT-057`: `aws-level-3`, `aws-release-hardening-3`
- `AWS-SBOMART-058`: `aws-level-3`, `aws-release-hardening-3`
- `AWS-PROVART-059`: `aws-level-3`, `aws-release-hardening-3`
- `SEC-SECRETS-050`: `appsec-sast-sca-1`, `cra-eu-ready-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `ssdf-baseline-1`
- `SEC-GITIGNORE-051`: `appsec-sast-sca-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `SEC-PINLOCK-052`: `appsec-sast-sca-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-1`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-1`, `azure-release-hardening-2`, `azure-release-hardening-3`, `cis-supply-chain-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `owasp-cicd-top10-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`
- `GH-MERGEQ-053`: `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-3`, `owasp-cicd-top10-1`
- `GOV-EVIDFRESH-054`: `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `container-baseline-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-1`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `iac-bicep-baseline-1`, `iac-cfn-baseline-1`, `iac-pulumi-baseline-1`, `iac-terraform-baseline-1`, `kubernetes-baseline-1`, `ssdf-baseline-1`, `webhook-security-1`, `webhook-security-2`
- `CI-WFCALLSHA-055`: `appsec-sast-sca-1`, `cis-supply-chain-1`, `github-level-3`, `github-release-hardening-3`, `owasp-cicd-top10-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `slsa-build-l2-1`, `ssdf-baseline-1`
- `DEP-UPDATE-001`: `appsec-llm-ssdf-218a-1`, `appsec-sast-sca-1`, `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `cis-supply-chain-1`, `cra-eu-ready-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `ssdf-baseline-1`
- `OSS-SCORECARD-001`: `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`
- `CONT-IMAGE-001`: `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `container-baseline-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `CONT-IMAGE-002`: `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `container-baseline-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `CONT-IMAGE-003`: `aws-level-2`, `aws-level-3`, `aws-release-hardening-2`, `aws-release-hardening-3`, `azure-level-2`, `azure-level-3`, `azure-release-hardening-2`, `azure-release-hardening-3`, `container-baseline-1`, `github-aws-level-2`, `github-azure-level-2`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `ORG-MFA-001`: `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`, `cis-supply-chain-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-3`, `gitlab-level-3`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `ssdf-baseline-1`
- `BUILD-SBOM-QUAL-003`: `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`, `cis-supply-chain-1`, `cra-eu-ready-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-3`, `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`, `osps-baseline-1`, `osps-baseline-2026-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`, `slsa-build-l2-1`, `ssdf-baseline-1`
- `AUDIT-STREAM-060`: `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`, `cra-eu-ready-1`, `cra-eu-reporting-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-3`, `gitlab-level-3`, `gitlab-release-hardening-3`, `owasp-cicd-top10-1`, `s2c2f-l3-1`, `ssdf-baseline-1`
- `PROV-VERIFY-061`: `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`, `cis-supply-chain-1`, `cra-eu-ready-1`, `cra-eu-strict-1`, `github-level-3`, `github-release-hardening-3`, `gitlab-level-3`, `gitlab-release-hardening-3`, `oss-publish-readiness-1`, `owasp-cicd-top10-1`, `s2c2f-l3-1`, `slsa-build-l2-1`, `ssdf-baseline-1`
- `GH-RUNNER-062`: `cis-supply-chain-1`, `github-level-2`, `github-level-3`, `github-release-hardening-2`, `github-release-hardening-3`, `owasp-cicd-top10-1`, `slsa-build-l2-1`
- `RELEASE-ARCHIVE-063`: `aws-release-hardening-3`, `azure-release-hardening-3`, `cis-supply-chain-1`, `cra-eu-ready-1`, `cra-eu-strict-1`, `github-release-hardening-3`, `gitlab-release-hardening-3`
- `SAST-SEMGREP-064`: `appsec-sast-sca-1`
- `GOV-DISC-065`: `cra-eu-ai-act-art11-1`, `cra-eu-ready-2-1`, `cra-eu-reporting-1`, `gitlab-level-3`, `gitlab-release-hardening-3`
- `SAST-ZIZMOR-066`: `appsec-sast-sca-1`
- `SAST-POUTINE-067`: `appsec-sast-sca-1`, `gitlab-release-hardening-3`
- `SAST-OSV-068`: `appsec-llm-ssdf-218a-1`, `appsec-sast-sca-1`, `cra-eu-ai-act-art11-1`, `cra-eu-ready-2-1`, `s2c2f-l2-1`, `s2c2f-l3-1`
- `SAST-GITLEAKS-069`: `appsec-sast-sca-1`, `s2c2f-l3-1`
- `GL-PIPE-001`: `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-002`: `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-003`: `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-004`: `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-005`: `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-006`: `gitlab-level-1`, `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-1`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `IAC-TF-001`: `iac-terraform-baseline-1`
- `IAC-TF-002`: `iac-terraform-baseline-1`
- `IAC-TF-003`: `iac-terraform-baseline-1`
- `IAC-TF-004`: `iac-terraform-baseline-1`
- `IAC-TF-005`: `iac-terraform-baseline-1`
- `IAC-TF-006`: `iac-terraform-baseline-1`
- `IAC-TF-007`: `iac-terraform-baseline-1`
- `IAC-TF-008`: `iac-terraform-baseline-1`
- `IAC-TF-009`: `iac-terraform-baseline-1`
- `IAC-TF-010`: `iac-terraform-baseline-1`
- `IAC-TF-011`: `iac-terraform-baseline-1`
- `IAC-TF-012`: `iac-terraform-baseline-1`
- `SEC-FUZZ-001`: `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`, `github-level-3`, `github-release-hardening-3`, `gitlab-level-3`, `gitlab-release-hardening-3`
- `CONT-RUNTIME-001`: `container-baseline-1`
- `CONT-RUNTIME-002`: `container-baseline-1`
- `CONT-RUNTIME-003`: `container-baseline-1`
- `CONT-RUNTIME-004`: `container-baseline-1`
- `CONT-RUNTIME-005`: `container-baseline-1`
- `CONT-RUNTIME-006`: `container-baseline-1`
- `CONT-SIGN-001`: `container-baseline-1`
- `K8S-PSS-001`: `kubernetes-baseline-1`
- `K8S-PSS-002`: `kubernetes-baseline-1`
- `K8S-PSS-003`: `kubernetes-baseline-1`
- `K8S-PSS-004`: `kubernetes-baseline-1`
- `K8S-PSS-005`: `kubernetes-baseline-1`
- `K8S-PSS-006`: `kubernetes-baseline-1`
- `K8S-PSS-007`: `kubernetes-baseline-1`
- `K8S-PSS-008`: `kubernetes-baseline-1`
- `K8S-PSS-009`: `kubernetes-baseline-1`
- `K8S-PSS-010`: `kubernetes-baseline-1`
- `K8S-RBAC-001`: `kubernetes-baseline-1`
- `K8S-RBAC-002`: `kubernetes-baseline-1`
- `K8S-RBAC-003`: `kubernetes-baseline-1`
- `K8S-RBAC-004`: `kubernetes-baseline-1`
- `K8S-RBAC-005`: `kubernetes-baseline-1`
- `K8S-NETPOL-001`: `kubernetes-baseline-1`
- `IAC-CFN-001`: `iac-cfn-baseline-1`
- `IAC-CFN-002`: `iac-cfn-baseline-1`
- `IAC-CFN-003`: `iac-cfn-baseline-1`
- `IAC-CFN-004`: `iac-cfn-baseline-1`
- `IAC-CFN-005`: `iac-cfn-baseline-1`
- `IAC-CFN-006`: `iac-cfn-baseline-1`
- `IAC-PUL-001`: `iac-pulumi-baseline-1`
- `IAC-PUL-002`: `iac-pulumi-baseline-1`
- `IAC-PUL-003`: `iac-pulumi-baseline-1`
- `IAC-PUL-004`: `iac-pulumi-baseline-1`
- `IAC-PUL-005`: `iac-pulumi-baseline-1`
- `IAC-PUL-006`: `iac-pulumi-baseline-1`
- `IAC-BICEP-001`: `iac-bicep-baseline-1`
- `IAC-BICEP-002`: `iac-bicep-baseline-1`
- `IAC-BICEP-003`: `iac-bicep-baseline-1`
- `IAC-BICEP-004`: `iac-bicep-baseline-1`
- `IAC-BICEP-005`: `iac-bicep-baseline-1`
- `IAC-BICEP-006`: `iac-bicep-baseline-1`
- `SEC-WEBHOOK-001`: `webhook-security-1`, `webhook-security-2`
- `SEC-WEBHOOK-002`: `webhook-security-1`, `webhook-security-2`
- `GH-EGRESS-HRN-001`: _not bundled in a profile_
- `SEC-WEBHOOK-HMAC-001`: `webhook-security-2`
- `SEC-WEBHOOK-TIMING-002`: `webhook-security-2`
- `SEC-WEBHOOK-REPLAY-003`: `webhook-security-2`
- `SEC-WEBHOOK-BODY-004`: `webhook-security-2`
- `SEC-WEBHOOK-IDEMP-005`: `webhook-security-2`
- `SEC-WEBHOOK-ROTATE-006`: `webhook-security-2`
- `PUBLISH-OIDC-001`: `oss-publish-readiness-1`
- `PUBLISH-OIDC-002`: `oss-publish-readiness-1`
- `PUBLISH-OIDC-003`: `oss-publish-readiness-1`
- `SLSA-SRC-001`: `slsa-source-l1-1`, `slsa-source-l2-1`
- `SLSA-SRC-002`: `slsa-source-l1-1`, `slsa-source-l2-1`
- `SLSA-SRC-003`: `slsa-source-l1-1`, `slsa-source-l2-1`
- `SLSA-SRC-004`: `slsa-source-l1-1`, `slsa-source-l2-1`
- `SLSA-SRC-005`: `slsa-source-l1-1`, `slsa-source-l2-1`
- `GL-PIPE-007`: `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-008`: `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-009`: `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-010`: `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-011`: `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `GL-PIPE-012`: `gitlab-level-2`, `gitlab-level-3`, `gitlab-release-hardening-2`, `gitlab-release-hardening-3`
- `AIBOM-PRESENT-001`: `appsec-llm-ssdf-218a-1`, `cra-eu-ai-act-art11-1`
- `LLM-218A-PO-001`: `appsec-agentic-asi-1`, `appsec-llm-ssdf-218a-1`, `appsec-mcp-server-1`, `cra-eu-ai-act-art11-1`
- `LLM-218A-PO-002`: `appsec-llm-ssdf-218a-1`
- `LLM-218A-PS-001`: `appsec-llm-ssdf-218a-1`, `cra-eu-ai-act-art11-1`
- `LLM-218A-PS-002`: `appsec-llm-ssdf-218a-1`
- `LLM-218A-PW-001`: `appsec-llm-ssdf-218a-1`
- `LLM-218A-PW-002`: `appsec-llm-ssdf-218a-1`
- `LLM-218A-RV-001`: `appsec-llm-ssdf-218a-1`
- `LLM-AI-ACT-001`: `cra-eu-ai-act-art11-1`
- `LLM-AI-ACT-002`: `cra-eu-ai-act-art11-1`
- `LLM-AI-ACT-003`: `cra-eu-ai-act-art11-1`
- `WORM-POSTINSTALL-001`: `oss-publish-readiness-1`
- `WORM-LOCKFILE-DRIFT-001`: `oss-publish-readiness-1`
- `WORM-PUBLISH-SCOPE-001`: `oss-publish-readiness-1`
- `AI-AGENT-001`: `ai-agent-baseline-1`, `appsec-mcp-server-1`
- `AI-AGENT-002`: `ai-agent-baseline-1`, `appsec-agentic-asi-1`
- `AI-AGENT-003`: `ai-agent-baseline-1`
- `AI-AGENT-004`: `ai-agent-baseline-1`
- `AI-AGENT-005`: `ai-agent-baseline-1`
- `AI-AGENT-006`: `ai-agent-baseline-1`
- `AI-AGENT-007`: `ai-agent-baseline-1`
- `AI-AGENT-008`: `ai-agent-baseline-1`
- `AI-AGENT-009`: `ai-agent-baseline-1`
- `AI-AGENT-010`: `ai-agent-baseline-1`
- `OSPS-SCORECARD-V6-001`: `osps-baseline-2026-1`
- `LLM-AI-ACT-DEV-002`: `cra-eu-ai-act-art11-1`
- `LLM-AI-ACT-PERF-004`: `cra-eu-ai-act-art11-1`
- `LLM-AI-ACT-CYBER-006`: `cra-eu-ai-act-art11-1`
- `LLM-AI-ACT-CHANGE-007`: `cra-eu-ai-act-art11-1`
- `LLM-AI-ACT-STD-008`: `cra-eu-ai-act-art11-1`
- `LLM-AI-ACT-PMM-009`: `cra-eu-ai-act-art11-1`
- `CRA-ART13-SBD-001`: `cra-eu-ready-2-1`
- `CRA-ART13-DEFAULTS-002`: `cra-eu-ready-2-1`
- `CRA-ART14-CSAF-001`: `cra-eu-ready-2-1`
- `CRA-ART14-COORD-002`: `cra-eu-ready-2-1`
- `CRA-PRODUCT-CLASS-001`: `cra-eu-ready-2-1`
- `SCA-KEV-001`: `appsec-sast-sca-1`
- `SCA-EPSS-001`: `appsec-sast-sca-1`
- `SLSA-SRC-006`: `slsa-source-l2-1`
- `SLSA-SRC-007`: `slsa-source-l2-1`
- `SLSA-SRC-008`: `slsa-source-l2-1`
- `MCP-TOOL-HASH-001`: `appsec-agentic-asi-1`, `appsec-mcp-server-1`
- `MCP-CONFIRM-001`: `appsec-agentic-asi-1`, `appsec-mcp-server-1`
- `MCP-EGRESS-001`: `appsec-mcp-server-1`
- `MCP-INJECTION-TEST-001`: `appsec-mcp-server-1`
- `MCP-SCOPE-001`: `appsec-mcp-server-1`
- `AGENT-ASI-GOAL-001`: `appsec-agentic-asi-1`
- `AGENT-ASI-TOOL-002`: `appsec-agentic-asi-1`
- `AGENT-ASI-MEMORY-006`: `appsec-agentic-asi-1`
- `AGENT-ASI-INTER-007`: `appsec-agentic-asi-1`
- `AGENT-ASI-CONFIRM-009`: `appsec-agentic-asi-1`
- `GH-EGRESS-NATIVE-001`: `oss-publish-readiness-1`
- `GH-WF-LOCKFILE-001`: `oss-publish-readiness-1`
- `CONT-DISTROLESS-001`: `container-baseline-1`
- `SCANNER-INTEGRITY-001`: `oss-publish-readiness-1`

