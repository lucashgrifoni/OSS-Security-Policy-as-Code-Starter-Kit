# Collector parity matrix (GitHub vs Azure vs AWS)

`collect-evidence` produces JSON files under `.oss-policy-kit/evidence/` that back the
`evidence-backed` controls in `*-level-3` and `*-release-hardening-3` profiles. The three
bundled collectors do not retrieve the same set of endpoints today; this page documents the
gap concretely so operators can see what `collect-evidence` will and will not produce, per
platform.

The authoritative sources are the collector classes under
`src/oss_policy_kit/infrastructure/collectors/` (`github_collector.py`,
`azure_collector.py`, `aws_collector.py`).

## Why parity matters

Hard-gate profiles (`*-level-3`, `*-release-hardening-3`) project an `evidence-backed`
control as `pass` only when the JSON is **API-collected** (`attested_by:
<platform>-api-collection` or `collection.evidence_collection_method: live`). A
hand-edited file passes through the engine as `self_attested` / `trust_level: declared`,
which the report Markdown surfaces honestly. See [results-guide.md](results-guide.md) and
[reports-contract-v1.0.md](reports-contract-v1.0.md) for the projection rules.

When a collector does **not** retrieve a given endpoint, the operator has two options:

1. Hand-fill the evidence JSON (synthetic / self-attested — the engine will mark it as such).
2. Treat that control as `manual-review-required` until the platform-specific tooling fills the gap.

Either way, the kit refuses to silently inflate trust.

## What each collector currently retrieves

### GitHub (`GitHubEvidenceCollector`)

| evidence_key | Source endpoint | Backs profile control(s) |
|---|---|---|
| `branch-protection` | `GET /repos/{owner}/{repo}/branches/{default}/protection` | `PLAT-BRPROT-015` |
| `github-rulesets` | `GET /repos/{owner}/{repo}/rulesets` | `GH-PLAT-024` |
| `github-secret-scanning` | `GET /repos/{owner}/{repo}` (`security_and_analysis`) | `GH-PLAT-025` |
| `github-environment-protection` | `GET /repos/{owner}/{repo}/environments` | `GH-PLAT-026` |

GitHub is **the most complete collector**: 4 endpoints feed 4 evidence keys covering the 4
GitHub-specific platform controls used by `github-level-3` and `github-release-hardening-3`.

### Azure DevOps (`AzureDevOpsEvidenceCollector`)

| evidence_key | Source endpoint | Backs profile control(s) |
|---|---|---|
| `azure-branch-policies` | `GET /{org}/{project}/_apis/policy/configurations?api-version=7.1` | `AZ-PLAT-034` |
| `azure-pipeline-governance` | `GET /{org}/{project}/_apis/pipelines?api-version=7.1` | `AZ-PLAT-035`, `AZ-SCONN-056`, `AZ-WIFEV-057`, `AZ-IDENT-036` |

Azure today retrieves **2 endpoints**. The pipeline governance file is overloaded — a single
JSON has to provide enough metadata for four different evaluators (platform pipeline state,
service connections, workload identity federation, deployment identity). A real-world Azure
evaluation can therefore reach `pass` on those four controls only if the project's pipeline
metadata is rich enough; otherwise some rows fall back to `self-attested`.

### AWS (`AWSEvidenceCollector`)

| evidence_key | Source endpoint | Backs profile control(s) |
|---|---|---|
| `aws-codebuild-project` | `codebuild.batch_get_projects` (when `AWS_CODEBUILD_PROJECT` is set) | AWS platform/IAM controls |
| `aws-codepipeline` | `codepipeline.get_pipeline` (when `AWS_CODEPIPELINE_NAME` is set) | AWS pipeline posture controls |

AWS today retrieves up to **2 endpoints**, but only when the right environment variables
are set. The collector is optional-by-design: AWS_CODEBUILD_PROJECT and AWS_CODEPIPELINE_NAME
each gate one collection path. If a customer uses CodeStar Connections, AWS Signer, or
another path the kit does not know about today, that posture stays self-attested.

## What is **not** API-collected today

These slots are evidence-backed by design but the kit ships **no** collector path. They are
maintainer-supplied, intentionally — the digests have to come from the actual release
pipeline (CycloneDX SBOM, in-toto/SLSA provenance), and exposing a digest via a REST API
without binding to a real artifact would be misleading.

| File / control | Platform | Source today | Why no collector |
|---|---|---|---|
| `azure-sbom-artifact.json` (`AZ-ARTSBOM-058`) | Azure | release pipeline emit | Digest is artifact-bound, not retrievable from REST APIs |
| `azure-provenance-artifact.json` (`AZ-ARTPRV-059`) | Azure | release pipeline emit | Same |
| `aws-sbom-artifact.json` (AWS artifact SBOM control) | AWS | release pipeline emit | Same |
| `aws-provenance-artifact.json` (AWS artifact provenance) | AWS | release pipeline emit | Same |
| `org-mfa-posture.json` (organization MFA) | All | maintainer attestation | Org-wide MFA enforcement is not exposed by repo-scoped APIs |

These intentionally stay as `self-attested` even after a successful `collect-evidence` run —
that is by design, not a parity gap. The fixture README documents the same boundary.

## Operational impact summary

- **GitHub** profiles (`github-level-3`, `github-release-hardening-3`) reach `pass` on the
  4 platform controls when `GITHUB_TOKEN` has the required permissions.
- **Azure** profiles reach `pass` on the 4 evidence-backed pipeline controls when
  `AZURE_DEVOPS_ORG` + `AZURE_DEVOPS_TOKEN` are set and the project metadata is complete.
  Artifact-bound rows (`AZ-ARTSBOM-058`, `AZ-ARTPRV-059`) stay `self-attested` until the
  release pipeline emits the digest files.
- **AWS** profiles reach `pass` on the 2-3 collected endpoints when the matching environment
  variables are set. Artifact-bound rows stay `self-attested` for the same reason.
- **All platforms**: `org-mfa-posture` stays `self-attested` until you wire your IdP /
  organization-level evidence manually.

## How to read the evidence projection in `reports/1.0`

Each control in `reports/1.0` carries an `evidence` object. The fields below decide whether
that control's `trust_level` becomes `verified` or stays `declared`:

```json
"evidence": {
  "source_type": "api_collected",        // vs "user_supplied", "static_clone", "heuristic_signal"
  "trust_level": "verified",             // vs "declared", "inferred", "unobserved"
  "collection_method": "live",           // vs "manual", "static"
  "collected_at": "2026-05-06T10:00Z",   // freshness anchor for the 90-day window
  "freshness_status": "fresh",           // vs "stale", "unknown", "not_applicable"
  "attestation_status": "signed",        // vs "self_attested", "none"
  "limitations": []
}
```

Consult [reports-contract-v1.0.md](reports-contract-v1.0.md) for the complete projection
rules and [signal-controls-audit.md](signal-controls-audit.md) for the rule that `signal`
controls cannot project to `verified` regardless of the collector path.

## Planned collector additions (post-v5.2.0)

The v5.1.0 / v5.2.0 controls `AUDIT-STREAM-060` and `RELEASE-ARCHIVE-063` are evidence-collectable from API endpoints that the bundled collectors do not yet call. The plan tracked for the next collector parity push:

| evidence_key | Platform | Source endpoint (planned) | Notes |
|---|---|---|---|
| `audit-log-streaming` | GitHub | `GET /orgs/{org}/audit-log/stream-key` | Org-scope token (`admin:org` read). Optional; collector will degrade gracefully when permissions are insufficient. |
| `audit-log-streaming` | Azure DevOps | `GET https://auditservice.dev.azure.com/{org}/_apis/audit/streams?api-version=7.1-preview.1` | Project Collection Administrator scope. |
| `audit-log-streaming` | AWS | `cloudtrail.describe-trails` (boto3) | Account-scope IAM role with `cloudtrail:DescribeTrails`. |
| `runner-groups` (GH-RUNNER-062 evidence path) | GitHub | `GET /orgs/{org}/actions/runner-groups` | Already a real endpoint; not in the v5.2.0 GitHub collector but trivial to add. Org-scope token. |
| `provenance verification` (PROV-VERIFY-061) | All | `gh attestation verify <artifact>` / `cosign verify-bundle` | The verification step itself is offline against the sigstore bundle; collector will emit the `verification:` block by invoking the CLI when present. |

Until the bundled collectors call these endpoints, the v5.1.0 / v5.2.0 controls behave as documented in their evaluators:

- `AUDIT-STREAM-060`: signal-grade fallback (clone marker file or doc keyword) → PASS at low confidence; evidence-backed → PASS at high confidence when JSON is API-collected.
- `PROV-VERIFY-061`: requires the operator to run `gh attestation verify` (or `cosign verify-bundle`) and write the `verification:` block into the existing `*-provenance-artifact.json`. The kit accepts the verification result; it does not run cosign itself.
- `GH-RUNNER-062`: signal-grade detection from workflow YAML; evidence-backed via hand-filled `runner-groups.json`.
- `RELEASE-ARCHIVE-063`: signal-grade detection of policy file; evidence-backed via hand-filled `release-archival-policy.json`.

The collector additions are scheduled as a separate engineering push (Phase C1 of the post-v5.0.0 maturity roadmap).

## See also

- [release-hardening-workflow.md](release-hardening-workflow.md) — when and how to wire
  `collect-evidence` in CI.
- [azure-aws-collector-privacy.md](azure-aws-collector-privacy.md) — what stamps the
  collectors place on emitted JSON and why.
- [profiles/overview.md](profiles/overview.md) — full profile ladder, including the
  "Maturity stance" callout that flags Azure / AWS L3 as "close — not equal — to GitHub
  hard-gate" until parity is closed.
