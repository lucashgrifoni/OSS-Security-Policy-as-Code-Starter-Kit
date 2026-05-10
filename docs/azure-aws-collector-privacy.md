# Azure / AWS evidence collection — permissions and privacy boundaries

The kit's `collect-evidence` subcommand can talk to Azure DevOps and AWS to gather posture evidence. This page describes the **least-privilege** credential expectations and the **privacy invariants** that apply to every artifact the kit writes.

`collect-evidence` is opt-in, read-only, and never persists tokens. If you only need clone-visible evaluation, you do not need this page — `evaluate` works without any cloud credentials.

## Required permissions

### Azure DevOps

The kit's Azure collector expects a Personal Access Token (PAT) or service-connection-issued token with the **minimum** scopes below. Anything broader is more access than the kit needs.

| Scope | Why |
|---|---|
| `Code (read)` | Branch policy enumeration, repository discovery. |
| `Build (read)` | Pipeline definition export and run history. |
| `Project and team (read)` | Resolving project context for the pipeline. |
| (optional) `Service Connections (read)` | Service connection posture; advisory only. |

The collector **never** writes to Azure DevOps and **never** uses scopes outside the read family.

### AWS

The AWS collector uses standard AWS SDK credential resolution (env vars, profiles, instance role). The IAM policy attached to the principal should grant only:

| Action | Resource | Why |
|---|---|---|
| `codepipeline:GetPipeline` | `arn:aws:codepipeline:*:*:*` | Read pipeline structure. |
| `codepipeline:ListPipelines` | `*` | Discovery. |
| `codebuild:BatchGetProjects` | `arn:aws:codebuild:*:*:project/*` | Read CodeBuild project posture. |
| `codebuild:ListProjects` | `*` | Discovery. |
| `iam:GetRole` | the specific service role ARN | Only required for IAM-aware evaluators; can be omitted. |

The collector never calls write actions. There is no IAM permission required to *update* anything.

## Privacy invariants (apply to every artifact the kit writes)

The following identifiers must NEVER appear in tracked files, generated reports, SARIF logs, evidence JSON committed to a repository, or release assets:

- Personal email addresses or consumer email domains.
- Local workstation or runner filesystem paths.
- Real Azure organization, directory, or cloud account identifiers.
- Real Azure DevOps organization names where they identify a private tenant.
- Real AWS account IDs.
- Real service connection identifiers that map to a private tenant.
- Self-hosted runner machine names.
- Tokens, secrets, or credential-looking strings.
- Internal project planning, prompt, traceability, or validation artifacts.

Synthetic placeholders to use in fixtures, docs, and tests:

| Domain | Placeholder |
|---|---|
| Azure org | `example-azure-org` |
| Azure project | `example-project` |
| Azure service connection | `example-service-connection` |
| AWS account | `000000000000` |
| AWS role ARN | `arn:aws:iam::000000000000:role/example-role` |
| Repo URL | `https://example.invalid/example/example-repo` |
| Email | `noreply@example.invalid` |

## How the v1 evidence model surfaces privacy

`reports/1.0` projects every result through `oss_policy_kit.application.evidence_projection.project_evidence`. The projection redacts host paths and never persists raw tokens or auth headers. Specifically:

- `evidence.references[i].value` is path-redacted (`<redacted-absolute>/...`) when the source string was an absolute filesystem path.
- `evidence.references[i].redacted` is `True` when redaction occurred — downstream tools can flag the result as having had unsafe input.
- `evidence.collected_at` is stored as the originally supplied ISO8601 string; consumers should verify it does not embed a workstation hostname or a private timezone.
- `evidence.source_platform` is one of the public-safe values (`github`, `azure`, `aws`, `local`, or null) — not a private organization identifier.

## Stale evidence handling

Evidence with a `collected_at` older than 90 days projects to `freshness_status: stale` and `trust_level: declared`. Hard-gate profiles will surface this through the `evidence.limitations` array. Custom freshness windows are available at the projection level via `FreshnessContext(window_days=N)`.

## When a collector value cannot be safely emitted

If a collector cannot redact or normalize a value safely (for example, a service connection identifier that embeds private account context), the collector should:

1. Replace the value with the synthetic placeholder from the table above.
2. Set `evidence.references[i].redacted = True`.
3. Append a string to `evidence.limitations` explaining why the field is suppressed.

This keeps evidence-backed evaluation honest without leaking private tenant data.

## Validating before you publish

Before sharing evidence files or a SARIF log, run a privacy spot-check:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 \
  --output-dir ./out/privacy-check --sarif-output evaluation-report.sarif
gitleaks detect --source ./out/privacy-check --redact --no-banner
```

If `gitleaks` reports anything, treat it as a release blocker.

For the full release-time hygiene gate see `docs/release-readiness.md`.
