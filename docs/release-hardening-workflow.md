# Release-hardening workflow

This document explains how to use the strict L3 and release-hardening profiles
of OSS Policy Kit in a real CI pipeline, with the evidence that these profiles
require to produce meaningful results.

## Why evidence is required

Profiles with `evidence-backed` controls cannot be fully evaluated from the
clone alone. They need JSON evidence under `.oss-policy-kit/evidence/` that
describes platform configuration the git clone does not expose
(branch protection, environment protection, CodeBuild project settings,
Azure pipeline policies, service connections, artifact SBOM/provenance, etc.).

The kit defends against unfilled templates: controls whose evidence contains
placeholder tokens such as `REPLACE_ME`, `YOUR_*`, `PLACEHOLDER`, `TODO`, or
known scaffold SHA-256 digests are returned with status `not-evaluated` and
produce an operational warning, so placeholder evidence never inflates your
posture score.

## Two paths to produce evidence

### Path 1 - Manual scaffold (dry runs and local rehearsals)

```bash
python -m oss_policy_kit scaffold-evidence --target . --platform github
python -m oss_policy_kit scaffold-evidence --target . --platform aws
python -m oss_policy_kit scaffold-evidence --target . --platform azure
```

This creates template JSON files under `.oss-policy-kit/evidence/` that must
be edited by hand. Every scaffold field carrying `REPLACE_ME` or similar
tokens is treated as unfilled until you replace it with real data.

Use `--force` to overwrite an existing scaffold when re-seeding a dry run.

### Path 2 - Automatic collection via platform APIs (recommended in CI)

```bash
# GitHub
GITHUB_TOKEN=... python -m oss_policy_kit collect-evidence \
    --target . --platform github --repo owner/repo

# AWS (boto3 credential chain, plus optional env vars)
AWS_CODEBUILD_PROJECT=... AWS_CODEPIPELINE_NAME=... \
    python -m oss_policy_kit collect-evidence --target . --platform aws

# Azure DevOps
AZURE_DEVOPS_ORG=... AZURE_DEVOPS_TOKEN=... \
    python -m oss_policy_kit collect-evidence --target . --platform azure \
    --repo ProjectName/repoName
```

API-collected evidence carries `attested_by`, `collection`, and
`posture_support` metadata. Evaluators use that metadata to promote live API
attestations to `pass` with higher confidence, instead of the
`self-attested` path taken by manually edited templates.

Preview what would be written without calling remote APIs:

```bash
python -m oss_policy_kit collect-evidence --target . --platform github --dry-run
```

## Recommended ladder per CI moment

| CI moment              | Profile                                           | Gate mode                                                   |
|------------------------|---------------------------------------------------|-------------------------------------------------------------|
| PR open / updated      | `<family>-level-1` or `<family>-level-2`          | `--fail-on fail` for L1; `--fail-on none` for L2 (advisory) |
| Trunk merge            | `<family>-level-2`                                | `--fail-on none` (advisory)                                 |
| Release tag            | `<family>-release-hardening-2` or `-3`            | `--fail-on fail`                                            |
| Pre-release hard gate  | `<family>-level-3`                                | `--fail-on fail`                                            |

Replace `<family>` with `github`, `aws`, or `azure` according to the CI/CD
source of truth for the target repository.

Hybrid advisory profiles (`github-aws-level-2`, `github-azure-level-2`) must
not be used as release gates.

## Reading the report

The report JSON (under `--output-dir`) contains a `controls` array (one entry
per control) and a `summary_by_status` dict. Status values you should know:

- `pass`, `fail`: self-explanatory.
- `not-applicable`: control does not apply to this target.
- `manual-review-required`: automation cannot conclude; a human decides.
- `not-evaluated`: evidence was present but invalid (placeholders, malformed).
- `self-attested`: local evidence exists, but trust depends on maintainer
  honesty or platform confirmation.
- `waived`: a waiver entry explicitly excepts this control.

For the full wire schema of the report JSON, see
[`docs/reports-contract-v2.0.md`](reports-contract-v2.0.md) and the schema
under `src/oss_policy_kit/data/schema/reports/2.0.json`.

## Weighted scoring for hard gates

Each catalog control carries a `weight` that feeds the `weighted_score` block
of the report. Two reports with the same `summary_by_status` can differ in
posture percent when different controls are in `pass` vs `fail`. Treat
`weighted_score.percent` as the primary hard-gate signal and
`summary_by_status` as the detail breakdown.

## Troubleshooting

- **"Evidence file ... contains unfilled placeholder tokens"**: Edit the JSON
  under `.oss-policy-kit/evidence/` and replace the placeholder values with
  real data (or use `collect-evidence`).
- **Score stuck at 0%**: usually the target folder has no
  `.github/workflows/`, no `buildspec.yml`, no Azure pipeline YAML in a supported path. Run
  `python -m oss_policy_kit recommend-profile --target .` to see which
  profile family actually fits the repository shape.
- **"Signal came from supplemental evidence only"**: the profile produced a
  `pass` from Scorecard JSON or equivalent supplemental input rather than
  from in-repo workflow evidence. For hard gates, prefer API-backed
  collection or structured in-repo evidence.
- **Legacy alias `github-release-hardening`**: removed in v5.0.0. Passing
  `--profile github-release-hardening` now exits with code 2 and prints a
  migration message. Use `github-release-hardening-1` (same control set).

## Minimal end-to-end example (GitHub L3)

```bash
# 1. Collect evidence from the GitHub API (read-only PAT with repo:read)
GITHUB_TOKEN=$GH_PAT python -m oss_policy_kit collect-evidence \
    --target . --platform github --repo owner/repo

# 2. Evaluate with the strict L3 profile and fail on any fail
python -m oss_policy_kit evaluate \
    --target . \
    --profile github-level-3 \
    --output-dir ./out/release-gate \
    --fail-on fail

# 3. Inspect the report
cat ./out/release-gate/evaluation-report.json | jq '.summary_by_status,
    .weighted_score.percent,
    .operational_warnings'
```

If `operational_warnings` remains empty and `summary_by_status` shows only
`pass`, `self-attested`, `not-applicable`, and `waived`, the release gate
is clean.

### Reading `Operational warnings (N)` on stderr

The `(N)` count printed next to `Operational warnings` on stderr is the
**total number of warning events across all controls**, not the number of
distinct warning lines shown. The same warning text can legitimately repeat
across multiple controls (for example, several controls can each raise a
"Signal came from supplemental evidence only" event), so it is normal for
`N` to be larger than the number of unique lines visible on the terminal.
The full, deduplicated-per-control detail lives in the Markdown and JSON
reports under `--output-dir`, not in the stderr summary — treat stderr as a
quick signal and the report files as the source of truth.
