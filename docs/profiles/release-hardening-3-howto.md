# Release-hardening-3 how-to

Practical guide for the three "extreme" release-hardening profiles in the bundled catalog:

- `github-release-hardening-3`
- `azure-release-hardening-3`
- `aws-release-hardening-3`

These are the most strict bundled profiles. They are designed to act as **release gates**: a clean run with `--fail-on fail` is the green light to ship the artifact. Before they pass, you need real evidence files filled in. This document walks through the minimum.

## Common shape

All three `*-release-hardening-3` profiles share the same workflow:

1. **Run `scaffold-evidence` once** to create the JSON templates under `.oss-policy-kit/evidence/`.
2. **Fill the templates** by hand, or run **`collect-evidence`** with platform credentials to populate them via the platform API.
3. **Run `evaluate`** with the matching profile and `--fail-on fail`.

What differs between platforms is the set of evidence files that must exist and which controls depend on each.

## GitHub — `github-release-hardening-3`

### Required evidence files

Created by `scaffold-evidence --target . --platform github`:

- `.oss-policy-kit/evidence/branch-protection.json` — feeds `PLAT-BRPROT-015`.
- `.oss-policy-kit/evidence/github-rulesets.json` — feeds `GH-PLAT-024`.
- `.oss-policy-kit/evidence/github-environment-protection.json` — feeds `GH-PLAT-025`.
- `.oss-policy-kit/evidence/github-secret-scanning.json` — feeds `GH-PLAT-026`.
- `.oss-policy-kit/evidence/audit-log-streaming.json` — feeds `AUDIT-STREAM-060`.
- `.oss-policy-kit/evidence/github-provenance-artifact.json` — feeds `PROV-VERIFY-061`.
- `.oss-policy-kit/evidence/runner-groups.json` — feeds `GH-RUNNER-062`.
- `.oss-policy-kit/evidence/release-archival-policy.json` — feeds `RELEASE-ARCHIVE-063`.
- `.oss-policy-kit/evidence/org-mfa-posture.json` — feeds `ORG-MFA-001`.

### Suggested flow

```bash
# 1. Scaffold (idempotent; existing files preserved unless --force is set).
python -m oss_policy_kit scaffold-evidence --target . --platform github

# 2. Either fill the JSONs by hand, or:
export GITHUB_TOKEN=ghp_<token-with-admin:org-and-repo-read>
python -m oss_policy_kit collect-evidence --target . --platform github --repo "<org>/<repo>"

# 3. Evaluate as a release gate.
python -m oss_policy_kit evaluate \
  --target . \
  --profile github-release-hardening-3 \
  --output-dir ./oss-policy-reports \
  --fail-on fail
```

### Expected behavior before evidence is filled

`manual-review-required` for every evidence-backed control. `--fail-on fail` will not trip on `manual-review-required`, but `--fail-on degraded` will. This is by design: the kit reports the gap honestly instead of false-passing.

## Azure DevOps — `azure-release-hardening-3`

### Required evidence files

- `.oss-policy-kit/evidence/azure-branch-policies.json` — feeds `AZ-PLAT-034`.
- `.oss-policy-kit/evidence/azure-pipeline-governance.json` — feeds `AZ-PLAT-035`.
- `.oss-policy-kit/evidence/azure-sbom-artifact.json` — feeds `AZ-ARTSBOM-058`.
- `.oss-policy-kit/evidence/azure-provenance-artifact.json` — feeds `AZ-ARTPRV-059`.
- `.oss-policy-kit/evidence/audit-log-streaming.json` — feeds `AUDIT-STREAM-060`.
- `.oss-policy-kit/evidence/release-archival-policy.json` — feeds `RELEASE-ARCHIVE-063`.
- `.oss-policy-kit/evidence/org-mfa-posture.json` — feeds `ORG-MFA-001`.

### Suggested flow

```bash
python -m oss_policy_kit scaffold-evidence --target . --platform azure

export AZURE_DEVOPS_ORG=<org>
export AZURE_DEVOPS_TOKEN=<PAT-with-Code-and-Build-read>
python -m oss_policy_kit collect-evidence --target . --platform azure --repo "<Project>/<Repo>"

python -m oss_policy_kit evaluate \
  --target . \
  --profile azure-release-hardening-3 \
  --output-dir ./oss-policy-reports \
  --fail-on fail
```

### Caveats

The Azure collector reaches fewer endpoints than the GitHub one. Several artifact-bound evidence files (`azure-sbom-artifact`, `azure-provenance-artifact`) intentionally remain self-attested because the digests must come from the release pipeline, not from a generic API call. Keep the SBOM and provenance JSONs current as part of your release pipeline output.

## AWS — `aws-release-hardening-3`

### Required evidence files

- `.oss-policy-kit/evidence/aws-codebuild-project.json` — feeds `AWS-CB-045`.
- `.oss-policy-kit/evidence/aws-codepipeline.json` — feeds `AWS-CP-044`.
- `.oss-policy-kit/evidence/aws-codecommit-review-posture.json` — feeds `AWS-CC-046` (only when CodeCommit is in scope; this control is in catalog but not in this profile by default — see `melhorias/AWS-CC-046-decision-pending.md`).
- `.oss-policy-kit/evidence/aws-sbom-artifact.json` — feeds `AWS-SBOMART-058`.
- `.oss-policy-kit/evidence/aws-provenance-artifact.json` — feeds `AWS-PROVART-059`.
- `.oss-policy-kit/evidence/audit-log-streaming.json` — feeds `AUDIT-STREAM-060`.
- `.oss-policy-kit/evidence/release-archival-policy.json` — feeds `RELEASE-ARCHIVE-063`.
- `.oss-policy-kit/evidence/org-mfa-posture.json` — feeds `ORG-MFA-001`.

### Suggested flow

```bash
python -m oss_policy_kit scaffold-evidence --target . --platform aws

# Configure AWS credentials via the boto3 default chain
export AWS_REGION=us-east-1
export AWS_PROFILE=<profile>
export AWS_CODEBUILD_PROJECT=<project>
export AWS_CODEPIPELINE_NAME=<pipeline>
python -m oss_policy_kit collect-evidence --target . --platform aws --repo "<codecommit-repo-or-empty>"

python -m oss_policy_kit evaluate \
  --target . \
  --profile aws-release-hardening-3 \
  --output-dir ./oss-policy-reports \
  --fail-on fail
```

### Caveats

Same as Azure: the AWS collector covers CodeBuild and CodePipeline but artifact-bound SBOM/provenance evidence stays self-attested by design. Wire those into your release pipeline output.

## Why expect `manual-review-required` on first run

The bundled `examples/hardened-repo` fixture is tuned to make these profiles reach `pass=majority` with synthetic evidence — that is **not** the same as proving real release readiness. On a real repository:

- An empty `.oss-policy-kit/evidence/` directory will produce `manual-review-required` for every evidence-backed control.
- A scaffolded but unfilled evidence file will produce `manual-review-required` (because placeholder values are detected).
- A self-attested but unsigned evidence file will produce `pass` with `attestation_status: self_attested` and `trust_level: attested`. To reach `verified`, you need API-collected evidence with proper attestation metadata.

This is by design. The kit is honest about what it can and cannot prove.

## Recommended `--fail-on` ladder by environment

| Environment | Recommended `--fail-on` | Rationale |
|---|---|---|
| Local pre-PR check | `none` | See findings without tripping; iterate. |
| PR pipeline (CI) | `degraded` | Treat `manual-review-required` as a soft block; encourages filling evidence. |
| Release gate | `fail` | Hard block; release only when no `fail` rows remain. |

## Related

- [profiles/overview.md](overview.md) — catalog of profiles and maturity tiers.
- [results-guide.md](../results-guide.md) — what each result status means and how to read evidence-backed results.
- [evidence-pack.md](../evidence-pack.md) — exact JSON shape per evidence file.
- [collector-parity.md](../collector-parity.md) — what `collect-evidence` covers per platform.
- [framework-alignment.md](../framework-alignment.md) — how each control maps to OpenSSF / SLSA / NIST SSDF / EU CRA.
