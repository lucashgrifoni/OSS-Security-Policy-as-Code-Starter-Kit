# AWS profiles

Six profiles: `aws-level-1` through `aws-level-3` and `aws-release-hardening-1` through
`aws-release-hardening-3`.

## Usage classes

- **Daily baseline**: `aws-level-1`, `aws-level-2`, `aws-release-hardening-1`,
  `aws-release-hardening-2`.
- **Extreme hard-gate**: `aws-level-3`, `aws-release-hardening-3`.

## Ladder

- **level-1**: `buildspec.yml` plus scanner / SCA / SBOM **signal** controls (directional PASS only).
- **level-2**: adds a validated CodePipeline export under `pipelines/aws/` and stricter buildspec
  posture; still signal-heavy for scanners.
- **level-3**: **hard-gate** with JSON evidence (`aws-codebuild-project.json`,
  `aws-codepipeline.json`), artifact-bound SBOM/provenance, **ORG-MFA-001**,
  **GOV-EVIDFRESH-054**, and related controls. Buildspec text signals are **not** treated as hard
  proof at this tier.

## Release hardening

Stacks release discipline (including extra buildspec **signals** on `aws-release-hardening-3`) on
top of the AWS hard-gate core.

## `aws-level-3` vs `aws-release-hardening-3` — when to use which

Both are AWS extreme hard-gates and both expect live `collect-evidence --platform aws`. They differ in operational fit:

- Use **`aws-level-3`** for **steady-state CodeBuild/CodePipeline hardening** — IAM identity posture, scanner/SCA evidence, ORG-MFA, evidence freshness on the AWS-native side. 7 of the 25 controls are evidence-backed.
- Use **`aws-release-hardening-3`** when the gate runs at the **release event** — adds release-track signals on top of the same hard-gate core (extra buildspec signals, artifact-bound SBOM/provenance evidence files). 7 of the 29 controls are evidence-backed; the additional rows over `aws-level-3` are mostly release-discipline signals.

Operational rule of thumb:

- For PR-time and steady-state CI on AWS: `aws-level-3`.
- For tag/release-time gates on AWS: `aws-release-hardening-3`.
- Both depend on the same AWS credential chain for `collect-evidence`. Without it, expect a tail of `self-attested` and `manual-review-required` rows on the platform-evidence controls — see [L3 evidence-heavy caveat](overview.md#l3-evidence-heavy-caveat-read-before-wiring-a-hard-gate).

## When to use each profile

Pick the lowest level that actually matches how your release flow is governed today:

| You want to … | Start at |
| --- | --- |
| Prove a repository is not empty of AWS-native signals and CI scanners fire | `aws-level-1` |
| Prove CodePipeline is committed and buildspec posture is cleaner | `aws-level-2` |
| Prove live CodeBuild/CodePipeline posture from boto3 + artifact-bound SBOM/provenance | `aws-level-3` |
| Stack release discipline signals on top of daily baselines | `aws-release-hardening-1` / `-2` |
| Gate a release with evidence freshness and strict identity posture | `aws-release-hardening-3` |

Move up only when the evidence for the next tier is realistically available. Climbing tiers without
running `collect-evidence` turns strict rows into `self-attested` — which is honest, but does not
represent live platform posture.

## What `fail == 0` means (and does not mean)

- On the **synthetic fixture** (`examples/hardened-repo`), `fail == 0` is achievable for every AWS
  profile. The fixture ships self-attested JSON that is designed to be coherent with the bundled
  buildspec and CodePipeline export.
- `fail == 0` on a real repository means every evaluated AWS control produced enough evidence to
  clear a `fail` outcome — it does **not** mean every control was API-attested.
- At `level-3` / `release-hardening-3`, rows can still come back as `self-attested` when maintainer
  JSON is present but `collect-evidence --platform aws` was not run. Treat those rows as real
  follow-up items until a live collection replaces them.

## When synthetic evidence is enough and when live collection is required

| Situation | Acceptable input |
| --- | --- |
| Adoption demo, kit evaluation, internal review | Synthetic JSON under `.oss-policy-kit/evidence/` |
| Pipeline guardrail on a development branch | Scaffolded JSON with maintainer attestation |
| Release gate on a customer-facing artifact | `collect-evidence --platform aws` output (live) |
| Audit / compliance conversation | Live JSON + record of `attested_at` and `source_url` |

Use `oss-policy-kit collect-evidence --platform aws --dry-run` to preview exactly which files will
be written and which environment variables the tool will read before committing to a live run. The
dry-run prints presence/absence of `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_PROFILE`,
`AWS_CODEBUILD_PROJECT`, and `AWS_CODEPIPELINE_NAME` **without ever printing their values**.

## Practical maturity

AWS depends more on **maintained evidence** and `collect-evidence --platform aws` than GitHub for
equivalent confidence. The `examples/hardened-repo` fixture includes `buildspec.yml`,
`pipelines/aws/codepipeline.json`, and synthetic JSON to show the **ceiling of the kit** without
claiming posture of a real AWS account.

Expectation for operators: even when `fail == 0`, AWS extreme profiles commonly include
`self-attested` rows in synthetic fixtures unless evidence was collected live.

## When `aws-level-3` and `aws-release-hardening-3` are honestly green

These two profiles can reach `weighted 100%` on the synthetic fixture, but that number only
represents an *honest gate* when combined with a real `collect-evidence` run for the AWS family.
Without it, several controls fall back to `self-attested` rows and the same `100%` reflects
maintainer attestation, **not** live platform proof.

To wire `aws-level-3` or `aws-release-hardening-3` as a release gate, expect the AWS credential
chain (`AWS_REGION` plus a profile or access key, optionally `AWS_CODEBUILD_PROJECT` /
`AWS_CODEPIPELINE_NAME`) to be available with the minimal read permissions documented in the
collector help. A typical sequence:

```bash
# only with valid credentials; verify minimum permissions first
python -m oss_policy_kit collect-evidence \
  --target . --platform aws --repo my-codecommit-repo

python -m oss_policy_kit evaluate \
  --target . --profile aws-release-hardening-3 \
  --fail-on fail --summary-only
```

`--dry-run` is safe for public CI logs (it prints presence/absence of the AWS environment
variables, never their values) but it does **not** substitute live collection for a real release
gate. Use the dry-run to confirm the contract; use a real run to feed the gate.
