# Hardened example

Small repository layout used by tests, demos, and regression checks. It is intentionally a
**kitchen-sink fixture**: it carries clone-visible signals and synthetic supplemental evidence
for **all three CI/CD platforms** (GitHub, Azure DevOps, AWS) so that the bundled L1 profiles
can be exercised against a single target.

This is what makes evaluations like the table below succeed against the same directory:

| Profile | Outcome | Notes |
|---|---|---|
| `github-level-1` | `pass=14` (100%) | clone-visible GitHub workflows + governance files |
| `azure-level-1` | `pass=13` (100%) | `azure-pipelines.yml` + Azure evidence JSON files |
| `aws-level-1`   | `pass=12` (100%) | `buildspec.yml`, `pipelines/aws/codepipeline.json`, AWS evidence JSON files |

The repo therefore contains:

- `.github/workflows/` (ci, security, release-example) plus `CODEOWNERS` and `dependabot.yml`;
- `azure-pipelines.yml` (Azure CI signal);
- `buildspec.yml` and `pipelines/aws/codepipeline.json` (AWS CI signal);
- `.oss-policy-kit/evidence/` populated with 14 synthetic evidence JSON files covering GitHub,
  Azure, AWS, and org-level MFA posture (the same shapes `scaffold-evidence` would create).

## What this fixture is good for

- Demonstrating starter-level posture (`github-level-1`) and general clone-visible hygiene.
- Exercising synthetic evidence flows under `.oss-policy-kit/evidence/` for single-platform extreme tracks.
- Regression testing for bundled examples (`hardened` vs `vulnerable`).
- Showing that the same target can be validated against several `*-level-1` profiles when the
  repo deliberately carries multi-platform CI signals and supplemental evidence.

## What this fixture is **not** claiming

- It is **not** a live-platform proof pack for GitHub / Azure DevOps / AWS organizations.
- The fact that this fixture passes `aws-level-1` and `azure-level-1` does **not** imply that an
  arbitrary GitHub-only repository will pass those profiles. It passes here because we
  intentionally added `azure-pipelines.yml`, `buildspec.yml`, and the matching evidence JSON
  files. Real GitHub-only repos should run `python -m oss_policy_kit recommend-profile --target .`
  to get a heuristic suggestion grounded in the signals actually present.
- Operational warnings such as "Signal came from supplemental evidence only" are expected:
  several controls are satisfied via synthetic evidence files, not API-backed collection.
- A run with `fail == 0` is **not** equivalent to all controls being `pass`. Outcomes such as
  `self-attested`, `not-evaluated`, and `not-applicable` are part of the same total and remain
  expected in stricter profiles.
- L2, L3, and `*-release-hardening-*` profiles can still depend on additional evidence (live
  collectors, scorecard exports, etc.) beyond what this fixture carries.

## Known representativity limits

From the 2026-04-22 validation baseline, this fixture is not expected to be universally green across all advisory tracks. In particular:

- `github-level-2`
- `github-release-hardening-2`
- `github-aws-level-2`
- `github-azure-level-2`

can still fail on GitHub-centric signal controls (notably `GH-PROV-023` and/or `SEC-SECRETS-050`) depending on the exact fixture contents. That should be interpreted as a fixture-coverage limitation, not as automatic profile invalidation.
