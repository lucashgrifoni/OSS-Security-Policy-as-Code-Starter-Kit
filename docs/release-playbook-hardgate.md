# Release playbook - hard-gate evaluation

This runbook uses only commands and flags that exist in the current CLI: `evaluate`, `profiles`, `recommend-profile`, `evaluate-many`, and `collect-evidence`.

## Zero `fail` is not the same as all-pass

A green `--fail-on fail` run only means **no control ended in `fail`**. You can still have `manual-review-required`, `self-attested`, `not-evaluated`, `not-applicable`, and operational warnings. On the bundled `examples/hardened-repo` fixture, the six extreme profiles are tuned to reach **zero `fail`**, not a literal row of only `pass`.

## When to use a hard-gate profile

Use `github-release-hardening-3`, `aws-release-hardening-3`, or `azure-release-hardening-3` when you want the strictest bundled release-oriented gate for that platform. For day-to-day repo service gates without the full release stack, the matching `level-3` profile is the parallel hard-gate.

Hybrid profiles `github-aws-level-2` and `github-azure-level-2` remain advisory-only; do not substitute them for these hard-gates.

## Recommended evaluation command

From the repository root you want to gate:

```bash
python -m oss_policy_kit evaluate --target . --profile github-release-hardening-3 --output-dir ./out/release-gate --fail-on fail
```

Adjust `--profile` to `aws-release-hardening-3` or `azure-release-hardening-3` when AWS CodeBuild/CodePipeline or Azure DevOps is the CI/CD source of truth.

Other supported flags for this workflow include `--format`, `--summary-only`, and `--output-dir` as documented in `python -m oss_policy_kit evaluate --help`.

## Legacy profile id (GitHub) — removed in v5.0.0

The bundled id `github-release-hardening` was **removed in v5.0.0**. Passing `--profile github-release-hardening` exits with code `2` and a migration message pointing to the canonical `github-release-hardening-1` (same control set). Update CI workflows, scripts, and dashboards. See [docs/v5.0.0-migration-guide.md](v5.0.0-migration-guide.md).

## Operational warnings on supplemental evidence

When a hard-gate profile passes a row using only supplemental evidence (a hand-filled `.oss-policy-kit/evidence/` JSON, a keyword match in a workflow, or a Scorecard heuristic), the CLI emits an **operational warning** on stderr:

> Signal came from supplemental evidence only; prefer in-repo workflow evidence or API-backed collection for hard gates.

Treat this as a real signal in CI:

- The default of `evaluate` keeps these warnings visible. In a release-gate run, do **not** suppress them with `--quiet/-q` — that flag is meant for daily triage runs where the warnings would dominate stdout, not for the strict release path.
- Operational warnings alone do **not** flip `--fail-on fail` or `--fail-on degraded`. They are informational. Promote a warning to a hard gate by replacing the supplemental source with `collect-evidence` output for the matching family.
- For `*-level-3` and `*-release-hardening-3` profiles, plan the `collect-evidence` step before the gate runs (see [Optional: populate evidence from APIs](#optional-populate-evidence-from-apis) below). The warning is the kit telling you that the row's `trust_level` is `heuristic` or `observed` and not yet `verified`/`attested`.

## Optional: populate evidence from APIs

When you have credentials configured for the target platform:

```bash
python -m oss_policy_kit collect-evidence --target . --platform github
```

Platforms: `github`, `azure`, or `aws` (each requires the matching credentials; see `python -m oss_policy_kit collect-evidence --help`).

Use `--dry-run` to preview which evidence files would be written without calling remote APIs.

Evidence is written under `<target>/.oss-policy-kit/evidence/` unless you pass `--output-dir`.

## Choose a profile interactively

```bash
python -m oss_policy_kit recommend-profile --target . --format text
```

```bash
python -m oss_policy_kit profiles --format json
```

## Interpret results for release decisions

- `fail`: the control bar was not met; with `--fail-on fail`, the process exits non-zero when any control is in this state.
- `manual-review-required`: human judgment or missing context; it is not a clean PASS. Your release policy may still block on this even when `--fail-on fail` passes, because `fail-on` only maps explicit severities you choose (see `evaluate --help` for supported values).
- `not-applicable`: the evaluator decided the control does not apply to this repository. Treat as neutral for that repo.
- `not-evaluated`: required inputs were absent (for example optional Scorecard JSON). Do not treat as PASS.
- `self-attested`: evidence was supplied without live API collection metadata the kit treats as proof-grade; common on AWS/Azure extreme paths in synthetic fixtures.

## GitHub vs AWS or Azure (practical maturity)

Inside this kit, GitHub has the most mature path (workflow parsing, evidence schemas, and `collect-evidence --platform github`). AWS and Azure hard-gates depend more on evidence files and operator discipline; synthetic fixtures can show schema validity but cannot certify a live account or organization. Expect **more `self-attested` outcomes** on AWS/Azure extreme profiles than on GitHub for the same style of fixture.

## Further reading

- [Profiles overview](profiles/overview.md)
- [Evidence pack](evidence-pack.md)
