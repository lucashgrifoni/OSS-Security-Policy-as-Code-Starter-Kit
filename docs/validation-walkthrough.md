# Validation Walkthrough

This is the fastest way to understand how the kit is meant to be used in practice. It walks through the command flow in the same order a maintainer or AppSec engineer would normally follow:

1. learn the CLI surface
2. choose the right profile
3. run a quick demo or self-check
4. compare expected good and bad repository shapes
5. turn the same evaluation into a CI gate

Treat the generated Markdown and JSON reports as the operational evidence. They show that the kit runs, reports clearly, and differentiates repository posture. They do **not** claim that a `pass` result is equivalent to universal security assurance.

This walkthrough intentionally uses text output, report paths, and structured tables instead of image captures. If the output changes, rerun the commands and update the text excerpts from the generated artifacts.

## Command Flow At A Glance

| Step | Command or artifact | Use it when | Text evidence to keep |
| --- | --- | --- | --- |
| Understand the CLI | `python -P -m oss_policy_kit --help` | You want to see the supported commands, flags, and exit codes before wiring the tool into scripts or CI. | Copy the `Usage`, `Commands`, and `Exit Codes` sections into a text evidence file. |
| Discover profiles | `python -P -m oss_policy_kit profiles` | You need to choose the right platform and strictness level before running an evaluation. | Record the selected profile id, platform, level, and control count. |
| Compare baseline outcomes | `python -P -m oss_policy_kit evaluate --target ./examples/... --summary-only` | You want a fast contrast between a stronger fixture and a weaker fixture under the same profile. | Preserve the summary lines for `Outcome`, `Controls`, and `Weighted score`. |
| Self-check the current repo | `python -P -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck` | You want to validate the current repository revision using the same kit it ships. | Keep `evaluation-report.md` and `evaluation-report.json` from the exact revision being evaluated. |
| Compare fixtures | `python -P -m oss_policy_kit evaluate --target ./examples/...` | You want a stable passing fixture and a stable failing fixture for demos, tests, or onboarding. | Compare the generated `Summary`, `Controls`, and `Detail` sections. |
| Gate CI | `python -P -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-ci --fail-on fail` | You want reports written first and the pipeline blocked only when the chosen threshold is violated. | Preserve stdout, stderr, exit code, and the generated report directory. |

## 1. Learn The CLI Surface

Start with the help output. This is the right command to use when you are integrating the tool for the first time, because it shows:

- the preferred `evaluate` entrypoint
- compatibility invocation forms
- output options such as `--summary-only` and `--format`
- the exit-code contract used by local scripts and CI

```bash
python -P -m oss_policy_kit --help
```

Expected contract:

| Section | What to confirm |
| --- | --- |
| `Usage` | `python -P -m oss_policy_kit [OPTIONS] COMMAND [ARGS]...` is present. |
| `Commands` | `evaluate`, `profiles`, `recommend-profile`, `evaluate-many`, `scaffold-evidence`, `collect-evidence`, `export-evidence`, `diff-reports`, `emit-vex`, `emit-insights`, and scanner helpers are listed. |
| `Options` | `--profile`, `--target`, `--output-dir`, `--format`, `--summary-only`, `--fail-on`, `--sarif-output`, and `--report-json-contract` are documented. |
| `Exit Codes` | `0`, `1`, `2`, and `3` keep the meanings documented in the CLI reference. |

## 2. Discover And Choose A Profile

Before evaluating a repository, choose the profile that matches the platform and the desired assurance level. The canonical command is:

- `python -P -m oss_policy_kit profiles` prints the compact bundled profile table
- `python -P -m oss_policy_kit profiles --format detailed` prints the same table with full audience and description text
- `python -P -m oss_policy_kit profiles --format json` returns the listing as JSON (`oss-policy-kit/profile-list/v2`) for automation

(`python -P -m oss_policy_kit --show-profiles` is a deprecated alias. It still works but emits a deprecation warning. Prefer the subcommand above.)

Use `level-1` when you are starting with the baseline and want honest clone-only checks. Move to higher levels or `release-hardening-*` profiles when you want stricter controls and are ready to provide supporting evidence for release posture.

```bash
python -P -m oss_policy_kit profiles
python -P -m oss_policy_kit profiles --format detailed
python -P -m oss_policy_kit profiles --format json
```

Profile selection checklist:

| Question | Start with |
| --- | --- |
| Is this a first GitHub repository gate? | `github-level-1` |
| Is this an existing GitHub repository with stricter governance expectations? | `github-level-2` |
| Is this an OSS release readiness check? | `oss-publish-readiness-1` |
| Do scanner outputs need to be composed into one review? | `appsec-sast-sca-1` |
| Is this an advisory OpenSSF OSPS Baseline 2026 review? | `osps-baseline-2026-1` |
| Is this an AI agent or MCP server repository? | `ai-agent-baseline-1` or `appsec-mcp-server-1` |

## 3. Compare Hardened And Vulnerable Baselines

When you want the fastest practical explanation of what the kit does, compare the bundled hardened and vulnerable fixtures under the same `github-level-1` profile. This keeps the policy set constant and changes only the repository posture, so the contrast is easy to explain.

Run the hardened fixture:

```bash
python -P -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --summary-only
```

Representative summary on this repository revision:

```text
Profile: github-level-1
Outcome: pass=14
Controls: 14 | Operational warnings: 1
Weighted score: 28/28 (100.0%)
```

Run the vulnerable fixture:

```bash
python -P -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --summary-only
```

Representative summary on this repository revision:

```text
Profile: github-level-1
Outcome: pass=2, fail=11, manual-review-required=1
Controls: 14 | Operational warnings: 0
Weighted score: 4/28 (14.3%)
```

Interpretation:

| Fixture | Result shape | Meaning |
| --- | --- | --- |
| `examples/hardened-repo` | `pass=14` | The fixture contains the expected governance files and CI signals for the starter GitHub profile. |
| `examples/vulnerable-repo` | `pass=2, fail=11, manual-review-required=1` | The fixture intentionally lacks key governance and workflow hygiene signals, so the same profile produces actionable non-pass states. |

## 4. Validate The Package And The Current Repository

After the CLI and profiles are clear, validate that the package itself is healthy and that the current repository revision can evaluate cleanly.

Run the automated test suite when you want regression confidence before changing code, policy data, or templates:

```bash
python -m pytest -q
```

Text evidence to keep:

| Evidence line | Why it matters |
| --- | --- |
| Final pytest summary | Confirms the actual test result and count for the revision under review. |
| Process exit code | Confirms whether CI would treat the run as passing or failing. |
| Any skipped or failed test names | Prevents a green-looking summary from hiding scope loss. |

Then run a maintainer self-check when you want to know whether the repository itself satisfies the chosen baseline in its current revision:

```bash
python -P -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck
```

Representative summary on this repository revision:

```text
Profile: github-level-1
Outcome: pass=14
Controls: 14 | Operational warnings: 1
Weighted score: 28/28 (100.0%)
```

The generated files under `./out/selfcheck` remain the source of truth for the exact commit being evaluated.

## 5. Compare Known-Good And Known-Bad Fixtures

The bundled example repositories are the clearest way to understand what the tool is checking and why those checks matter.

Use the hardened example when you want to show the target baseline outcome:

```bash
python -P -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

Use the vulnerable example when you want to prove that the kit is not a cosmetic report generator and that obvious repository weaknesses really do surface as non-pass states:

```bash
python -P -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
```

Generated artifacts to compare:

| Artifact | Hardened fixture | Vulnerable fixture |
| --- | --- | --- |
| `evaluation-report.md` | Use the `Summary`, `Controls`, and `Detail` sections as the human-readable review package. | Use the same sections to explain each missing governance or CI/CD signal. |
| `evaluation-report.json` | Use `summary_by_status`, `controls_total`, and per-control records for automation. | Use the same fields to build backlog items or CI annotations. |
| stdout summary | Confirms the high-level posture quickly. | Confirms fail and manual-review states without opening the full report. |

## 6. Read The Controls Table And Detail Blocks

After you see a fixture pass or fail at the summary level, inspect the generated Markdown report and understand why each control resolved that way.

Use the vulnerable fixture for this walkthrough because it produces a mix of governance, CI/CD, release, and supply-chain findings:

```bash
python -P -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
```

Open `./out/vulnerable/evaluation-report.md` and scroll past the summary sections. The `## Controls` table is the compact triage view: one row per control, with the control id, category, lifecycle, status, confidence, short reason, remediation hint, and waiver column.

Text-first review pattern:

| Field | Review question |
| --- | --- |
| Control id | Which policy requirement is being discussed? |
| Status | Did it pass, fail, require manual review, or get waived? |
| Confidence | Was the result deterministic, signal-grade, or evidence-backed? |
| Reason | What exact condition caused the result? |
| Remediation | What concrete action should the maintainer take next? |
| Evidence | Which file, workflow, schema, or supplied evidence supported the result? |

That table answers the first-level questions quickly: what failed, how confident the kit is, and what should be fixed next. In this example, governance controls fail because the repository is missing `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, and other baseline files, while workflow controls show whether CI/CD signals exist and whether they are safe enough for the selected profile.

When you need the full reasoning behind one result, keep scrolling into `## Detail`. Each control expands into a dedicated block with status, lifecycle, confidence, reason, remediation, and evidence when the evaluator found a concrete file or signal.

Detail block checklist:

| Check | Expected content |
| --- | --- |
| Status | A single state such as `pass`, `fail`, or `manual-review-required`. |
| Reason | A concise explanation tied to observed repository content. |
| Remediation | The owner-ready fix, not just a restatement of the failure. |
| Evidence | File paths, workflow names, or evidence JSON references when available. |

## 7. Turn Evaluation Into A CI Gate

Once the report content makes sense locally, the same evaluation can be used as a pipeline gate. The key flag is `--fail-on`, which turns result thresholds into exit-code policy:

```bash
python -P -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-ci --fail-on fail
```

`--fail-on` modes:

- `none`: never fail from result statuses (exit `0` unless internal/usage errors).
- `fail`: exit `1` if any control has status `fail`.
- `degraded`: exit `1` if any control has `fail` **or** `manual-review-required`.
- Operational warnings alone do **not** trigger `fail` or `degraded`.

Use this mode when you want the job to:

1. complete evaluation
2. write `evaluation-report.json` and `evaluation-report.md`
3. fail the CI step only after the evidence is available for review

That behavior matters. A blocked pipeline should still leave behind actionable evidence.

**GitHub Actions break build behavior:** run the evaluator in a normal workflow step with `--fail-on fail`. The command writes `evaluation-report.json` and `evaluation-report.md` first. If any control resolves to `fail`, the process exits with code `1`, which marks the step, job, and required check as failed. Keep the output directory as an artifact with `if: always()` when you want reviewers to inspect the reports after a blocked PR or release job.

You can reproduce both the pass and fail paths locally to confirm the exit-code contract before wiring it into CI:

```bash
# Pass path against the current repository
python -P -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-pass --fail-on fail
echo "exit=$?"   # 0 when no control fails

# Fail path against the bundled vulnerable fixture
python -P -m oss_policy_kit evaluate --target examples/vulnerable-repo --profile github-level-1 --output-dir ./out/selfcheck-fail --fail-on fail
echo "exit=$?"   # 1 when at least one control fails
```

**Azure Pipelines break build behavior:** the same exit-code contract applies in a Bash or Command Line task on a Linux/Ubuntu agent. If `--fail-on fail` finds a failing control, Azure marks that task and job as failed after the reports have already been written. Publish the report directory with `PublishPipelineArtifact@1` and `condition: succeededOrFailed()` so the JSON and Markdown evidence remain available even when the gate blocks the run.

The same command above produces the failure-path evidence on an Azure Ubuntu agent; the JSON and Markdown reports are written before the non-zero exit, so the artifact remains publishable.
