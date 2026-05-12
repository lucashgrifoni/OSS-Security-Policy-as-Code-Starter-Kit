# Validation Walkthrough

This is the fastest way to understand how the kit is meant to be used in practice. It walks through the command flow in the same order a maintainer or AppSec engineer would normally follow:

1. learn the CLI surface
2. choose the right profile
3. run a quick demo or self-check
4. compare expected good and bad repository shapes
5. turn the same evaluation into a CI gate

Treat these artifacts as operational evidence. They show that the kit runs, reports clearly, and differentiates repository posture. They do **not** claim that a `pass` result is equivalent to universal security assurance.

## Command Flow At A Glance

| Step | Command or artifact | Use it when |
| --- | --- | --- |
| Understand the CLI | `python -m oss_policy_kit --help` | You want to see the supported commands, flags, and exit codes before wiring the tool into scripts or CI. |
| Discover profiles | `python -m oss_policy_kit profiles` | You need to choose the right platform and strictness level before running an evaluation. |
| Compare baseline outcomes | `python -m oss_policy_kit evaluate --target ./examples/... --summary-only` | You want a fast visual contrast between a stronger fixture and a weaker fixture under the same profile. |
| Self-check the current repo | `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck` | You want to validate the current repository revision using the same kit it ships. |
| Compare fixtures | `python -m oss_policy_kit evaluate --target ./examples/...` | You want a stable passing fixture and a stable failing fixture for demos, tests, or onboarding. |
| Gate CI | `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-ci --fail-on fail` | You want reports written first and the pipeline blocked only when the chosen threshold is violated. |

## 1. Learn The CLI Surface

Start with the help output. This is the right command to use when you are integrating the tool for the first time, because it shows:

- the preferred `evaluate` entrypoint
- compatibility invocation forms
- output options such as `--summary-only` and `--format`
- the exit-code contract used by local scripts and CI

```bash
python -m oss_policy_kit --help
```

<p align="center">
  <img src="../screenshots/01-cli-help.png" alt="OSS Policy Kit CLI help showing usage, evaluate subcommand, options, and exit codes." width="960">
</p>

## 2. Discover And Choose A Profile

Before evaluating a repository, choose the profile that matches the platform and the desired assurance level. The canonical command is:

- `python -m oss_policy_kit profiles` prints the compact bundled profile table
- `python -m oss_policy_kit profiles --format detailed` prints the same table with full audience and description text
- `python -m oss_policy_kit profiles --format json` returns the listing as JSON (`oss-policy-kit/profile-list/v2`) for automation

(`python -m oss_policy_kit --show-profiles` is a deprecated alias — it still works but emits a deprecation warning. Prefer the subcommand above.)

Use `level-1` when you are starting with the baseline and want honest clone-only checks. Move to higher levels or `release-hardening-*` profiles when you want stricter controls and are ready to provide supporting evidence for release posture.

```bash
python -m oss_policy_kit profiles
python -m oss_policy_kit profiles --format detailed
```

<p align="center">
  <img src="../screenshots/02-cli-show-profiles.png" alt="Built-in profile table showing profile id, title, platform, level, audience, and description." width="960">
</p>

<p align="center">
  <img src="../screenshots/02-cli-profiles.png" alt="Compact bundled profile listing showing GitHub, Azure, and AWS ladders." width="960">
</p>

## 3. Compare Hardened And Vulnerable Baselines

When you want the fastest practical explanation of what the kit does, compare the bundled hardened and vulnerable fixtures under the same `github-level-1` profile. This keeps the policy set constant and changes only the repository posture, so the contrast is easy to explain.

The first command in the screen targets `./examples/hardened-repo` and uses `--summary-only` to collapse the result to status counts instead of printing file paths and report locations. In the current fixture, `pass=14` means all active controls in `github-level-1` passed for the hardened repository.

The second command targets `./examples/vulnerable-repo` with the same profile and the same summary mode. `pass=2 | fail=11 | manual-review-required=1` means the kit found only two passing controls, eleven direct failures, and one control that cannot be cleanly confirmed from the clone alone. `controls: 14` in both blocks confirms that the same policy set was evaluated in both cases, so the difference comes from repository posture, not from a different rule set.

Use this comparison when you want a compact, high-signal explanation of the product: the hardened fixture shows the target baseline outcome, and the vulnerable fixture shows that missing governance and CI/CD hygiene signals really do degrade the result.

<p align="center">
  <img src="../screenshots/03-demo-contrast.png" alt="Terminal screenshot showing the hardened example returning pass=14 and the vulnerable example returning pass=2, fail=11, and manual-review-required=1." width="960">
</p>

## 4. Validate The Package And The Current Repository

After the CLI and profiles are clear, the next step is to validate that the package itself is healthy and that the current repository revision can evaluate cleanly.

Run the automated test suite when you want regression confidence before changing code, policy data, or templates:

```bash
python -m pytest -q
```

The passing test run below is evidence that the implementation is stable at the code level, not just at the documentation level.

<p align="center">
  <img src="../screenshots/03-test-suite.png" alt="Pytest output showing the automated test suite passing." width="960">
</p>

Then run a maintainer self-check when you want to know whether the repository itself satisfies the chosen baseline in its current revision:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck
```

This is the command to use when validating the repository before release, before documentation updates, or after changing workflows and governance files. The current repository revision produces `pass=14` on `github-level-1`; generated reports under `./out/selfcheck` remain the source of truth for the exact commit being evaluated.

<p align="center">
  <img src="../screenshots/04-selfcheck-current.png" alt="Current repository self-check report for github-level-1." width="960">
</p>

## 5. Compare Known-Good And Known-Bad Fixtures

The bundled example repositories are the clearest way to understand what the tool is checking and why those checks matter.

Use the hardened example when you want to show the target baseline outcome:

```bash
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

This repository includes the expected governance files and CI signals, so it is the reference fixture for a strong `github-level-1` result.

<p align="center">
  <img src="../screenshots/05-example-hardened.png" alt="Hardened example report showing pass=14 on github-level-1." width="960">
</p>

Use the vulnerable example when you want to prove that the kit is not a cosmetic report generator and that obvious repository weaknesses really do surface as non-pass states:

```bash
python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
```

This is the right fixture for onboarding, demos, and CI-gate demonstrations because it shows missing governance artifacts, weak workflow patterns, and other expected gaps as actionable failures.

<p align="center">
  <img src="../screenshots/06-example-vulnerable.png" alt="Vulnerable example report showing pass=2, fail=11, and manual-review-required=1 on github-level-1." width="960">
</p>

## 6. Read The Controls Table And Detail Blocks

After you see a fixture pass or fail at the summary level, the next step is to inspect the generated Markdown report and understand why each control resolved that way.

Use the vulnerable fixture for this walkthrough because it produces a mix of governance, CI/CD, release, and supply-chain findings:

```bash
python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
```

Open `./out/vulnerable/evaluation-report.md` and scroll past the summary sections. The `## Controls` table is the compact triage view: one row per control, with the control id, category, lifecycle, status, confidence, short reason, remediation hint, and waiver column.

<p align="center">
  <img src="../screenshots/08-controls-table.png" alt="Controls table from the vulnerable example report showing control ids, status, confidence, reason, remediation, and waiver columns." width="960">
</p>

That table answers the first-level questions quickly: what failed, how confident the kit is, and what should be fixed next. In this example, the governance controls fail because the repository is missing `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, and `LICENSE`, while `CI-WF-005` passes because a workflow file is present. The same table also shows why `GOV-WAIV-014` reads as **`manual-review-required`** when no versioned in-repo waiver policy file is present: a CLI waiver file is not the same thing as a versioned in-repo waiver policy.

When you need the full reasoning behind one result, keep scrolling into `## Detail`. Each control expands into a dedicated block with status, lifecycle, confidence, reason, remediation, and evidence when the evaluator found a concrete file or signal.

<p align="center">
  <img src="../screenshots/09-control-details.png" alt="Detailed control blocks from the vulnerable example report showing fail and pass results with reasons, remediation, and evidence." width="960">
</p>

That detailed view is what makes the report actionable. A failing control explains exactly what is missing, while a passing control explains which signal satisfied the rule. In this example, governance controls fail because required repository files are absent, and `CI-WF-005` passes because the evaluator detected at least one GitHub Actions workflow. This is the section to use when you are deciding what to remediate first or when you need to justify a result to someone else reviewing the repository.

## 7. Turn Evaluation Into A CI Gate

Once the report content makes sense locally, the same evaluation can be used as a pipeline gate. The key flag is `--fail-on`, which turns result thresholds into exit-code policy:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-ci --fail-on fail
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
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-pass --fail-on fail
echo "exit=$?"   # 0 when no control fails

# Fail path against the bundled vulnerable fixture
python -m oss_policy_kit evaluate --target examples/vulnerable-repo --profile github-level-1 --output-dir ./out/selfcheck-fail --fail-on fail
echo "exit=$?"   # 1 when at least one control fails
```

**Azure Pipelines break build behavior:** the same exit-code contract applies in a Bash or Command Line task on a Linux/Ubuntu agent. If `--fail-on fail` finds a failing control, Azure marks that task and job as failed after the reports have already been written. Publish the report directory with `PublishPipelineArtifact@1` and `condition: succeededOrFailed()` so the JSON and Markdown evidence remain available even when the gate blocks the run.

The same command above produces the failure-path evidence on an Azure Ubuntu agent; the JSON and Markdown reports are written before the non-zero exit, so the artifact remains publishable.
