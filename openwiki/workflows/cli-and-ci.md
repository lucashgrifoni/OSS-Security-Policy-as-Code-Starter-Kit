---
type: workflow
title: CLI and CI decisions
description: "How command configuration, artifact creation and fail-on policy affect CI outcomes."
tags: [cli, ci, gates, reports]
sources:
  - id: openwiki-source-96d0addee4aedab20d360121
    resource: repo://action.yml
  - id: openwiki-source-645665e27957da919cf563a8
    resource: repo://src/oss_policy_kit/application/cli_output.py
  - id: openwiki-source-248b9a62bf9d97f700ae7eec
    resource: repo://src/oss_policy_kit/application/engine.py
  - id: openwiki-source-af24618414b293764d200fc5
    resource: repo://src/oss_policy_kit/cli/common.py
  - id: openwiki-source-2c1982196f9fe8cf4a1506f2
    resource: repo://src/oss_policy_kit/cli/evaluate.py
  - id: openwiki-source-b21ada9d12b89263154f1dc1
    resource: repo://src/oss_policy_kit/cli/main.py
generated: { by: "codex", at: "2026-10-14T16:07:56.899Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-15T00:15:09.719Z
---

# CLI and CI decisions

The CLI is the main automation boundary. Its commands share a Typer application, but assessment, collection, scanning, initialization and export have different effects. Choose the command for the input and outcome needed rather than treating every exit zero as a clean security assessment.

## Assessment contract

Use the maintained [CLI reference](../../docs/cli-reference.md) for flags and examples. The explicit `evaluate` subcommand and compatible top-level invocation reach the same request implementation. Target and project configuration determine the effective profile, output directory and gate policy.

An assessment writes `evaluation-report.json` and `evaluation-report.md`. SARIF is opt-in. The current JSON contract is `reports/2.0`; removed or unsupported contracts are rejected rather than silently emitted as another format.

The CLI enables applicability and attested outcomes by default in its current command options. The programmatic engine has its own defaults, so a Python caller must supply the intended options explicitly. Read [profiles and waivers](../concepts/profiles-and-waivers.md) and [evidence and assurance](../concepts/evidence-and-assurance.md) before comparing runs from different callers.

## Gate policy

The policy acts on internal status counts after reports are written.

| `--fail-on` | Policy violation |
|---|---|
| `none` | No policy exit from the assessment counts |
| `fail` | At least one `fail` |
| `degraded` | At least one `fail` or `manual-review-required` |

The word `degraded` names a gate option, not a current domain result status. `not-evaluated`, `waived`, `not-observable` and `self-attested` do not independently trigger these two blocking policies. If incomplete collection must block a consumer pipeline, define and validate that additional policy rather than assuming `UNKNOWN` always blocks.

Exit 1 represents a policy violation after artifact creation. Invalid input is handled as exit 2; an unexpected kit defect is exit 3. Exit zero says the command completed without violating its implemented exit conditions. It does not establish deployment, remediation or complete observation.

## GitHub Action boundary

The root `action.yml` is a composite wrapper with target, profile, gate, waiver, Scorecard, optional SARIF and kit-version inputs. Its `fail-on` input defaults to `fail`. It exposes report paths and an exit-code output; SARIF upload belongs to the caller.

The wrapper ties its default installed package version to the pinned action revision. Use the [GitHub Action guide](../../docs/github-action.md) for the supported installation and caller workflow. A source declaration is not evidence that a particular branch requires the action or that its latest run evaluated the intended commit.

## Review artifacts

Keep the report, exact revision, selected profile and effective gate policy together. Review warnings and evidence scope alongside counts. See [evaluation flow](../architecture/evaluation-flow.md) for the implementation sequence and [testing and maintenance](../operations/testing-and-maintenance.md) for the repository's verification contract.
