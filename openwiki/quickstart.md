---
type: guide
title: Repository quickstart
description: "Find the evaluation engine, policy definitions, evidence boundaries and operational workflows."
tags: [quickstart, repository, navigation, policy]
sources:
  - id: openwiki-source-16b97cbfa50dd2e922fba80e
    resource: repo://docs/openwiki.md
  - id: openwiki-source-05ccef8d4cf1698187f20464
    resource: repo://pyproject.toml
  - id: openwiki-source-23775c3de52f3ab95a13cb8b
    resource: repo://README.md
  - id: openwiki-source-b21ada9d12b89263154f1dc1
    resource: repo://src/oss_policy_kit/cli/main.py
generated: { by: "codex", at: "2026-10-14T16:32:54.436Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T17:35:14.202Z
---

# Repository quickstart

The OSS Security Policy as Code Starter Kit is a Python CLI and policy pack for assessing local repository governance, delivery configuration and supplied security evidence. It produces reviewable results and can apply an explicit exit policy. It does not certify security, legal compliance or live enforcement.

The package is `oss-policy-kit`; its CLI entry point is `oss_policy_kit.cli.main:main`. Python 3.12 or newer is required. Use the [repository README](../README.md) for installation and product scope, and [canonical documentation](../docs/README.md) for full command and adoption guides. The [OpenWiki setup guide](../docs/openwiki.md) describes the coding-agent integration, read boundaries and the scheduled workflow kept outside this change.

## Find the relevant system

| Task or uncertainty | Wiki page |
|---|---|
| Trace an assessment from request to result and artifacts | [Evaluation flow](architecture/evaluation-flow.md) |
| Select a policy, add controls or understand a waiver | [Profiles, controls and waivers](concepts/profiles-and-waivers.md) |
| Interpret status, confidence, unknowns and provenance | [Evidence and assurance](concepts/evidence-and-assurance.md) |
| Choose a CLI gate or consume reports in CI | [CLI and CI decisions](workflows/cli-and-ci.md) |
| Understand platform collection and scanner inputs | [Collectors and scanner evidence](integrations/collectors-and-scanners.md) |
| Correlate findings, emit VEX or export evidence | [Findings and supply-chain outputs](workflows/findings-and-supply-chain.md) |
| Add an evaluator or consume exported Rego/CEL | [Extensions and policy export](architecture/extensions-and-policy-export.md) |
| Select regression checks and maintain this wiki | [Testing and maintenance](operations/testing-and-maintenance.md) |

## A useful first assessment

Choose the target repository and a profile before evaluating. The [15-minute guide](../docs/quickstart-15-min.md) and [CLI reference](../docs/cli-reference.md) cover supported invocation forms. Start with a local assessment whose artifacts you can inspect.

Read the report's effective profile, control results, warnings and evidence scope together. A pass may be a local signal; missing or unobservable input remains a separate state. The `reports/2.0` JSON projection retains reason fields for unknown outcomes. A gate option then decides whether the assessed counts should stop CI.

Collection and scanning are separate opt-in workflows. Initializing consumer files writes configuration; evaluating a target writes reports. An external policy skeleton consumes the kit's output rather than reperforming analysis. Follow the page for that boundary before running a broader operation.

## Where source and tests live

`src/oss_policy_kit/` holds CLI, domain, application, adapters, infrastructure and packaged policy data. `tests/` holds focused examples, regression and property checks. `examples/` contains synthetic target repositories, and `action.yml` is the GitHub composite wrapper.

This wiki explains relationships and behavior rather than repeating the complete command or control catalog. Read the linked code and canonical guide when making a consequential decision. When source changes, update the affected pages and their source-linked claims; preserve the difference between implemented behavior, proposal and unverified external state.
