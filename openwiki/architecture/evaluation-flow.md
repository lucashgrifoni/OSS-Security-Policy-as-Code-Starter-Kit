---
type: architecture
title: Evaluation flow
description: "How a CLI request becomes control results, artifacts and a gate decision."
tags: [evaluation, architecture, reports, cli]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T16:07:56.899Z
sources:
  - id: openwiki-source-248b9a62bf9d97f700ae7eec
    resource: repo://src/oss_policy_kit/application/engine.py
  - id: openwiki-source-af24618414b293764d200fc5
    resource: repo://src/oss_policy_kit/cli/common.py
  - id: openwiki-source-8fb9ccbe2c3431ac446d9686
    resource: repo://tests/application/test_engine.py
generated: { by: "codex", at: "2026-10-14T16:07:56.899Z" }
---

# Evaluation flow

The assessment runs against a local repository directory. The CLI resolves the target and settings, loads a profile and catalog, builds evaluation context, evaluates the selected controls, then writes reports. The gate decision follows the report-writing step.

## Request and configuration boundary

`cli/main.py` registers command modules against one Typer application. Both the explicit `evaluate` command and the compatible top-level invocation reach the shared implementation in `cli/common.py`.

The shared implementation resolves the target, combines CLI settings with project configuration, validates the output and gate options, loads waivers and optional Scorecard input, and calls `evaluate_repository`. Configuration affects which policy is applied; it does not establish that a platform control is enforced.

## Context and control dispatch

`evaluate_repository` analyzes GitHub Actions workflows, Azure pipelines, AWS CI definitions and GitLab CI files, and puts those observations into one `EvalContext`. The selected profile supplies the ordered control IDs. The catalog supplies each control's title, assurance class, lifecycle and weight.

For each ID, the engine checks the catalog and evaluator registry. When the applicability engine is enabled and a declared precondition is absent, it returns `not-applicable` before calling the evaluator. Applicability is an explicit option in this engine path.

Built-in evaluators run directly. A built-in exception is a kit defect and reaches the CLI error boundary. Third-party evaluator calls have a separate containment boundary: a broken plugin yields a bounded control outcome and warning, so it can be distinguished from a kit defect.

## Results, exceptions and artifacts

An evaluator returns `EvalOutcome`, including status, reason, remediation, confidence, evidence sources and collection method. The engine applies a valid control waiver after evaluation and builds a `ControlResult` with catalog metadata and any applied exception. The underlying outcome remains visible through the reason and evidence; a waiver does not prove a fix.

The run assembles an `ExecutionReport` containing control results, warnings, status counts and scoring information. The CLI writes JSON and Markdown and optionally SARIF before applying `--fail-on`. This ordering gives a failing CI assessment reviewable artifacts.

See [evidence and assurance](../concepts/evidence-and-assurance.md) for the difference between internal states and the `reports/2.0` wire contract, and [CLI and CI decisions](../workflows/cli-and-ci.md) for exit behavior.

## Tests and canonical references

`tests/application/test_engine.py` covers hardened and vulnerable fixtures and a waiver that turns one failure into `waived`. Those are synthetic repository cases, not observations of a production platform. Plugin failure tests are under `tests/application/`.

The maintained [architecture reference](../../docs/architecture.md) provides the package and control-family map. Follow current source when a historical description differs from a present implementation.
