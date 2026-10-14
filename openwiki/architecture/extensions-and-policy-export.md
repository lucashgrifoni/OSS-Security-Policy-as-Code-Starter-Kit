---
type: architecture
title: Extensions and policy export
description: "The evaluator plugin contract and the boundary between assessment and external policy engines."
tags: [plugins, policy-export, rego, cel, architecture]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T16:07:56.899Z
sources:
  - id: openwiki-source-c27a03c6c89debff79801854
    resource: repo://src/oss_policy_kit/application/evaluators/__init__.py
  - id: openwiki-source-a90ebfa82ed65a5f993280af
    resource: repo://src/oss_policy_kit/cli/export_policy.py
  - id: openwiki-source-4d94a072b57258acb5bab0ec
    resource: repo://src/oss_policy_kit/domain/plugin_contract.py
  - id: openwiki-source-7c80b05264f2eda0124f531b
    resource: repo://tests/cli/test_export_policy_command.py
generated: { by: "codex", at: "2026-10-14T16:07:56.899Z" }
---

# Extensions and policy export

The evaluator registry owns control dispatch. Extensions add callables for new control IDs; policy export translates a profile into rules that consume an already-produced assessment report. These are separate integration boundaries.

## Evaluator plugins

A package registers evaluators in the `oss_policy_kit.evaluators` entry-point group. The entry-point name identifies the control. The callable accepts `EvalContext` and returns `EvalOutcome`; `domain/plugin_contract.py` exposes this as the `EvaluatorPlugin` protocol.

Built-ins load before third-party entry points. A plugin cannot replace a control that is already owned by a built-in. If two plugins claim the same ID, the first discovered callable retains it and the second receives a `plugin-collision` diagnostic. This diagnostic differs from `builtin-precedence`.

Discovery, import failures and non-callable objects are recorded in `PLUGIN_LOAD_ERRORS`. Consumers can inspect `plugin_load_errors()`, and the verbose evaluation path surfaces diagnostics. Successfully registered external IDs are tracked in `PLUGIN_CONTROL_IDS`, which lets the engine apply the third-party failure boundary described in [evaluation flow](evaluation-flow.md).

A plugin also needs policy data that references a known catalog entry. Registering a callable alone does not make an arbitrary ID part of a bundled profile. Review plugin code as executable Python in the assessor's process; the structural protocol is not a sandbox.

## Exported Rego and CEL

`export-policy` consumes a profile and catalog rather than an execution report. It sorts control IDs and emits a Rego or CEL skeleton. The external engine then receives an `evaluation-report.json` using the `reports/2.0` contract.

The generated rules require expected controls to be present with accepted report states. They do not repeat workflow parsing, scanner analysis, evidence verification or live collection. A policy engine consumes the kit's result; it does not independently establish the truth of the evidence behind it.

The lightweight `--validate` path checks generated structure. Runtime semantics belong to the target engine. The test suite distinguishes golden output and CLI checks from actual CEL compilation/evaluation and OPA execution; engine-dependent checks may skip when their runtime is missing. Inspect those results before claiming external engine compatibility.

## Where to extend and verify

Start with `domain/plugin_contract.py` and the registry's `_load_external_evaluators`. Failure and collision behavior is exercised in the focused plugin tests under `tests/application/`.

For policy export, follow `cli/export_policy.py`, `tests/cli/test_export_policy_command.py` and the maintained [policy export guide](../../docs/policy-export.md). See [CLI and CI decisions](../workflows/cli-and-ci.md) before treating exported policy as equivalent to a chosen CLI gate.
