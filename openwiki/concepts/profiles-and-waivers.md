---
type: concept
title: Profiles, controls and waivers
description: "How the policy catalog selects controls and how exceptions affect an assessment."
tags: [profiles, controls, waivers, applicability]
sources:
  - id: openwiki-source-30273f94f6f895e562a0db2f
    resource: repo://src/oss_policy_kit/application/applicability.py
  - id: openwiki-source-248b9a62bf9d97f700ae7eec
    resource: repo://src/oss_policy_kit/application/engine.py
  - id: openwiki-source-adc28e55a941dffa04498dd7
    resource: repo://src/oss_policy_kit/application/loader.py
  - id: openwiki-source-07cd0eb6ac54e767dda774cf
    resource: repo://src/oss_policy_kit/application/vuln_waivers.py
  - id: openwiki-source-fce9f2750633ebdf6b0f8983
    resource: repo://src/oss_policy_kit/application/waivers.py
generated: { by: "codex", at: "2026-10-14T17:21:37.203Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T17:21:37.203Z
---

# Profiles, controls and waivers

A profile selects control IDs. The catalog defines the metadata and assurance attached to those IDs. The evaluator registry supplies executable behavior. This separation lets the same assessment engine apply different repository and framework baselines.

## Policy loading

Bundled assets live under `src/oss_policy_kit/data/`: the catalog is `controls/catalog.yaml`, and each profile has a `profiles/<id>/profile.yaml`. A catalog entry includes category, automation, lifecycle, assurance and weight. A profile includes its identity, purpose and ordered controls.

The loader accepts a bundled profile ID or an existing YAML profile file. External files receive schema validation. It removes repeated control IDs while preserving first occurrence, so an external profile cannot increase summary counts or score merely by listing a control twice. Removed profile IDs receive migration guidance rather than a silent replacement.

The engine rejects unknown catalog IDs. For a control that proceeds to dispatch, a missing evaluator is an error; an unmet applicability condition can end evaluation before registry lookup. A custom profile must reference controls the selected catalog and registry can actually evaluate. See the [CLI reference](../../docs/cli-reference.md) and the CLI's `profiles` command for discovery.

## Applicability

A control can declare a `requires_any_files` precondition. The resolver checks the repository filesystem; it does not execute the target. No precondition means applicable, and any matching real file satisfies a declared pattern set.

The engine consults these conditions when the applicability option is enabled. An unmet condition then produces `not-applicable` before dispatch. Do not read that result as a statement that a platform is safe: it is a statement about the control's scope for this target.

## Control exceptions

The waiver parser expects a YAML mapping with a `waivers` list. A usable record needs a control ID, justification and owner. An omitted status defaults to `approved`; an explicit status must be `approved` or `active`. The parser validates expiry data and skips invalid or expired entries with warnings. The legacy `reason` spelling can supply the justification.

The engine applies an approved or active control waiver only to `fail` or `manual-review-required`. It does not change an existing pass or substitute evidence for an unattempted evaluation. Applied records travel in `ControlResult` so consumers can retain owner and expiry.

Entries keyed by `vulnerability_ids` belong to the vulnerability/VEX workflows rather than control-gate exceptions. Keep those models distinct. See [findings and supply-chain outputs](../workflows/findings-and-supply-chain.md).

## Validation and related behavior

`test_profile_schemas.py` checks required profile fields, ID-directory agreement, catalog membership and duplicate controls. Waiver and engine tests cover validation and the resulting `waived` disposition.

Read [evaluation flow](../architecture/evaluation-flow.md) for dispatch and [CLI and CI decisions](../workflows/cli-and-ci.md) for how status counts become an exit decision.
