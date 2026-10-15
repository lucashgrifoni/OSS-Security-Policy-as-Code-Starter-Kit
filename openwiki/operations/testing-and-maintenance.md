---
type: operations
title: Testing and maintaining the wiki
description: "Choose validation for policy, CLI and evidence changes, and keep repository documentation grounded."
tags: [testing, maintenance, documentation, quality]
sources:
  - id: openwiki-source-f317ee207e1653d2033c81a4
    resource: repo://CONTRIBUTING.md
  - id: openwiki-source-16b97cbfa50dd2e922fba80e
    resource: repo://docs/openwiki.md
  - id: openwiki-source-e865e7cced25c8de4a959b5d
    resource: repo://scripts/check_public_hygiene.py
  - id: openwiki-source-9e261c7f6301c42cb1acc765
    resource: repo://tests/application/test_profile_schemas.py
generated: { by: "codex", at: "2026-10-14T16:32:54.436Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-15T00:15:09.719Z
---

# Testing and maintaining the wiki

Validation should follow the behavior that changed. A profile change needs catalog and profile invariants; an evaluator change needs positive, negative and incomplete-input cases; a report change needs schema and rendering checks. A green job describes the checks it ran, not coverage of every platform condition.

## Repository quality contract

The [contribution guide](../../CONTRIBUTING.md) defines the local gate: lint, formatting, type checking, public hygiene, the test suite, property tests and the kit's own assessment of this repository.

Its two coverage invocations are one gate. The non-property tests collect coverage first; property tests append to it and enforce the final 100% floor. Running plain pytest without that coverage sequence does not verify the documented floor.

The public-hygiene check is separate from pytest. It scans public file content and forbids private operating-context filenames. Keep agent configuration, local evidence and runtime paths out of public changes. The repository self-check adds a different observation: controls run against actual repository input rather than only synthetic fixtures.

## Focused tests by boundary

| Changed behavior | Starting point |
|---|---|
| Evaluation and exceptions | `tests/application/test_engine.py`, waiver tests |
| Profile identity and membership | `tests/application/test_profile_schemas.py` |
| Current report contract | `tests/application/test_report_schema.py`, reports/2.0 tests |
| Evidence trust and redaction | Evidence projection tests under `tests/application/` |
| Collector degradation | Collector tests under `tests/unit/` |
| CLI exits and artifacts | `tests/cli/` |
| Exported policy execution | `tests/cli/test_export_policy_command.py` |

The profile invariant suite checks identity, required fields, known control IDs and duplicate membership. Property tests broaden input coverage for clocks, schemas, normalization and other contracts; they complement specific regression examples.

When an external engine, scanner or live canary is unavailable, record the affected skip or limitation. A mocked collector response does not validate credentials against a live organization. Read [testing strategy](../../docs/testing-strategy.md) before choosing broader validation.

## Maintaining repository memory

This wiki is an architecture and workflow map. Canonical user guides remain under `docs/`; update those guides when their public contract changes. Follow [evaluation flow](../architecture/evaluation-flow.md) and [CLI and CI decisions](../workflows/cli-and-ci.md) to find the affected source and consumers.

For OpenWiki maintenance, use the coding-agent integration to update the wiki after source changes. The [project setup guide](../../docs/openwiki.md) records installation, read boundaries and the local-only scheduled-workflow scaffold. The [upstream guide](https://github.com/langchain-ai/openwiki#keep-your-wiki-current) explains source-linked claims and update runs. Review the resulting Markdown and instruction-file diff alongside the source change.

Treat wiki content as evidence-backed context. Verify consequential details against source and tests, retain limitations, and keep roadmap separate from implemented behavior. This pilot adds repository documentation; it does not introduce scheduled generation or auto-merge.
