# Evaluation report contract `reports/0.3`

> **`reports/1.0` is the v5.0.0 default contract.** `0.3` remains selectable for the entire `5.x` line via `--report-json-contract 0.3`. New integrations should target [reports/1.0](reports-contract-v1.0.md).

Version **0.3** is the default JSON contract for `evaluation-report.json` **for the v4.0.0 release line** once published; until **`v4.0.0`** is tagged and released, treat defaults on this branch as **implementation preview** alongside **`CHANGELOG.md`**.

It is a **strict superset** of `reports/0.2`: every key required by v0.2 remains, with two additional top-level objects that make CI gate semantics explicit for JSON consumers.

## Migration from `reports/0.2`

| Aspect | v0.2 | v0.3 |
| --- | --- | --- |
| `schema_version` URL suffix | `/reports/0.2` | `/reports/0.3` |
| Gate semantics | Implicit from `summary_by_status` | Same counts **plus** `summary_by_gate_role` and `gate_execution_model` |
| CLI selection | `--report-json-contract 0.2` | `--report-json-contract 0.3` (default) |

Downstream parsers can continue to read `summary_by_status` and `results`. New integrations should prefer `summary_by_gate_role` when deciding how a status participates in policy without re-deriving roles from free-form status strings.

## New fields

### `summary_by_gate_role`

Sparse object: only non-zero counts are emitted. Keys are stable:

| Key | Meaning |
| --- | --- |
| `ci_blocking_fail` | Controls in `fail` — counted when `--fail-on fail` or `degraded` |
| `human_review_gate` | `manual-review-required` — counted only when `--fail-on degraded` |
| `passed_observation` | `pass` |
| `self_attested_declarative` | `self-attested` (declarative, not verifier proof) |
| `not_evaluated_limit` | `not-evaluated` (limit of observation / evidence) |
| `waived` | `waived` |
| `not_applicable` | `not-applicable` |
| `not_observable` | `not-observable` |

### `gate_execution_model`

Static documentation object (version **1**) describing how `--fail-on` maps to `summary_by_status`. It does not change evaluation results; it documents the CLI contract.

## JSON Schema

Bundled schema file: `src/oss_policy_kit/data/schema/evaluation-report-v3.schema.json`.
