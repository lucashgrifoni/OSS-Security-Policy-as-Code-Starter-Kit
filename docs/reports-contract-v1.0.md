# Evaluation report contract `reports/1.0`

> **Removed in v9.0.0 (ADR-043).** `reports/1.0` was the default contract from **v5.0.0** through the v6.x line, then became non-default in **v7.0.0** when the default flipped to [`reports/2.0`](reports-contract-v2.0.md) (ADR-027). In **v9.0.0** `reports/2.0` became the only evaluation-report contract: `reports/1.0` is no longer selectable, and `--report-json-contract=1.0` now exits 2. This page is kept as a historical reference for the contract that v5.x integrations consumed. See [`reports/2.0`](reports-contract-v2.0.md) and the [v9.0.0 migration guide](v9.0.0-migration-guide.md).

`reports/1.0` was the default JSON contract for `evaluation-report.json` from **v5.0.0** through v6.x.

It is decoupled from the Python package version: contract `1.0` describes wire stability for downstream tooling, not the release-track stability of the package itself (the package classifier remains independent).

## Why a new contract

`reports/1.0` introduces three structural improvements over `reports/0.3`:

1. **Structured `evidence` object per result.** Trust semantics, freshness, attestation status, source platform, and limitations become first-class fields instead of being inferred from free-form text.
2. **Strict shape (`additionalProperties: false`).** Top-level and per-result keys are locked to the schema. Forward-compatible growth happens under the explicit `extensions` namespace (`x_*` keys only).
3. **Deterministic `results_digest`.** A SHA-256 fingerprint over canonical control-result fields lets drift tooling compare runs without re-deriving stability from free-form output.

## Selecting `reports/1.0`

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 \
  --output-dir ./out --report-json-contract 1.0
```

Selecting `1.0` was removed in v9.0.0 (ADR-043): `--report-json-contract` now accepts only `2.0`, and passing `1.0` exits 2. The command above is retained only to show the historical invocation. See [`reports/2.0`](reports-contract-v2.0.md).

## Compatibility with `0.3` and `0.2`

| Contract | v5.0.0 status | Selectable via |
|---|---|---|
| `reports/1.0` | **Default.** | `--report-json-contract 1.0` (or omit the flag). |
| `reports/0.3` | Selectable for the entire `5.x` line. | `--report-json-contract 0.3`. |
| `reports/0.2` | Selectable. | `--report-json-contract 0.2`. |
| `reports/0.1` | **Removed.** | Rejected with migration text. |

`0.3` and `0.2` payloads are emitted byte-for-byte unchanged from v4 to keep downstream parsers stable.

## Top-level shape

Required keys:

| Key | Description |
|---|---|
| `schema_version` | URL ending in `/reports/1.0`. |
| `evidence_provenance_version` | Evidence model version (`evidence/2.0` in v5.0.0). |
| `generated_at` | UTC timestamp. |
| `kit_version` | OSS Policy Kit version that produced the report. |
| `target_path` | Evaluated repository path. |
| `profile` | `{ id, title, family, level, posture, is_release_track, recommended_gate }`. |
| `summary_by_status` | Aggregate counts per status string. |
| `summary_by_gate_role` | Aggregate counts under CI gate roles. |
| `gate_execution_model` | Documentation object (`model_version: 2`) describing `--fail-on` semantics. |
| `results` | Array of structured control results (see below). |
| `results_digest` | `sha256:` over canonical fields, stable across runs. |
| `operational_warnings` | Non-blocking strings. |
| `scorecard` | `{ path, supplemental }`. |
| `external_waiver_path` | Path passed via `--waivers`, or null. |
| `action_insights` | `{ top_structural_causes, recommended_actions, failing_controls_by_category }`. |
| `live_collection` | Live API-collection metadata, or null. |
| `weighted_score` | `{ earned, possible, percent }`, or null. |
| `migration` | Object describing legacy artifacts encountered, or null. |
| `extensions` | Object reserved for `x_*` keys. |

`additionalProperties: false` at the document root.

## Control result shape

Required per-result keys:

- `control_id`, `title`, `category`, `lifecycle`, `profile`.
- `status` (existing enum).
- `gate_role` — derived from status: one of `ci_blocking_fail`, `human_review_gate`, `passed_observation`, `self_attested_declarative`, `not_evaluated_limit`, `waived`, `not_applicable`, `not_observable`.
- `assurance` (`deterministic | signal | evidence-backed`).
- `confidence` enum (`high | medium | low | none`).
- `weight` (1..3).
- `reason`, `remediation`.
- `evidence` (structured, see next section).
- `owner`, `expires_at` (`string|null`).
- `waiver` — same shape as v0.x or null.
- `extra` — object reserved for non-public extension data.

Optional:

- `deprecation_note`.
- `finding_id` — stable id `{control_id}@{profile_id}` for SARIF correlation and downstream deduplication.

## `evidence` object (Evidence Model v2)

Each result carries a structured `evidence` object:

| Field | Type | Notes |
|---|---|---|
| `source_type` | enum | `static_clone`, `api_collected`, `user_supplied`, `derived`, `heuristic_signal`, `manual_review`, `not_observable`. |
| `trust_level` | enum | `verified`, `declared`, `inferred`, `unobserved`. |
| `collection_method` | enum | `live`, `manual`, `static`. |
| `collected_at` | `string|null` | ISO8601 UTC timestamp when known. |
| `source_platform` | `string|null` | `github`, `azure`, `aws`, `local`, etc. |
| `freshness_status` | enum | `fresh`, `stale`, `unknown`, `not_applicable`. |
| `attestation_status` | enum | `signed`, `self_attested`, `none`, `not_applicable`. |
| `references` | array | `{ kind, value, redacted }` items. Absolute paths are redacted. |
| `limitations` | string array | Human-readable scope notes ("evidence is self-attested", "freshness window exceeded", "catalog assurance is signal — trust cannot exceed inferred"). |
| `digest` | `string|null` | Optional `sha256:` digest of an evidence artifact. |
| `evidence_schema_id` | `string|null` | Identifier of the bundled evidence schema this result resolves against. |

### Trust promotion rules (no silent inflation)

1. `assurance: signal` results cannot project to `trust_level: verified`. They become `trust_level: inferred` at best — even when `status == pass`.
2. `api_collected` evidence reaches `trust_level: verified` only when `freshness_status: fresh` AND `attestation_status` is `signed` or `self_attested`.
3. Stale evidence (older than the freshness window — default 90 days) projects to `trust_level: declared`.
4. `not-observable` and `not-applicable` route to `unobserved`.

## SARIF output

`evaluate` accepts `--sarif-output PATH` to emit a SARIF 2.1.0 log alongside the JSON and Markdown reports. Mapping:

- One SARIF result per `fail` or `manual-review-required` finding.
- `level: error` for `fail`; `level: warning` for `manual-review-required`.
- Repository-level findings emit `physicalLocation.artifactLocation.uri = "."` and **omit** the `region` object.
- File-backed findings (with clone-relative evidence) emit the relative path under `%SRCROOT%`.
- `properties.security-severity` derived from weight × status. Manual-review entries get a -2.0 floor relative to a hard fail at the same weight.
- `partialFingerprints.controlAndProfile/v1 = "{control_id}@{profile_id}"` for stable deduplication.

## JSON Schema

Bundled schema file, while this contract shipped: `src/oss_policy_kit/data/schema/evaluation-report-v1.schema.json` (UTF-8, strict). It was **deleted in v10.0.0** along with the other legacy schema files, so it is not in the current wheel; `git show v9.0.3:src/oss_policy_kit/data/schema/evaluation-report-v1.schema.json` recovers it if an old report still needs validating.

## Migration from `reports/0.3`

| Aspect | `0.3` | `1.0` |
|---|---|---|
| `schema_version` URL suffix | `/reports/0.3` | `/reports/1.0` |
| Per-result evidence | flat: `evidence_sources`, `evidence_collection_method`, free-form `confidence` | structured `evidence` object + enum `confidence` (`high|medium|low|none`) |
| Top-level identity of profile | `profile_id`, `profile_title` | `profile.{id,title,family,level,posture,is_release_track,recommended_gate}` |
| Scorecard layout | `scorecard_path`, `scorecard_supplemental` (flat) | `scorecard.{path,supplemental}` |
| Drift fingerprint | not provided | `results_digest` (sha256 over canonical fields) |
| Strictness | `additionalProperties: true` | `additionalProperties: false` |
| Migration block | not provided | `migration` (null when no legacy artifacts encountered) |
| Extension surface | implicit | explicit `extensions.x_*` |

Downstream parsers that key off `summary_by_status` and `results[]` keep working with the 0.3 selector during the entire `5.x` line. New integrations should target `1.0` and read the structured `evidence` block.
