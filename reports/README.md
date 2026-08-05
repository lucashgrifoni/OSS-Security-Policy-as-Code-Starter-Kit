# Report Schemas

This directory contains the **public JSON Schema files** for evaluation output and optional evidence documents that downstream consumers and integrators are expected to read.

The concrete schema files live under [`reports/schema/`](./schema/).

## Public vs internal schemas

This kit ships two JSON Schema directories that are intentionally distinct:

- **`reports/schema/`** — *public surface*. Stable JSON Schema files for the documented CURRENT contracts: `evaluation-report-2.0.schema.json` (`docs/reports-contract-v2.0.md`), `findings-1.0.schema.json` (`docs/findings-correlation.md`), and the per-scanner `evidence-*.schema.json` files. External tooling that parses `evaluation-report.json`, `findings.json`, or evidence JSON should pin to files under this directory.
- **`src/oss_policy_kit/data/schema/`** — *internal/packaged surface*. The schemas the CLI imports at runtime: `reports/2.0.json`, `findings/1.0.json`, `profile-recommendation-v2.schema.json`, `profile-spec.schema.json`, and the per-scanner `evidence-*.schema.json` files. They are loaded as Python package data via `importlib.resources` and are part of the wheel.

The two directories are kept in sync where they cover the same artifact — `reports/schema/evaluation-report-2.0.schema.json` mirrors `src/.../data/schema/reports/2.0.json`, and each shared `evidence-*.schema.json` is byte-identical in both. That parity is enforced by tests (`test_schema_copies_match_reports_schema` and its AWS and Azure siblings), so the copies cannot drift silently. The internal copy is what the CLI validates against; the public copy is what external integrators should read.

The internal directory additionally carries schemas with no public counterpart, because they describe evidence the CLI consumes rather than output it produces: `evidence-ai-agent-baseline`, `evidence-ai-system-technical-doc`, and the four `evidence-iac-*` schemas.

**Removed in v10.0.0 (ADR-043):** the legacy `evaluation-report-v1`, `-v2` and `-v3` schema files no longer exist. `reports/2.0` is the only report contract, and `--report-json-contract` accepts only `2.0`. If you pinned a pre-2.0 schema file, see [`docs/v10.0.0-migration-guide.md`](../docs/v10.0.0-migration-guide.md).

If you are writing a downstream parser or pinning a contract version, prefer `reports/schema/`. If you are debugging the kit itself, the source of truth at runtime is `src/oss_policy_kit/data/schema/`.

## Output directory hygiene

The `evaluate`, `evaluate-many`, `scaffold-evidence`, and `collect-evidence` commands all accept an `--output-dir` flag (default `out/`). Two operational notes:

- The default `out/` directory is **gitignored** for this project. It is meant to hold reports and evidence emitted during local runs.
- The CLI **does not auto-prune** `--output-dir`. Successive runs accumulate; either point each run at a unique path (for example `--output-dir ./out/<run-id>/`) or clean periodically.
- In CI, publish the output as a workflow artifact when you need to retain evidence; do not commit it to the repository.
