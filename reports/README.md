# Report Schemas

This directory contains the **public JSON Schema files** for evaluation output and optional evidence documents that downstream consumers and integrators are expected to read.

The concrete schema files live under [`reports/schema/`](./schema/).

## Public vs internal schemas

This kit ships two JSON Schema directories that are intentionally distinct:

- **`reports/schema/`** — *public surface*. Stable JSON Schema files referenced from the documented contracts (`docs/reports-contract-v0.3.md`, `docs/reports-contract-v1.0.md`) and from `evaluation-result.schema.json` here. External tooling that parses `evaluation-report.json` or evidence JSON should pin to files under this directory.
- **`src/oss_policy_kit/data/schema/`** — *internal/packaged surface*. The schemas the CLI imports at runtime (versioned `evaluation-report-v1`, `-v2`, `-v3` schemas, plus profile-list, profile-recommendation, and profile-spec schemas). They are loaded as Python package data via `importlib.resources` and are part of the wheel.

The two directories are kept in sync where they cover the same artifact (for example `evaluation-result.schema.json` mirrors the public-facing portion of `src/.../data/schema/evaluation-report-v1.schema.json`). The internal copy is what the CLI validates against; the public copy is what external integrators should read.

If you are writing a downstream parser or pinning a contract version, prefer `reports/schema/`. If you are debugging the kit itself, the source of truth at runtime is `src/oss_policy_kit/data/schema/`.

## Output directory hygiene

The `evaluate`, `evaluate-many`, `scaffold-evidence`, and `collect-evidence` commands all accept an `--output-dir` flag (default `out/`). Two operational notes:

- The default `out/` directory is **gitignored** for this project. It is meant to hold reports and evidence emitted during local runs.
- The CLI **does not auto-prune** `--output-dir`. Successive runs accumulate; either point each run at a unique path (for example `--output-dir ./out/<run-id>/`) or clean periodically.
- In CI, publish the output as a workflow artifact when you need to retain evidence; do not commit it to the repository.
