# Evidence export (`export-evidence`)

> **In development (v6.0.0; experimental)**. The `export-evidence` subcommand and its Chainloop format renderer land with PR-17 on the `feat/v6.0.0-evolution` branch. **They do not ship in v5.9.x.** The `chainloop` format is **experimental** — its output may change in v6.0.x if the Chainloop ingest spec evolves. See ADR-012 for the experimental-label rationale.

This page is the third in the emit-only subcommand family alongside [`vex-emission.md`](vex-emission.md) (`emit-vex`) and [`insights-emission.md`](insights-emission.md) (`emit-insights`). The architectural pattern is the same: a dedicated subcommand re-projects existing evaluator outputs into a stable external format without adding new controls to the catalog.

## What is Chainloop?

[Chainloop](https://chainloop.dev/) is an open-source evidence platform (controlplane + persistence) that aggregates attestations, SBOMs, scan results, and policy verdicts emitted from CI pipelines. Release reviewers can then query the corpus per artifact and per release through Chainloop's UI or API. The relationship between Chainloop and this kit is **composition**, not competition (see [`positioning.md`](positioning.md) → *Composition with Chainloop*):

- **This kit** is a local-first emit layer.
- **Chainloop** is the server-side store.

Adopters running both today write glue code to translate the kit's `evaluation-report.json` plus SARIF into Chainloop's attestation envelope. `export-evidence --format chainloop` removes that glue.

## How `export-evidence` will work

```text
$ oss-policy-kit export-evidence --target . --format chainloop --output evidence.json
```

The subcommand:

1. **Reads the target repository** — same `--target` semantics as `evaluate`.
2. **Re-projects the most recent evaluation output** (or runs evaluation internally if no prior output exists) into the requested format.
3. **Writes the output** to the path specified by `--output` (default depends on format).
4. **Exits 0** on successful export, **1** on contract validation failure, **2** on usage errors.

## Formats supported in v6.0.0

| Format | Stability | Output |
|---|---|---|
| `chainloop` | experimental | Chainloop attestation envelope (JSON) wrapping the kit's report + SARIF. |
| `sarif` | stable | Re-export of the SARIF the `evaluate` subcommand already produces. Provided for parity with the registry pattern. |

Planned for v6.1.0+ (not in v6.0.0):

| Format | Notes |
|---|---|
| `guac` | [GUAC](https://guac.sh/) ingest format. Audience is graph-database supply-chain tooling. Will land if adopter demand surfaces. |
| `oscal` | OSCAL-aligned compliance evidence. Heavier; depends on stabilizing OSCAL's component-definition shape. |
| `in-toto-bundle` | in-toto Attestation Bundle v1. Smaller scope; may be a Chainloop sub-format rather than a peer. |

## Why "experimental" for `chainloop`

Chainloop's ingest spec is pre-1.0 and has changed twice since 2024. ADR-012 documents the design tension. The contract from the kit's side:

- The **subcommand surface** (`export-evidence`, `--format`, `--output`, `--target`) is stable.
- The **output shape for `--format chainloop`** may change in v6.0.x if Chainloop maintainers revise their spec. The CHANGELOG will call out any change.
- Promotion to **stable** happens in v6.1.0 based on adopter feedback and Chainloop spec stability.

Adopters running `export-evidence --format chainloop` in production should pin the kit version explicitly and read the CHANGELOG before upgrading inside the v6.0.x line.

## What `export-evidence` will not do

- Push to a Chainloop server. The subcommand writes a local file; piping into Chainloop is a separate step (`chainloop attestation add ...`).
- Validate that Chainloop accepted the evidence. Adopters should run their own ingest verification.
- Re-implement the kit's evaluation logic. If the working tree has no prior `evaluation-report.json`, the subcommand runs `evaluate` internally with the default profile and exports the result.
- Add new controls to the catalog. The format registry is renderer-only.

## What you should still do

1. **Pin the kit version** when wiring `export-evidence --format chainloop` into CI; experimental output may change.
2. **Watch the CHANGELOG** for `## Unreleased` entries that mention `export-evidence` or Chainloop.
3. **Open an issue** on the kit repo if the Chainloop ingest spec moves before the kit catches up — that is the fastest path to adopter-relevant feedback.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Export successful. |
| 1 | Export wrote output but contract validation against the requested format failed. |
| 2 | Usage error (bad flags, missing target, unknown format). |

## References

- [Chainloop repo](https://github.com/chainloop-dev/chainloop) + [Chainloop docs](https://chainloop.dev/)
- ADR-012 — design rationale, experimental-label justification, format registry
- ADR-002 (`emit-vex` scope) and ADR-011 (`emit-insights`) — same emit-only pattern
- [`positioning.md`](positioning.md) → *Composition with Chainloop*
