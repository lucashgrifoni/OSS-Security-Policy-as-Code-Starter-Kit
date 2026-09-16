# Evidence export (`export-evidence`)

> **Available since v6.0.0; the `chainloop` format is still experimental.** The `export-evidence` subcommand and its Chainloop format renderer shipped in v6.0.0 and the `chainloop` format has carried the **experimental** label ever since, through the v10.x line: its output may change in any minor release if the Chainloop ingest spec evolves. Pin the exact kit version before a pipeline depends on that shape. See ADR-012 for the experimental-label rationale.

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
2. **Re-projects the most recent stored `reports/2.0` evaluation report** into the requested format. If no `reports/2.0` report is found (checked at `--report`, then `<target>/out/evaluation-report.json`, then `<cwd>/out/evaluation-report.json`), it exits 2 with a usage error telling you to run `evaluate` first — it never runs evaluation internally, and a stored pre-2.0 report is rejected (exit 2).
3. **Writes the output** to the path specified by `--output` (default depends on format).
4. **Exits 0** on successful export, **1** on contract validation failure, **2** on usage errors.

## Formats supported

| Format | Stability | Output |
|---|---|---|
| `chainloop` | experimental | Chainloop attestation envelope (JSON) wrapping the kit's report + SARIF. |
| `sarif` | stable | Re-export of the SARIF the `evaluate` subcommand already produces. Provided for parity with the registry pattern. |
| `spdx` | GA (v7.0.0) | SPDX 2.3 JSON **evidence projection** — one package (the evaluated repo) with one annotation per control. **Not** a dependency/component SBOM of the target (the kit is a clone-only evaluator, not a dependency resolver). See ADR-034. |
| `oscal` | GA (v7.0.0) | OSCAL 1.1 `assessment-results` JSON — each control result becomes an `EXAMINE` observation carrying the kit's verdict + assurance grade (as `props` under the `https://oss-policy-kit` namespace) and a reference to the evaluated repository; the result also carries an `assessment-subjects` entry and an `assessment-log` (run timestamp + tool). Unsigned. See ADR-036. Assurance/subject/log enrichment added in v8.1.0. |
| `in-toto-bundle` | GA (v7.0.0) | **Unsigned** in-toto v1 statement with a custom policy-evaluation predicate. Signing (cosign/Sigstore) is the v8 ATTESTED track; this statement is its input. See ADR-036. |
| `gemara` | GA (v8.1.0) | OpenSSF **Gemara Layer 5 Evaluation Log** (JSON) — the kit is a conformance gate (Layer 5). Each control becomes a `ControlEvaluation`; the kit state maps to a Gemara `Result` (`Passed`/`Failed`/`Needs Review`/`Not Applicable`) and the assurance grade to a `ConfidenceLevel`. Structurally valid, unsigned; the Gemara schema is pre-1.0 (CUE), so the targeted model version is pinned in `gemara-version` and no CUE dependency is added. See ADR-042. |

Planned for a future release (not yet shipped):

| Format | Notes |
|---|---|
| `guac` | [GUAC](https://guac.sh/) ingest format. Audience is graph-database supply-chain tooling. Deferred until adopter demand surfaces (avoids duplicating Chainloop's graph integration). |

## Why "experimental" for `chainloop`

Chainloop's ingest spec is pre-1.0 and has changed twice since 2024. ADR-012 documents the design tension. The contract from the kit's side:

- The **subcommand surface** (`export-evidence`, `--format`, `--output`, `--target`) is stable.
- The **output shape for `--format chainloop`** may change in v6.0.x if Chainloop maintainers revise their spec. The CHANGELOG will call out any change.
- Promotion to **stable** depends on adopter feedback and Chainloop spec stability; no v6.x promotion date is committed.

Adopters running `export-evidence --format chainloop` in production should pin the kit version explicitly and read the CHANGELOG before upgrading inside the v6.x line.

## What `export-evidence` will not do

- Push to a Chainloop server. The subcommand writes a local file; piping into Chainloop is a separate step (`chainloop attestation add ...`).
- Validate that Chainloop accepted the evidence. Adopters should run their own ingest verification.
- Re-implement the kit's evaluation logic. If no prior `reports/2.0` `evaluation-report.json` is found (checked at `--report`, then `<target>/out/`, then `<cwd>/out/`), the subcommand exits 2 with a usage error pointing you to run `evaluate` first — it never runs evaluation internally.
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
- ADR-034 — SPDX 2.3 evidence export (evidence projection, not a dependency SBOM)
- ADR-036 — OSCAL + in-toto-bundle (unsigned) GA promotion; `guac` deferred
- [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) · [OSCAL assessment-results](https://pages.nist.gov/OSCAL/) · [in-toto attestation](https://github.com/in-toto/attestation)
- ADR-002 (`emit-vex` scope) and ADR-011 (`emit-insights`) — same emit-only pattern
- [`positioning.md`](positioning.md) → *Composition with Chainloop*
