# ADR-027 - Flip the default report contract to reports/2.0 (v7.0.0)

- **Status**: accepted (targets v7.0.0, BREAKING) — ratified by maintainer 2026-06-01
- **Date**: 2026-05-25 (proposed); 2026-06-01 (accepted)
- **Context window**: v7.x roadmap horizon — "Contract modernization & ecosystem interoperability"
- **Related**: ADR-013 (reports/2.0 contract), ADR-008 (schema URL), ADR-033/034/035/036 (v7.0.0 bundle companions), `docs/reports-contract-v2.0.md`, `scripts/migrate-1.0-to-2.0.py`, the maintainer's local roadmap (not published)

> **Ratification note (2026-06-01).** This supersedes the roadmap plan §11.1 decision
> (2026-05-26) that deferred the flip for "one more opt-in cycle". The maintainer elected to
> stop deferring and ship the flip as the defining change of **v7.0.0**, bundled with the
> remaining v7.x interop additives (SPDX/CEL-Rego/OSCAL+in-toto exporters — ADR-034/035/036)
> and the ingest-insights control-evidence wiring (ADR-033). The bundle's stacked-risk is
> **accepted by the owner**; mitigation is internal phase ordering (flip + additive exporters
> + wiring sequenced so golden fixtures are regenerated once per phase, not interleaved). The
> hard gate from roadmap §8 — RX-05 (`docs/reports-contract-v2.0.md` factually correct) — is
> **resolved**: the stale "removed in v6.1.0" claim was already corrected (the doc now states
> no removal shipped). See `melhorias` execution plan `roadmap-v7.0.0-execution-plan-2026-06-01.md`.

## Context

ADR-013 (v6.0.0) registered a parallel `reports/2.0` contract with the
Scorecard-aligned five-state vocabulary (`PASS / FAIL / UNKNOWN / NOT_APPLICABLE /
ATTESTED`) and **deliberately deferred** the default switch: `reports/1.0` has
remained the default through v6.5.0, with `2.0` opt-in via `--report-json-contract`.

That deferral has now outlived its purpose. The wider ecosystem the kit composes
with (Scorecard v6 conformance output, Gemara, OSPS Baseline) speaks the five-state
vocabulary, and a stale deprecation note in `docs/reports-contract-v2.0.md` already
claimed (incorrectly) that `1.0` was removed in v6.1.0 — evidence that carrying two
defaults indefinitely is a documentation and trust liability. The offline migration
tool (`scripts/migrate-1.0-to-2.0.py`) already exists and converts stored reports
between vocabularies, so the mechanical cost of the switch is low.

Flipping the **default** report contract is breaking for any consumer that parses
report JSON and does not pin `--report-json-contract=1.0`. A breaking change requires
a major bump and a migration window.

## Decision

In **v7.0.0**, make `reports/2.0` the **default** report contract.

- `reports/1.0` remains selectable via `--report-json-contract=1.0` for **one minor
  cycle** after the flip, then is deprecated with a warning, then removed in a later
  major.
- `docs/reports-contract-v2.0.md` is corrected to state the real timeline (RX-05 of
  the 2026-05-25 raio-x) **before** the flip ships; the obsolete "removed in v6.1.0"
  lines are deleted.
- A migration guide accompanies the release; `scripts/migrate-1.0-to-2.0.py` is
  referenced as the mechanical path for stored reports.
- SARIF and Markdown outputs are unaffected (the flip is scoped to the default JSON
  contract). Exit-code semantics are unchanged.
- The change is validated by `cli-api-ui-contract-validator` and by updating golden
  report fixtures to `2.0`.

## Alternatives considered

1. **Keep `1.0` as default indefinitely.** Rejected — diverges permanently from the
   Scorecard-aligned vocabulary the kit positions around, and the stale docs show the
   dual-default is already causing factual drift.
2. **Flip inside a v6.x minor.** Rejected — changing the default output shape is
   breaking for unpinned consumers; semver requires a major.
3. **Remove `1.0` in the same release as the flip.** Rejected — too abrupt; a one-cycle
   selectable window preserves trust for adopters who pin late.

## Consequences

- Unpinned consumers receive `reports/2.0` JSON after v7.0.0; the migration guide and
  script make the transition mechanical.
- The kit's default output finally matches the vocabulary it composes with downstream.
- Two contracts coexist for one more cycle (selectable), then `1.0` is deprecated —
  ending the open-ended dual-default.
- Trade-off: a major bump is "spent" on a contract flip; ADR-028 (v8.0.0) sequences
  after it so the five-state vocabulary is the default *before* the engine starts
  populating the `ATTESTED` state meaningfully.

## References

- ADR-013, `docs/reports-contract-v2.0.md`, `scripts/migrate-1.0-to-2.0.py`
- OpenSSF Scorecard v6 conformance model — <https://github.com/ossf/scorecard/pull/4952>
- the maintainer's local roadmap (not published) (v7.x horizon); local roadmap plan (§6, §11.1)
