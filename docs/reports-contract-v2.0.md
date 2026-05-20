# Reports contract `reports/2.0`

> **In development (v6.0.0; breaking)**. `reports/2.0` lands with PR-16 on the `feat/v6.0.0-evolution` branch. **It does not ship in v5.9.x.** This page is the design and migration guide for what will be available when v6.0.0 GA ships. `reports/1.0` remains selectable via `--report-json-contract=1.0` during the v6.0.x line; it is removed in v6.1.0. See ADR-013 for the breaking-change rationale.

## TL;DR

- `reports/2.0` is a **new JSON report contract** that replaces the seven-state vocabulary of `reports/1.0` with a tighter five-state vocabulary aligned with Scorecard v6.
- Five states: **`PASS` / `FAIL` / `UNKNOWN` / `NOT_APPLICABLE` / `ATTESTED`**.
- `UNKNOWN` gains a sub-field `reason` so the granularity of the old seven states is preserved where it matters (`manual-review-required`, `not-observable-in-clone`, etc.).
- **Default contract in v6.0.0**: `reports/2.0`. Adopters who need byte-stability with v5.9.x output explicitly opt in via `--report-json-contract=1.0`.
- A **deprecation warning** prints on stderr when `--report-json-contract=1.0` is used.
- A **migration script** (`scripts/migrate-1.0-to-2.0.py`) converts existing `reports/1.0` JSON to `reports/2.0` for adopters with long-lived dashboards.

## Why a new contract

`reports/1.0` accumulated seven possible per-control statuses over the v5.x line: `pass`, `fail`, `degraded`, `manual-review-required`, `not-applicable`, `skipped`, `error`. Adopters writing dashboards repeatedly conflated `degraded` with `fail`, and `manual-review-required` with `not-applicable`. Scorecard v6 standardized on a tighter vocabulary — five states — that closed similar conflations upstream. Aligning is cheaper to do in a major than to keep documenting workarounds.

## The five states

| State | Meaning |
|---|---|
| `PASS` | The control's evidence supports a positive verdict at the declared assurance level (deterministic / signal / evidence-backed). |
| `FAIL` | The control's evidence supports a negative verdict at the declared assurance level. |
| `UNKNOWN` | The control could not produce a verdict from the available evidence. The required sub-field `reason` explains why. |
| `NOT_APPLICABLE` | The control does not apply to this target (e.g. GitHub-specific control evaluated against an Azure-only target). |
| `ATTESTED` | The control's verdict is anchored on an externally signed attestation (Sigstore bundle, GitHub artifact attestation, in-toto envelope). Stronger than `PASS evidence-backed`. |

## Mapping from `reports/1.0` to `reports/2.0`

| `reports/1.0` status | `reports/2.0` status | Notes |
|---|---|---|
| `pass` | `PASS` | Direct. |
| `fail` | `FAIL` | Direct. |
| `degraded` | `FAIL` with `degraded: true` in the per-control metadata | Adopters who treated `degraded` as a soft signal should now read the `degraded` flag explicitly. |
| `manual-review-required` | `UNKNOWN` with `reason: "manual-review-required"` | The `reason` sub-field preserves the distinction. |
| `not-applicable` | `NOT_APPLICABLE` | Direct. |
| `skipped` | `UNKNOWN` with `reason: "skipped-by-flag"` | Promoted into `UNKNOWN` with reason; consumers that branched on `skipped` should branch on `reason`. |
| `error` | `UNKNOWN` with `reason: "evaluator-error"` | Errors are not failures of the target; they are gaps in the kit's ability to evaluate. |
| (new) | `ATTESTED` | New state. Reserved for controls anchored on a verified attestation. Only `PROV-VERIFY-061` returns `ATTESTED` in v6.0.0. |

## Selecting a contract

```text
# Default in v6.0.0: reports/2.0
oss-policy-kit evaluate --target . --profile github-level-1

# Opt out: reports/1.0 (with deprecation warning on stderr)
oss-policy-kit evaluate --target . --profile github-level-1 --report-json-contract=1.0

# Legacy contracts also remain selectable:
oss-policy-kit evaluate --target . --profile github-level-1 --report-json-contract=0.3
oss-policy-kit evaluate --target . --profile github-level-1 --report-json-contract=0.2
```

## Deprecation timeline

| Version | `reports/1.0` status |
|---|---|
| v6.0.0 GA | Selectable via flag, deprecation warning on stderr. |
| v6.0.x patches | Same as v6.0.0 GA. |
| v6.1.0 | **Removed.** `--report-json-contract=1.0` becomes a usage error. |

`reports/0.3` and `0.2` continue to be selectable per existing precedent; they are legacy contracts kept for older dashboard compatibility and have separate removal cycles.

## Migration script

```text
$ python scripts/migrate-1.0-to-2.0.py \
    --input out/old/evaluation-report.json \
    --output out/new/evaluation-report.json
```

The script:

- Reads `reports/1.0` JSON.
- Applies the mapping table above.
- Writes `reports/2.0` JSON.
- Exits 0 on success, 1 on input parse error, 2 on usage error.

It is intentionally **lossless** — every distinction in `reports/1.0` survives into `reports/2.0` via the appropriate `reason` sub-field or per-control metadata flag. Round-trip tests in the kit ensure byte-stability for the hardened example.

## Dashboard adopter checklist

For each consumer of `evaluation-report.json`:

1. **Decide migration cadence**. Convert all consumers to `reports/2.0` during the v6.0.x line (before v6.1.0 removes `1.0`).
2. **Update the contract identifier check**. `reports/2.0` advertises `"contract_version": "reports/2.0"` at the top.
3. **Re-map status switches**. Use the mapping table above. The most common gotcha: `degraded` is now `FAIL` with `degraded: true`; consumers that treated `degraded` as PASS-ish must switch to the explicit flag.
4. **Handle `UNKNOWN.reason`** for any logic that previously branched on `manual-review-required`, `skipped`, or `error`. All three converge under `UNKNOWN` with distinct `reason` values.
5. **Optional**: enable `ATTESTED` highlighting. The new state is opt-in; consumers that ignore it still see PASS-shaped behavior because the underlying control is also `PASS`-grade.

## Why ATTESTED is its own state

`PASS evidence-backed` means "the kit consumed a structured evidence file and projected a positive verdict." `ATTESTED` is stronger: "the kit consumed a structured evidence file **and** the evidence is anchored on a verified attestation that survives independent verification by `gh attestation verify` or `cosign verify-bundle`." Adopters that need the strongest gate posture should look for `ATTESTED` specifically; adopters running advisory gates can treat `ATTESTED` and `PASS` identically without losing safety.

## References

- ADR-013 — design rationale, breaking-change justification, deprecation timeline
- [Scorecard v6 result vocabulary](https://github.com/ossf/scorecard) (the alignment source for the five states)
- Existing `reports/1.0` schema: `src/oss_policy_kit/data/schema/evaluation-report-v1.schema.json`
- [`v6.0.0-migration-guide.md`](v6.0.0-migration-guide.md) — the migration guide that wraps this contract change plus M-003 (ADR-008)
