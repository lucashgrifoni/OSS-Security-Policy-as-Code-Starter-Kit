# Reports contract `reports/2.0`

> **The only report contract since v9.0.0 (BREAKING).** `reports/2.0` shipped opt-in in v6.0.0, became the **default** in v7.0.0 (ADR-027), and became the **only** contract in v9.0.0 (ADR-043). The legacy `0.1`/`0.2`/`0.3`/`1.0` contracts were removed; `--report-json-contract` now accepts only `2.0`, and any other value exits 2. The offline converter script was removed in v10.0.0; for stored `1.0` reports run it from the v9.x tags (`git show v9.0.3:scripts/migrate-1.0-to-2.0.py`). See ADR-013 (contract design), ADR-027 (default-flip rationale), and ADR-043 (legacy-contract removal).

## TL;DR

- `reports/2.0` is a **new JSON report contract** that replaces the seven-state vocabulary of `reports/1.0` with a tighter five-state vocabulary aligned with Scorecard v6.
- Six states: **`PASS` / `FAIL` / `UNKNOWN` / `NOT_APPLICABLE` / `ATTESTED` / `SELF_ATTESTED`** (`SELF_ATTESTED` was emitted since the ADR-033 wiring but only formally added to the published schema in v9.0.3).
- `UNKNOWN` gains a sub-field `reason` so the granularity of the old seven states is preserved where it matters (`manual-review-required`, `not-observable-in-clone`, etc.).
- **The only contract since v9.0.0 (ADR-043)**: `reports/2.0`. The legacy `0.1`/`0.2`/`0.3`/`1.0` were removed; `--report-json-contract` accepts only `2.0` and any other value exits 2.
- A migration script for stored `reports/1.0` JSON shipped through the v9.x line; since v10.0.0 retrieve it from the tags (`git show v9.0.3:scripts/migrate-1.0-to-2.0.py`).

## Why a new contract

`reports/1.0` accumulated seven possible per-control statuses over the v5.x line: `pass`, `fail`, `degraded`, `manual-review-required`, `not-applicable`, `skipped`, `error`. Adopters writing dashboards repeatedly conflated `degraded` with `fail`, and `manual-review-required` with `not-applicable`. Scorecard v6 standardized on a tighter vocabulary — five states — that closed similar conflations upstream. Aligning is cheaper to do in a major than to keep documenting workarounds.

## The six states

| State | Meaning |
|---|---|
| `PASS` | The control's evidence supports a positive verdict at the declared assurance level (deterministic / signal / evidence-backed). |
| `FAIL` | The control's evidence supports a negative verdict at the declared assurance level. |
| `UNKNOWN` | The control could not produce a verdict from the available evidence. The required sub-field `reason` explains why (`waived` findings also surface here, with `reason: "waived"` and the waiver block attached). |
| `NOT_APPLICABLE` | The control does not apply to this target (e.g. GitHub-specific control evaluated against an Azure-only target). |
| `ATTESTED` | The control's verdict is anchored on an externally signed attestation (Sigstore bundle, GitHub artifact attestation, in-toto envelope). Stronger than `PASS evidence-backed`. |
| `SELF_ATTESTED` | The control's verdict rests on the project's own self-reported evidence (e.g. a SECURITY-INSIGHTS.yml consumed via `--use-insights-evidence`, ADR-033, or a self-attested azure/aws evidence file). Weaker than `PASS evidence-backed` — the kit records the claim, it does not verify it. Added to the published schema in v9.0.3 (the state was emitted earlier; the schema lagged). |

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
| (new) | `ATTESTED` | State for controls anchored on a verified attestation. Emitted by `PROV-VERIFY-061` and `GH-IMMUTREL-070` when a fully verified record (transparency-log inclusion + fresh `verified_at`) is present (ADR-028). `--enable-attested` defaults to **on** since v8.0.0 (ADR-041); pass `--no-enable-attested` and those controls stay `PASS`. Fail-closed: any verification gap keeps the prior `FAIL`/`UNKNOWN`, never `ATTESTED`. |
| `self-attested` | `SELF_ATTESTED` | Self-reported evidence (ADR-033 insights wiring, self-attested azure/aws evidence). Recorded as a claim, never verified by the kit. |
| `waived` | `UNKNOWN` with `reason: "waived"` | The waiver block on the control carries owner/justification/expiry; waived findings stay visible but stop tripping `--fail-on`. |
| `not-evaluated` | `UNKNOWN` with `reason: "not-evaluated"` | The control needs an input that was not supplied, so no verdict was attempted. `OSS-SCORECARD-001` without a Scorecard JSON is the common case. Supplying the input is what changes the outcome — this is not a judgement about the target. |
| `not-observable` | `UNKNOWN` with `reason: "not-observable-in-clone"` | The fact sits structurally outside a repository clone. No input you can pass to the kit resolves it; it needs live platform evidence or manual review. |

### The `reason` values

`UNKNOWN` always carries a `reason`. The complete set is `manual-review-required`,
`skipped-by-flag`, `evaluator-error`, `waived`, `not-evaluated`, `not-observable-in-clone`, and
`unmapped-source-status`.

The last one is a defensive fallback for an internal status the mapping does not recognise, and
**you should never see it**. It means the kit produced a status its own contract does not define —
if it appears in a report, that is a defect in the kit, not a statement about your repository.
Please open an issue with the control id.

## Selecting a contract

```text
# Default since v7.0.0: reports/2.0
oss-policy-kit evaluate --target . --profile github-level-1

# Explicit reports/2.0 (same as the default)
oss-policy-kit evaluate --target . --profile github-level-1 --report-json-contract=2.0

# Legacy contracts were REMOVED in v9.0.0 (ADR-043); selecting one exits 2:
oss-policy-kit evaluate --target . --profile github-level-1 --report-json-contract=1.0
#   Error: Report JSON contract '1.0' was removed in v9.0.0 (ADR-043); 'reports/2.0' is the only contract.  (exit 2)
```

## Deprecation timeline

| Version | `reports/1.0` status |
|---|---|
| v6.0.0 GA | `reports/1.0` is the **default**; `reports/2.0` is opt-in via `--report-json-contract=2.0`. |
| v6.0.x – v6.7.0 | Unchanged — `reports/1.0` **remained the default** through the v6.x line. The earlier plan to remove `1.0` in v6.1.0 was **not** carried out; no removal shipped. |
| v7.0.0 (BREAKING) | `reports/2.0` becomes the **default** (ADR-027). `reports/1.0` stays selectable via `--report-json-contract=1.0` for one minor cycle, then is deprecated with a warning, then removed in a later major. SARIF/Markdown output and exit-code semantics are unaffected. |
| v9.0.0 (BREAKING) | `reports/1.0` (and `0.3`/`0.2`/`0.1`) **removed** (ADR-043). `reports/2.0` is the only contract; `--report-json-contract` accepts only `2.0` and any other value exits 2 (no silent fallback). |

`reports/0.3` and `0.2` were also removed in v9.0.0 (ADR-043); like `1.0`, selecting them now exits 2. They survive only as historical contract docs.

## Migration script (removed in v10.0.0)

The offline `migrate-1.0-to-2.0.py` converter shipped through the v9.x line and was
removed in v10.0.0 (the kit has been unable to emit `reports/1.0` since v9.0.0). For
previously stored `1.0` reports, retrieve it from the tags:

```text
$ git show v9.0.3:scripts/migrate-1.0-to-2.0.py > migrate-1.0-to-2.0.py
$ python migrate-1.0-to-2.0.py --input out/old/evaluation-report.json --output out/new/evaluation-report.json
```

It applies the mapping table above losslessly (every `reports/1.0` distinction
survives via the appropriate `reason` sub-field or per-control metadata flag).

## `extensions.findings_summary` (opt-in, v10.0.0)

`evaluate --with-findings-summary` adds an additive block under the reserved
`extensions` key with correlated scanner-finding counts. It is computed
**in-process from the same clone** during the same `evaluate` invocation — it
never reads a pre-existing `findings.json` — and changes no control state,
`summary_by_status`, `results_digest`, or exit code. It is purely a reporting
convenience.

The block carries these keys:

| Key | Meaning |
|---|---|
| `findings_total` | Count of correlated (deduplicated) findings. |
| `correlated_groups` | Number of merged correlation groups (findings that collapsed across sources). |
| `by_severity` | Object mapping each normalized severity (`critical`/`high`/`medium`/`low`/`info`/`unknown`) to its count. |
| `kev_count` | Count of findings with a source-reported CISA-KEV signal — a **source-derived** signal, never a compliance or coverage claim. |
| `high_epss_count` | Count of findings whose source-reported EPSS is at or above `0.5` — likewise source-derived, not a claim. |
| `artifact` | The artifact basename this summary corresponds to (`findings.json`). |
| `findings_digest` | The sha256 (16 hex) of the canonical findings array, so consumers can pair this summary with a separately produced `findings/1.0` artifact. |
| `sources_ok` / `sources_total` | A source-read tally: how many of the correlated scanner sources were read successfully (`ok`) out of the total attempted. Missing or unreadable sources are counted honestly here and never fail the embed. |

The `findings_digest` pairs the report with a separately produced `findings/1.0`
artifact; it implies **no linkage** to the per-control `finding_id` (an unrelated
`{control_id}@{profile}` synthetic). See
[findings-correlation.md](findings-correlation.md).

## Dashboard adopter checklist

For each consumer of `evaluation-report.json`:

1. **Migrate any remaining `reports/1.0` consumers.** Since v9.0.0 `reports/2.0` is the only contract — pinning `--report-json-contract=1.0` is no longer possible (it exits 2). Convert any previously stored `1.0` reports with the offline migration script (retrieved from the v9.x tags since v10.0.0; see above).
2. **Update the contract identifier check**. `reports/2.0` advertises `"contract_version": "reports/2.0"` at the top.
3. **Re-map status switches**. Use the mapping table above. The most common gotcha: `degraded` is now `FAIL` with `degraded: true`; consumers that treated `degraded` as PASS-ish must switch to the explicit flag.
4. **Handle `UNKNOWN.reason`** for any logic that previously branched on `manual-review-required`, `skipped`, or `error`. All three converge under `UNKNOWN` with distinct `reason` values.
5. **Expect `ATTESTED` on a stock run.** `--enable-attested` defaults to on since v8.0.0 (ADR-041), so `PROV-VERIFY-061` and `GH-IMMUTREL-070` reach `ATTESTED` without any flag once their verification record is complete and fresh (ADR-028). It scores as a pass, so consumers that ignore it still see pass-shaped gate behavior, but adopters that want the strongest posture can branch on `ATTESTED` to require a verified attestation.

## Why ATTESTED is its own state

`PASS evidence-backed` means "the kit consumed a structured evidence file and projected a positive verdict." `ATTESTED` is stronger: "the kit consumed a structured evidence file **and** the evidence is anchored on a verified attestation that survives independent verification by `gh attestation verify` or `cosign verify-bundle`." Adopters that need the strongest gate posture should look for `ATTESTED` specifically; adopters running advisory gates can treat `ATTESTED` and `PASS` identically without losing safety.

## References

- ADR-013 — design rationale, breaking-change justification, deprecation timeline
- [Scorecard v6 result vocabulary](https://github.com/ossf/scorecard) (the alignment source for the five states)
- Legacy (removed) pre-2.0 schema files no longer ship in the wheel since v10.0.0; they remain in the v9.x git tags.
- [`v7.0.0-migration-guide.md`](v7.0.0-migration-guide.md) — the migration guide for the v7.0.0 default flip (ADR-027)
- [`v6.0.0-migration-guide.md`](v6.0.0-migration-guide.md) — earlier guide that documented this contract's introduction (ADR-013) plus M-003 (ADR-008)
