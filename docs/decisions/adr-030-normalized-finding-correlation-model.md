# ADR-030 - Normalized finding model with cross-scanner correlation (v10.0.0)

- **Status**: accepted (targets v10.0.0, BREAKING) — ratified 2026-06-19; sequenced **after** v9.0.0 (ADR-029 + ADR-043). Implementation begins once v9.0.0 ships, so v10.0.0 carries exactly one major's worth of breaking surface (the finding-shape change).
- **Date**: 2026-05-25
- **Context window**: v10.x roadmap horizon — "AI/agentic depth & correlation maturity"
- **Related**: ADR-021 (EPSS/KEV prioritization), ADR-001 (SCA scanner choice), ADR-012 (export-evidence), the maintainer's local roadmap (not published)

## Context

The kit composes scanner evidence (zizmor, OSV-Scanner, Gitleaks, Scorecard, Semgrep)
via SARIF/JSON adapters. Today that composition is shallow: there is per-adapter
normalization (e.g. `scorecard_json` normalized entries) and path-level dedup, but **no
cross-scanner finding model** — the same issue reported by two tools is not correlated,
and prioritization (EPSS/KEV, ADR-021) is applied in spots rather than as a first-class
layer over a unified finding set.

The market signal (ASPM-as-control-plane: normalize → dedup → prioritize → govern) is
exactly this capability, and Gartner projects 80% adoption in regulated verticals by
2027. The kit can deliver the honest, local-first slice of it: one normalized finding
view per run. But this is also the highest scope-creep risk in the roadmap — it must
**not** drift into an ASPM platform (persistent database, runtime, stateful triage).

Introducing a normalized finding shape changes the findings section of the report JSON,
which is breaking for consumers that parse it — hence a major bump.

## Decision

In **v10.0.0**, introduce a **normalized finding model** scoped to a single clone-only
run:

1. **Normalize** findings from all composed scanners into one internal schema
   (id, source tool, rule, location, severity, component, links).
2. **Deduplicate / correlate** across scanners by a deterministic key
   (component + rule/CWE + location), so the same issue from two tools collapses to one
   correlated finding that records all reporting sources.
3. **Prioritize** as a first-class layer: EPSS/KEV (ADR-021) and reachability signals
   (when a scanner exposes them, e.g. OSV-Scanner) attach to the normalized finding and
   drive an ordered, reproducible ranking.
4. **Hard scope fence (anti-ASPM).** Everything happens within one run: **no persistent
   database, no state carried between runs, no runtime/agent, no hosted triage.** This
   fence is part of the decision, not just a note, and is restated as a README non-goal.

The breaking finding-shape change ships with a migration note and updated golden
fixtures; `cli-api-ui-contract-validator` gates the contract change.

## Alternatives considered

1. **Keep per-adapter findings, no correlation.** Rejected — duplicate findings across
   tools mislead gate decisions and waste reviewer time; prioritization stays scattered.
2. **Build a stateful triage store / ASPM platform.** Rejected — violates the
   clone-only, no-runtime, no-database architecture; that ground belongs to dedicated
   ASPM tools the kit composes *with*, not competes against.
3. **Correlate but don't change the report shape.** Rejected — correlation that is not
   visible in the output delivers little; the shape change is the deliverable.
4. **Defer to a v9.x minor.** Rejected — the finding-shape change is breaking for
   consumers parsing the findings section; semver requires a major.

## Consequences

- One normalized, deduplicated, prioritized finding view per run — the honest local-first
  slice of the ASPM "control plane" pattern.
- EPSS/KEV/reachability prioritization becomes a coherent layer instead of spot logic.
- The findings section of the report changes shape (breaking); documented with a
  migration note and updated fixtures.
- The anti-ASPM fence is explicit and testable, protecting the project from the
  roadmap's biggest scope-creep risk.
- Trade-off: correlation keys must be tuned to avoid over-merging distinct issues;
  starts conservative (under-merge over over-merge) and tightens with fixtures.

## Amendment (2026-07) — re-grounded surface for the post-ADR-043 contract

This ADR was drafted 2026-05-25 against the pre-ADR-043 report contract. Since v9.0.0,
`reports/2.0` is the only contract and it has **no findings section** — its only
"finding" vocabulary is the per-control synthetic `finding_id` (`{control_id}@{profile}`).
The phrase "changes the findings section of the report JSON" in the Decision is therefore
re-grounded as follows; this amendment is normative and supersedes the conflicting wording.

### Amended surface

1. **The normalized finding view ships as a NEW artifact**, not a report reshape: a
   stateless `correlate-findings` subcommand reads the scanner evidence already on disk
   (the six kit evidence JSONs plus the four external SARIF drops) and writes
   `.oss-policy-kit/findings.json` under a new self-versioned contract
   **`oss-policy-kit/findings/1.0`** (strict schema, deterministic `opk-fk/v1`
   fingerprints, conservative under-merge correlation, deterministic priority ranking).
   `reports/2.0` is **not** bumped; rejected alternative 3 is re-scored accordingly.
2. **The only report change is additive and strictly flag-gated**: `evaluate
   --with-findings-summary` computes an `extensions.findings_summary` block **in-process,
   during the same invocation, from the same clone-local inputs**. `evaluate` never reads
   a pre-existing `findings.json` and no freshness/staleness comparison exists (any
   cross-invocation artifact dependency would violate the anti-ASPM fence).
3. **Full shipped surface** (everything v10.0.0 delivers under this ADR): the
   `correlate-findings` command; the `findings/1.0` contract + packaged schema + public
   mirror; opt-in findings-surface gate flags (`--fail-on-severity`, `--fail-on-kev`);
   finding-keyed waiver linkage (shared `vulnerability_ids` waiver parser); an optional
   **user-supplied, offline** EPSS/KEV enrichment snapshot input; `--format sarif` export
   that self-describes as an aggregator/correlator with per-result source-tool
   attribution; and the flag-gated report embed above.
4. **v10.0.0 breaking list** (the `feat!` surface, unchanged by this feature work):
   removal of the deprecated `cra-eu-ready-2-1` profile alias (ADR-029), deletion of the
   legacy `evaluation-report-v1/v2/v3.schema.json` files from the wheel, and removal of
   `export-evidence`'s dead reports/1.0 fallback reads. The SELF_ATTESTED published-schema
   fix ships earlier as the v9.0.3 hotfix and is NOT part of v10's breaking surface.

### Precondition discharged — ADR-021 audit result (2026-07-01)

The "spot logic" characterization is **accurate as implemented**: exactly two
experimental controls (`SCA-KEV-001`, `SCA-EPSS-001`; profile `appsec-sast-sca-1` only)
independently re-parse the single user-dropped OSV-Scanner SARIF; thresholds 0.5 (EPSS)
and 7.0 (CVSS) are hardcoded with no config surface while `docs/triage-cvss-epss-kev.md`
implies tunability; output is lossy prose (counts + up to 3 CVE ids) and no EPSS/KEV
value reaches a structured field; there is no network fetch (that fence stands); and
**no reachability parsing exists anywhere in src/** — `SAST-OSV-068`'s
"reachability-aware" title was label-only and is retitled in the same docs pass.
ADR-021's status is flipped to accepted (implemented v6.0.0 Cycle 2) alongside this
amendment.

### Honesty and fence clauses (normative)

- Enrichment snapshot data affects **only** `priority.rank`/`priority.rationale` — never
  `severity.normalized` and never any control state; snapshot provenance is recorded in
  `sources_read` with an inferred-trust label and as-of date.
- **Bundled/static CVE↔GHSA alias data in the wheel is rejected** for any `opk-fk`
  version; alias tables, if ever supported, are user-supplied inputs.
- The two existing EPSS/KEV evaluators keep their hardcoded thresholds in v10.0.0 (no
  evaluator threshold configuration ships); the findings surface gets its own flags.
- `reachability` exists in `findings/1.0` as a nullable slot that **no source populates
  today**; it is documented as promissory until a composed scanner exposes the data.
- Control evaluators are **not** rewired: control states, `summary_by_status`,
  `results_digest`, and `evaluate` exit codes are byte-identical with the findings
  feature present or absent (enforced by fence tests in the v10 suite).
- `cli-api-ui-contract-validator` gates the `findings/1.0` contract and the additive
  `extensions.findings_summary` property (an additive key under `extensions`, not a
  contract reshape) at release time.

## References

- ASPM trend (Gartner) — <https://www.gartner.com/reviews/market/application-security-posture-management-aspm-tools>, <https://apiiro.com/blog/gartner-on-aspm-what-it-means-for-your-security-strategy/>
- ADR-021 (EPSS/KEV), ADR-001, ADR-012
- the maintainer's local roadmap (not published) (v10.x horizon); roadmap plan §6, §11.5–11.6
