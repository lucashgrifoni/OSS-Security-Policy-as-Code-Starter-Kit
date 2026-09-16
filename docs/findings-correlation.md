# Normalized findings & cross-scanner correlation (`correlate-findings`)

> Introduced in **v10.0.0** (ADR-030). One deduplicated, ranked view of the scanner
> findings the kit already composes — normalized into a single vocabulary, correlated
> across tools, and written as a versioned `findings/1.0` artifact.

## What it does

```bash
oss-policy-kit correlate-findings --target . 
# writes .oss-policy-kit/findings.json (findings/1.0)
```

`correlate-findings` reads the scanner evidence **already on disk** under the target —
the six kit evidence JSONs (`sast-semgrep`, `iac-terraform`, `iac-cfn`, `iac-pulumi`,
`iac-bicep`, `k8s-baseline`) plus the four external SARIF drops
(`zizmor`, `poutine`, `osv-scanner`, `gitleaks` under `.oss-policy-kit/evidence/sast/`) — and:

1. **Normalizes** every finding into one schema (rule, message, location, severity)
   using the versioned `x-severity-map/v1`. Every source tool's *original* severity is
   preserved verbatim in `severity.by_source`; the kit never rewrites what a tool said.
2. **Correlates** findings that are the same issue via the deterministic **`opk-fk/v1`**
   key, scoped to one of four axes (`vuln` / `iac` / `k8s` / `code`). The strategy is
   **conservative under-merge**: cross-axis findings never merge, a missing location is
   never merged with a concrete one, and the same rule with a different message stays
   separate. The same CVE reported by two tools *does* collapse to one finding that
   records both sources. On the `vuln` axis the key is the advisory id **plus the
   package** (`component`), so one advisory against three dependencies stays three
   findings — one per thing you have to fix. When a source names no package the field
   is `null` and findings sharing the advisory still collapse: there is nothing to tell
   them apart by, and the kit does not infer a package from a lockfile path.
3. **Ranks** deterministically: CISA-KEV-listed first, then EPSS descending, then
   normalized severity, with stable tie-breaks. Re-runs on an unchanged clone are
   **deterministic in content** — the finding ids, ranks, and ordering are identical
   every time. The artifact is **byte-identical** across re-runs only when the
   evaluation clock is pinned (`SOURCE_DATE_EPOCH`, the reproducible-builds convention
   the kit honours); otherwise the sole difference is the `generated_at` field, which
   is a wall-clock stamp of when the artifact was produced.

## What it deliberately does NOT do (the fence)

- **No persistence, no state between runs, no runtime, no network.** One clone-only
  run in, one artifact out. This is the honest local-first slice of the
  "normalize → dedup → prioritize" pattern — not an ASPM platform.
- **It composes scanner verdicts; it never re-scans and never re-scores** another
  tool's semantics.
- **It never changes any `evaluate` result.** Control states, `summary_by_status`,
  `results_digest`, and exit codes are byte-identical with or without this feature
  (enforced by fence tests in the suite).

## Options

| Flag | Effect |
|---|---|
| `--output` | Artifact path (default `.oss-policy-kit/findings.json`). |
| `--format human\|json\|sarif` | stdout view: ranked summary, the full artifact, or an aggregator SARIF. |
| `--fail-on-severity <critical\|high\|medium\|low>` | Exit 1 if any non-waived finding is at/above the threshold. |
| `--fail-on-kev` | Exit 1 if any non-waived finding is CISA-KEV-listed. |
| `--waivers <file>` | Apply `vulnerability_ids:`-keyed waiver entries (see below). |
| `--enrichment-file <file>` | Offline EPSS/KEV snapshot; refines **ranking only** (see below). |
| `--include-absolute-path` | Opt out of the privacy-default basename `target_path`. |

Exit codes: `0` ok (including no evidence at all — sources are recorded honestly in
`sources_read`), `1` a `--fail-on-*` gate tripped, `2` usage/validation, `3` internal.

## Waivers (finding-level)

Waiver entries in `waivers.yaml` that carry `vulnerability_ids: [...]` — the same
entries `emit-vex` consumes — mark matching findings as waived: they stay fully
visible in the artifact (with owner and expiry) but stop tripping the `--fail-on-*`
gates. **They never affect `evaluate`**: control-gate waivers remain `control_id`-keyed
and the two kinds are parsed independently.

## Offline enrichment (inferred trust)

`--enrichment-file` takes a user-supplied JSON snapshot:

```json
{"as_of": "2026-07-01", "vulnerabilities": {"CVE-2026-1234": {"epss": 0.91, "kev": true}}}
```

Snapshot data affects **only** `priority.rank` / `priority.rationale` (tagged
`(snapshot)`), and only fills gaps — source-reported values always win. Finding fields,
severities, gates-by-severity, and every control state are untouched. The snapshot's
provenance (basename, as-of date, inferred-trust label) is recorded in `sources_read`.
The kit ships **no** bundled advisory data.

## The findings/1.0 artifact

Contract `oss-policy-kit/findings/1.0` — strict schema at
`reports/schema/findings-1.0.schema.json` (packaged copy:
`src/oss_policy_kit/data/schema/findings/1.0.json`). Adding any field means a
`findings/1.1`. Key semantics:

- `id` — `opk-fk/v1:<16 hex>`, the sha256 of the canonical correlation key, computed before
  the artifact is written.
- **`correlation.key` is redacted on the same rule as `location.file`**, on the `code`, `k8s`
  and `iac` key shapes that carry a file. An absolute path loses its directories; a
  repository-relative one is left alone.

  This page used to say the opposite, and the reason it gave was that the key is what merges
  two findings, so redacting it would merge findings that are not the same finding. That
  conflated two objects. Correlation groups on the canonical key **in memory** and `id` is the
  sha256 of that same in-memory string, both settled before serialization; only the printed
  copy is redacted, so no finding merges differently and no `id` changes. Measured on two
  results whose absolute paths differ only in their directory: two findings and two ids either
  way, with the printed keys identical under redaction and distinct without it.

  What it does cost: under the privacy default, the sha256 of the key you can see no longer
  reproduces `id`. Pass `--include-absolute-path` to get the key verbatim when you need to
  make that check. And as with `location.file`, two different files can now print the same
  key — the `id` beside it is what tells them apart.
  (`tests/application/test_the_findings_artifact_drops_the_host_layout.py` holds all of this.)
- **`id` is UNRELATED to the per-control `finding_id` in reports/2.0** (that one is a
  `{control_id}@{profile}` synthetic). The two artifacts imply no linkage.
- `location.file` — one spelling per file, so an id does not depend on the machine that
  scanned: separators are folded to `/`, and a leading `./`, a doubled `//`, and `/./`
  segments are dropped. A `..` segment is **kept** (resolving it would be a claim about
  the filesystem), a value carrying a URI scheme is left exactly as written, and a
  leading `//` survives as a UNC host.
- `component` — the package the advisory is about, read verbatim from whichever of
  `properties.purl`, `properties.package` / `packageName`, or a SARIF
  `logicalLocations` entry of kind `package` the source provides, in that order. `null`
  when the source names none; never inferred from the file path. It participates in the
  `vuln` key, so a purl carrying a version keeps two versions of one package apart.
- `severity.normalized` ∈ `critical|high|medium|low|info|unknown`; the per-source
  originals ride along.
- `kev: null` means *no source exposed a KEV signal* — never fabricated as `false`.
- `reachability` is a schema slot no composed scanner populates today (`null`); it is
  documented as promissory, not a capability claim.
- `kev`/`epss` counts and values are **source-derived signals** — never compliance,
  certification, or coverage claims.
- `sources_read` records every source honestly (`ok`, `missing`, `unreadable`,
  `oversize`, or the scanner's own reported status). A missing source never fails the run.

## SARIF export

`--format sarif` emits a SARIF 2.1.0 view whose `tool.driver` **self-describes as an
aggregator/correlator — not a scanner** — and every result names its original tool(s)
and evidence path(s) in `result.properties`. If a source tool already uploads its own
SARIF to code scanning, uploading this view too will double-report those issues.

## evaluate embed (opt-in)

`evaluate --with-findings-summary` adds an additive `extensions.findings_summary`
block to `evaluation-report.json` (totals, by-severity, KEV / high-EPSS counts, and a
`findings_digest` for pairing with a separately produced artifact). It is computed
in-process from the same clone during the same invocation — `evaluate` never reads a
`findings.json` — and changes no control state, summary, digest, or exit code.
