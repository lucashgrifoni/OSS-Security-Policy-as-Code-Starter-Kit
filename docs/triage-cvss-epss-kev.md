# Dependency triage: CVSS + EPSS + CISA KEV

> Severity alone over-counts. The kit's `SCA-KEV-001` and `SCA-EPSS-001` controls
> (ADR-021) triangulate CVSS with EPSS and the CISA KEV catalog using signals the
> OSV-Scanner SARIF already carries.

## Signals

- **CVSS** — intrinsic severity (0-10). Necessary but not sufficient.
- **EPSS** — Exploit Prediction Scoring System: probability (0-1) a CVE is
  exploited in the next 30 days.
- **CISA KEV** — Known Exploited Vulnerabilities catalog: confirmed *active*
  exploitation.

## Decision matrix

| KEV | EPSS | CVSS | Action |
|---|---|---|---|
| yes | any | any | **Fix now** — `SCA-KEV-001` FAIL (overrides severity) |
| no | ≥ 0.5 | ≥ 7.0 | **Prioritise** — `SCA-EPSS-001` FAIL |
| no | ≥ 0.5 | < 7.0 | review (probabilistic, lower impact) |
| no | < 0.5 | any | standard backlog |

## Generating the evidence

The controls read `.oss-policy-kit/evidence/sast/osv-scanner.sarif.json` (the
same file used by `SAST-OSV-068`). Run OSV-Scanner v2+ with EPSS/KEV enrichment
so the SARIF carries `result.properties.epss_score` and `result.properties.kev`:

```bash
osv-scanner --format sarif --recursive . > osv-scanner.sarif.json
mkdir -p .oss-policy-kit/evidence/sast
cp osv-scanner.sarif.json .oss-policy-kit/evidence/sast/
```

When the SARIF is absent, both controls return manual review — the kit does not
fetch EPSS/KEV over the network during evaluation (local-first).

## Thresholds

`SCA-EPSS-001` defaults to EPSS ≥ 0.5 and CVSS ≥ 7.0. These are conservative
starting points; tighten them as your remediation capacity allows.
