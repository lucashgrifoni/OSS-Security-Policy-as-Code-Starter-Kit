# AppSec native profile (`appsec-sast-sca-1`)

> **Expanded in v5.9.0**: grows from 11 to 15 controls. Adds four SARIF adapters (`SAST-ZIZMOR-066`, `SAST-POUTINE-067`, `SAST-OSV-068`, `SAST-GITLEAKS-069`) that consume scanner output produced by zizmor, poutine, OSV-Scanner v2, and Gitleaks.

- **Posture:** AppSec native bundle, **hard-gate-capable** when paired with `scan-sast` and the four SARIF adapters have real evidence.
- **Audience:** AppSec teams who want a multi-platform native profile rather than a CI-platform-specific ladder.
- **Total controls:** 15. Six core governance/CI hygiene + `SAST-SEMGREP-064` (Semgrep evidence via the bundled `scan-sast` subcommand) + the four v5.9.0 SARIF adapters + `GOV-EVIDFRESH-054`, `GOV-DISC-065`, and platform-agnostic CRA basics.
- **Evidence-backed:** 40% (six controls require `.oss-policy-kit/evidence/*.json`).
- **Experimental controls:** 27% (the four SARIF adapters plus `SAST-OSV-068`).

## SARIF adapters in v5.9.0

Each adapter reads a SARIF 2.1.0 document dropped at a canonical path under `.oss-policy-kit/evidence/sast/`. None of them runs the scanner for you — you produce the SARIF in CI, the kit grades it.

| Control | Tool | Path | Severity policy |
|---|---|---|---|
| `SAST-ZIZMOR-066` | [zizmor](https://docs.zizmor.sh/) — GitHub Actions AST analysis | `.oss-policy-kit/evidence/sast/zizmor.sarif.json` | Fail on `error`-level results; `warning`/`note` are tolerated |
| `SAST-POUTINE-067` | [poutine](https://github.com/boostsecurityio/poutine) — GitHub Actions + GitLab CI pipeline analysis | `.oss-policy-kit/evidence/sast/poutine.sarif.json` | Same as zizmor |
| `SAST-OSV-068` | [OSV-Scanner v2](https://google.github.io/osv-scanner/) — reachability-aware SCA | `.oss-policy-kit/evidence/sast/osv-scanner.sarif.json` | Fail on `error`-level results |
| `SAST-GITLEAKS-069` | [Gitleaks](https://github.com/gitleaks/gitleaks) — secret leak detection | `.oss-policy-kit/evidence/sast/gitleaks.sarif.json` | **Zero-tolerance** — any finding (even `warning`-level) blocks |

If the SARIF file is missing, the corresponding control returns `manual-review-required` — the gap is surfaced honestly, the gate does not silently pass.

### Pair with `emit-vex`

The companion `emit-vex` subcommand reads the OSV-Scanner SARIF and produces a CycloneDX VEX 1.6 document. Every distinct vulnerability ID (CVE / GHSA / OSV / RUSTSEC) lands in `analysis.state: in_triage` by default; per-CVE waivers in `waivers/waivers.yaml` (carrying `vulnerability_ids: [...]`) graduate matching entries to `analysis.state: not_affected`.

```bash
osv-scanner --format sarif --recursive . > .oss-policy-kit/evidence/sast/osv-scanner.sarif.json
python -m oss_policy_kit emit-vex \
    --osv-sarif .oss-policy-kit/evidence/sast/osv-scanner.sarif.json \
    --waivers waivers/waivers.yaml \
    --validate \
    --output vex.cdx.json
```

`emit-vex` warns when `--waivers` lists `vulnerability_ids` that do NOT match any SARIF finding (likely typo or CVE↔GHSA alias mismatch).

## Quickstart (full v5.9.0 SARIF pipeline)

```bash
mkdir -p .oss-policy-kit/evidence/sast

# 1. Generate SARIF for each scanner you adopt
zizmor --format sarif .github/workflows > .oss-policy-kit/evidence/sast/zizmor.sarif.json
poutine analyze --format sarif > .oss-policy-kit/evidence/sast/poutine.sarif.json
osv-scanner --format sarif --recursive . > .oss-policy-kit/evidence/sast/osv-scanner.sarif.json
gitleaks detect --report-format sarif --report-path .oss-policy-kit/evidence/sast/gitleaks.sarif.json

# 2. Gate the release with all four controls active
python -m oss_policy_kit evaluate --target . --profile appsec-sast-sca-1 \
    --fail-on fail --output-dir oss-policy-reports

# 3. Emit a VEX document for the SCA findings
python -m oss_policy_kit emit-vex \
    --osv-sarif .oss-policy-kit/evidence/sast/osv-scanner.sarif.json \
    --waivers waivers/waivers.yaml --validate \
    -o oss-policy-reports/vex.cdx.json
```

## Caveats

- **The kit does not run the scanners.** It only grades their SARIF output. If your CI does not run zizmor / poutine / OSV-Scanner / Gitleaks, the adapter controls return `manual-review-required` rather than silently pass.
- **SARIF severity drives the gate, not the rule ID.** Adopters who want a per-rule allowlist should manage that in their scanner config (e.g. `.zizmor.yml`, `osv-scanner.toml`), not at the kit level.
- **Gitleaks is zero-tolerance.** Even `warning`-level findings block. This is deliberate — a secret leak warning is operationally identical to an error.
- **`SAST-OSV-068` does not reproduce the OSV-Scanner reachability decision.** It grades the SARIF severity as reported. Use OSV-Scanner v2+ (`--call-analysis`) if you want reachability to enter the gate decision.

## Why this profile (vs. a CI-platform-specific ladder)

`appsec-sast-sca-1` is the right profile when you want one stable AppSec posture across GitHub, GitLab, Azure DevOps, and AWS CodeBuild. It does not depend on which CI platform you use; it depends on the SARIF artifacts your CI publishes. Pair it with the platform-specific ladder (`github-level-3`, `gitlab-level-1`, etc.) if you also want CI-hygiene grading in the same evaluate run — they compose without conflict.
