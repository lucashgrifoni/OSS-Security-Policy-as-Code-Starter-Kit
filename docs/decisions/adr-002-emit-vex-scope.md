# ADR-002 — `emit-vex` capability: scope and design

- **Status**: accepted; v0.1 implementation **shipped in v5.9.0** (`oss-policy-kit emit-vex` subcommand). Per-CVE waiver integration deferred to v5.9.x.
- **Date**: 2026-05-16
- **Context window**: planning Bloco E of the v5.9.0 line
- **Related**: ADR-001 (SCA scanner choice), `docs/cra-readiness.md`

## Context

The EU CRA's 2027-12-11 full-obligations deadline requires manufacturers to supply a machine-readable SBOM upon request and, by industry convention, a VEX (Vulnerability Exploitability eXchange) document that explains the manufacturer's analysis of CVEs affecting components.

The kit ingests scanner output (SARIF from OSV-Scanner, zizmor, poutine, Gitleaks) and consumes waivers (`waivers/waivers.yaml`) that document accepted risk per control. The combination of *which CVEs the scanner found* plus *which the manufacturer has analyzed and waived* is exactly the data shape CycloneDX VEX 1.6 was designed to express.

This ADR fixes the scope of `oss-policy-kit emit-vex` to avoid two anti-patterns:

1. **Overscope** — a full SBOM-generator that competes with Syft / Trivy in depth.
2. **Underscope** — a tool that emits VEX statements with no traceability back to the scanner finding or waiver entry that justified them.

## Decision

### What `emit-vex` will do (in scope)

- Read a list of OSV-Scanner SARIF findings from `.oss-policy-kit/evidence/sast/osv-scanner.sarif.json` (the file path mandated by `SAST-OSV-068`).
- Read `waivers/waivers.yaml` (the existing kit waiver format).
- For each OSV finding, emit a CycloneDX VEX 1.6 `vulnerabilities[]` entry with:
  - `id`: the OSV / CVE / GHSA identifier as recorded by OSV-Scanner.
  - `analysis.state`: `not_affected` when a matching waiver exists (waiver's `control_id` is `SAST-OSV-068` and the waiver's `applies_to` includes the file path), else `exploitable`.
  - `analysis.justification`: one of the CycloneDX-allowed values (`code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compensating_control`, `inline_mitigations_already_exist`) — chosen from the waiver text via a small mapping.
  - `analysis.detail`: free-text quote from the waiver's `justification`.
  - `analysis.response[].type`: where the waiver implies a response (e.g. `will_not_fix`, `update`, `workaround_available`).
- Output CycloneDX VEX 1.6 JSON to `--output <path>` or stdout when omitted.
- Exit 0 on success; exit 2 on parsing errors (consistent with `evaluate`).

### What `emit-vex` will not do (out of scope)

- **Generate an SBOM**. The kit does not maintain a dependency graph of the target. SBOM generation is delegated to Syft / Trivy / CycloneDX language-specific tools.
- **Verify the waiver's claim**. The kit emits the manufacturer's stated analysis; auditors verify it.
- **Auto-classify justification**. The waiver author must include enough context for the mapping; ambiguous waivers default to `analysis.detail` with no `analysis.justification` enum field.
- **Cover non-OSV findings**. zizmor / poutine / Gitleaks findings are *policy* patterns, not CVEs; emitting them as VEX would dilute the document's regulatory meaning. They remain inside the kit's evaluation report, not the VEX.

### Invocation surface

```
oss-policy-kit emit-vex \
  --osv-sarif .oss-policy-kit/evidence/sast/osv-scanner.sarif.json \
  --waivers waivers/waivers.yaml \
  --output vex.cyclonedx.json
```

Defaults:
- `--osv-sarif` defaults to the canonical path when omitted (so the common case is `oss-policy-kit emit-vex --output vex.json`).
- `--waivers` defaults to `waivers/waivers.yaml` when present.
- `--output` defaults to stdout.

## Implementation status (revised 2026-05-16 PM)

The "deferred" status was revised after a closer read of the CycloneDX 1.6 spec confirmed that the output schema is **externally defined and stable** — the kit only chooses which fields to populate, not the shape itself. The risk of "locking the wrong schema by shipping against synthetic fixtures" was overstated: as long as the kit emits canonical CycloneDX VEX 1.6 fields and validates against the spec, synthetic fixtures are sufficient.

**Shipped in v5.9.0 (v0.1 surface)**:

- `oss-policy-kit emit-vex --osv-sarif <path> --output <path>` subcommand.
- Reads OSV-Scanner SARIF, extracts unique vuln IDs (rule-level and result-level), emits CycloneDX VEX 1.6 with `analysis.state: in_triage` for every finding.
- Conservative: no auto-waiver application. Manufacturer fills in `state`, `justification`, `response` post-hoc.
- 11 tests cover SARIF parsing, document structure, CLI integration, error paths.

**Deferred to v5.9.x** (additive, non-breaking):

1. Extend `waivers/waivers.yaml` schema with `vulnerability_ids: [...]` for per-CVE waiver entries.
2. Auto-populate `state: not_affected` + `justification` when an OSV finding matches a waiver entry.
3. `--validate` flag to round-trip through CycloneDX schema before exit.
4. `--include-references` to embed advisory URLs from OSV records.

## Reversibility

This ADR is **fully reversible** until `emit-vex` ships. After it ships:

- The CLI flag surface (`--osv-sarif`, `--waivers`, `--output`) becomes part of the public contract; renames require deprecation.
- The output schema (CycloneDX VEX 1.6) is externally defined by OWASP CycloneDX; the kit only chooses which fields to populate. Field-set changes are non-breaking as long as we add, not remove.

## References

- [CycloneDX VEX capabilities](https://cyclonedx.org/capabilities/vex/)
- [CycloneDX 1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)
- [CISA Minimum Requirements for VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
- [OSV-Scanner v2 announcement](https://blog.google/security/announcing-osv-scanner-v2-vulnerability/)
- ADR-001 (this repo)
- `docs/cra-readiness.md` (this repo)
