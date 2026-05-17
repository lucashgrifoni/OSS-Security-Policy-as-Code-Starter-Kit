# `emit-vex` — CycloneDX VEX 1.6 emission from OSV-Scanner SARIF

The `emit-vex` subcommand reads OSV-Scanner SARIF output and emits a CycloneDX VEX 1.6 document. Findings without a matching waiver default to `state: in_triage` — the neutral CycloneDX state meaning "manufacturer is analyzing". Findings matched by a waiver carrying `vulnerability_ids: [...]` (v0.2) get `state: not_affected` plus the waiver's justification text.

Released surface (v5.9.0, **v0.2**):

- Read OSV-Scanner SARIF (`--osv-sarif`).
- Apply per-CVE waivers from `waivers/waivers.yaml` (`--waivers`).
- Validate output against CycloneDX VEX 1.6 required-field set (`--validate`).
- Embed advisory URLs from OSV-Scanner rule `helpUri` (`--include-references`).

---

## Why VEX, and why now

The EU Cyber Resilience Act's full obligations (2027-12-11) require manufacturers to supply machine-readable vulnerability information. CycloneDX VEX 1.6 is the de facto open exchange format for "did this CVE affect this product?". A manufacturer shipping a product with an OSV-Scanner finding needs to be able to say, on demand:

- *"CVE-X affects component Y. We have analyzed it. Our state is `not_affected` because `code_not_reachable`. See justification text."*

The kit's `SAST-OSV-068` control already ingests OSV-Scanner SARIF as evidence. `emit-vex` converts the same SARIF into a VEX document the operator can hand to legal / auditors / customers.

---

## What `emit-vex` does

1. Reads `.oss-policy-kit/evidence/sast/osv-scanner.sarif.json` (default path; configurable via `--osv-sarif`).
2. Extracts every distinct `ruleId` / rule `id` — OSV-Scanner emits one per vulnerability (alias-grouped). The collected set covers CVE / GHSA / OSV / RUSTSEC identifiers.
3. Optionally reads `waivers/waivers.yaml` (default; configurable via `--waivers`). Entries with a `vulnerability_ids: [...]` field auto-populate `state: not_affected` for matching findings. Expired / malformed entries are skipped with warnings on stderr. **Control-keyed waivers are ignored** — they steer the gate, not the VEX.
4. Optionally embeds advisory URLs (`--include-references`) from OSV-Scanner rule `helpUri` into `vulnerabilities[].advisories[].url`.
5. Optionally runs structural validation (`--validate`) against the CycloneDX VEX 1.6 required-field set. Errors exit 2.
6. Emits a CycloneDX VEX 1.6 JSON document with:
   - `bomFormat: CycloneDX`, `specVersion: 1.6`, `version: 1`.
   - `metadata.timestamp` (UTC ISO-8601) and `metadata.tools[]` recording the kit.
   - `vulnerabilities[]` — one entry per distinct ID with the chosen `analysis.state` and `analysis.detail`.
7. Writes to `--output <path>` when provided; otherwise to stdout.

Exit codes: `0` success, `2` user-input error (missing / malformed SARIF, unwritable output, validation failure), `3` unexpected internal error.

---

## What `emit-vex` does not do

- **It does not generate an SBOM.** Use Syft, Trivy SBOM, or your language toolchain's native SBOM emitter.
- **It does not verify the manufacturer's analysis.** The auditor / notified body does that.
- **It does not auto-fill `state: not_affected` or `analysis.justification`.** Those are manufacturer judgements; v0.1 emits `in_triage` so the manufacturer fills the analysis explicitly (the kit's waiver schema does not yet support per-CVE entries — see ADR-002 and `docs/profiles/deferred-followups.md`).
- **It does not cover non-OSV findings.** zizmor / poutine / Gitleaks findings are *policy* patterns, not CVEs; emitting them as VEX would dilute the document's regulatory meaning. They remain inside the kit's evaluation report, not the VEX.

---

## Invocation

```bash
# 1. Run OSV-Scanner against your repo, output SARIF to the canonical location
osv-scanner --format sarif --recursive . > .oss-policy-kit/evidence/sast/osv-scanner.sarif.json

# 2. (Optional) Evaluate with the kit — SAST-OSV-068 will surface the findings
python -m oss_policy_kit evaluate --target . --profile appsec-sast-sca-1

# 3. Emit VEX (v0.2 surface — applies per-CVE waivers, validates, embeds advisories)
python -m oss_policy_kit emit-vex \
  --waivers waivers/waivers.yaml \
  --validate \
  --include-references \
  --output vex.cyclonedx.json
```

### Per-CVE waiver shape (v0.2)

In `waivers/waivers.yaml`, alongside the existing control-keyed entries, add per-vulnerability waivers:

```yaml
version: 1
waivers:
  - vulnerability_ids:
      - CVE-2024-12345
      - GHSA-aaaa-bbbb-cccc
    justification: >
      Library X is bundled but the vulnerable function path is unreachable
      from our integration. Verified via static analysis; see ADR-099.
    vex_justification: code_not_reachable  # one of the CycloneDX VEX enum values
    owner: appsec@example.org
    status: approved
    expires_at: "2027-12-31"
```

The `vex_justification` field is optional. When supplied, it must be one of the CycloneDX VEX 1.6 enum values (`code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compensating_control`, `inline_mitigations_already_exist`); invalid values are dropped with a warning and the entry still applies (without an enum tag).

Output (truncated):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-16T20:49:59Z",
    "tools": [{"vendor": "oss-policy-kit", "name": "oss-policy-kit emit-vex", "version": "5.9.0"}]
  },
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "analysis": {
        "state": "in_triage",
        "detail": "Imported from .oss-policy-kit/evidence/sast/osv-scanner.sarif.json ..."
      }
    }
  ]
}
```

---

## Filling in the analysis

The manufacturer's analysis fields are filled post-hoc. Per the CycloneDX VEX 1.6 vocabulary:

| Field | Allowed values | Typical use |
|---|---|---|
| `analysis.state` | `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage`, `false_positive`, `not_affected` | Use `not_affected` once analysis confirms the vuln does not impact the product. |
| `analysis.justification` | `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compensating_control`, `inline_mitigations_already_exist` | Required when `state = not_affected`. |
| `analysis.detail` | Free text | Why the analysis reached that conclusion. |
| `analysis.response[].type` | `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available` | What the manufacturer commits to do. |

Edit the JSON directly, then validate against [CycloneDX 1.6 JSON Schema](https://cyclonedx.org/docs/1.6/json/) using `cyclonedx validate --input-file vex.cyclonedx.json`.

---

## Roadmap (post-v5.9.0)

Per [ADR-002](decisions/adr-002-emit-vex-scope.md), the v0.2 surface that ships in v5.9.0 covers waiver auto-population, structural validation, and advisory references. Remaining items tracked for later releases:

1. **Full CycloneDX 1.6 JSON Schema validation** — currently `--validate` is structural (required-field / enum check); bundling the canonical schema adds wire-level conformance. Optional dependency to keep the kit lean.
2. **`response.type` mapping** from waiver fields (`will_not_fix`, `update`, `workaround_available`) — today only `state` and `justification` are populated.
3. **Multi-source ingest** — accept `--zizmor-sarif`, `--poutine-sarif`, `--gitleaks-sarif` alongside `--osv-sarif`. Non-OSV findings would map to a *separate* output document because they are policy patterns, not CVEs (see ADR-002).

---

## Where this page sits

- `docs/cra-readiness.md` covers the EU CRA deadlines that motivate VEX emission.
- `docs/decisions/adr-001-sca-scanner-choice.md` records why OSV-Scanner v2 was chosen as the SCA primary.
- `docs/decisions/adr-002-emit-vex-scope.md` records the original scoping decision; this page reflects the v0.1 implementation that ships in v5.9.0.
- `docs/positioning.md` explains where the kit sits in the broader OSS security tooling landscape.
