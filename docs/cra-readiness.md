# EU Cyber Resilience Act — readiness with this kit

This page documents what the OSS Security Policy as Code Starter Kit can and cannot prove about EU Cyber Resilience Act (CRA) readiness. It is **not** a conformity assessment, **not** a substitute for a notified body's review, and **not** legal advice.

For the canonical regulatory text, see the [EU Commission's CRA page](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act). For the kit's framework mapping, see [`framework-alignment.md`](framework-alignment.md). For an overview of all bundled profiles, see [`profiles/overview.md`](profiles/overview.md).

---

## The two deadlines that matter

| Date | Obligation | Profile that maps |
|---|---|---|
| **2026-09-11** | Manufacturers of products with digital elements placed on the EU market must report **actively exploited vulnerabilities** to ENISA and designated national CSIRTs within **24 hours** of becoming aware. | `cra-eu-reporting-1` |
| **2027-12-11** | Full CRA obligations apply: SBOM in machine-readable format, vulnerability handling documentation, security-by-default, conformity assessment, CE-marking. | `cra-eu-ready-1`, `cra-eu-strict-1` |

Both deadlines apply to manufacturers placing **commercial products** on the EU market. Purely non-commercial, non-monetized OSS development is exempt; OSS incorporated into a commercial product is in scope through the manufacturer.

Non-compliance penalties: up to **€15M or 2.5% of global turnover**, whichever is higher.

---

## What the three CRA-aligned profiles cover

### `cra-eu-reporting-1` — 24h reporting readiness (2026-09-11)

Focused exclusively on the September 2026 deadline. Bundles 11 controls covering the **technical preconditions** a manufacturer needs to plausibly file a CRA report inside 24 hours:

| Capability | Controls | What it proves |
|---|---|---|
| Disclosure channel | `GOV-SEC-001`, `GOV-DISC-013`, `GOV-DISC-065` | A reporting channel exists, is documented, and carries an explicit acknowledgement SLA. `GOV-DISC-065` is evidence-backed via `.oss-policy-kit/evidence/disclosure-policy.json` (schema `disclosure-policy/v1`). |
| Detection capability | `SEC-DEPREV-011`, `DEP-UPDATE-001`, `SEC-SECRETS-050` | Dependency review, auto-update tooling, and secret scanning are present. |
| Audit trail | `AUDIT-STREAM-060`, `GOV-EVIDFRESH-054` | An audit log is being forwarded somewhere; evidence freshness is tracked. |
| Risk handling discipline | `GOV-WAIV-014` | A versioned waiver registry exists with owner + expiry. |
| Affected artifact identification | `REL-CHANGE-012`, `BUILD-SBOM-QUAL-003` | The changelog identifies the affected version; SBOM identifies the affected component. |

**Posture**: advisory. The profile **does not** prove the 24-hour clock is met — that is a process outside the kit's evidence surface.

### `cra-eu-ready-1` — broader CRA preparation (advisory)

Bundles 12 controls; a discovery surface for CRA preparation before September 2026. Less reporting-specific than `cra-eu-reporting-1`, more aligned with the documentation expectations of the full 2027 deadline.

### `cra-eu-strict-1` — full obligations alignment (2027-12-11)

Bundles 19 controls (12 from `cra-eu-ready-1` plus 7 stricter additions covering GitHub platform governance, org-wide MFA, action pinning, secret scanning posture). Still **advisory** — the kit does not certify conformity.

---

## What the kit **does not** prove

The kit's CRA-aligned profiles emit *technical alignment evidence*. They do **not** prove any of the following, all of which remain the manufacturer's responsibility:

- **The actual 24-hour reporting** — the kit cannot observe that ENISA or a national CSIRT was notified within the deadline.
- **Conformity assessment** — required by the CRA's Annex IV; performed by a notified body, not by tooling.
- **CE-marking and EU Declaration of Conformity** — administrative artifacts, outside the kit's surface.
- **Market surveillance compliance** — submitting SBOMs to authorities upon request is a process the kit does not simulate.
- **Severity-of-exploitation judgement** — deciding whether a vulnerability is "actively exploited" in the CRA sense is a human determination informed by detection telemetry.
- **Cross-product impact analysis** — when a CVE in a shared dependency affects multiple products, the impact mapping is operator-side.

For these, work with your legal team and your notified body. The kit narrows the technical surface; the rest remains with the manufacturer.

---

## How to use these profiles

The recommended `--fail-on` for every CRA-aligned profile is **`degraded`**. Using `--fail-on fail` defeats the design — the profile will surface `manual-review-required` on platform/SBOM/provenance controls when evidence files are not filled, and treating that as a blocker creates false outage signals on legitimate gaps.

```bash
# Reporting-readiness check (Sep 2026 deadline)
python -m oss_policy_kit evaluate \
  --target ./my-product \
  --profile cra-eu-reporting-1 \
  --fail-on degraded \
  --output-dir ./out/cra-reporting

# Full CRA preparation (Dec 2027 deadline)
python -m oss_policy_kit evaluate \
  --target ./my-product \
  --profile cra-eu-strict-1 \
  --fail-on degraded \
  --output-dir ./out/cra-strict
```

The `[advisory profile]` banner fires for all three CRA profiles to make the disposition visible at the top of every interactive run.

---

## What to do if the report shows gaps

A `degraded` or `manual-review-required` outcome on a CRA profile is the kit telling you the technical scaffolding has a hole. Typical responses:

| Symptom | Suggested action |
|---|---|
| `GOV-SEC-001` fails | Add a `SECURITY.md` documenting the disclosure channel. |
| `GOV-DISC-013` signal-only | Make the responsible disclosure language explicit (contact, response window, public disclosure timing). |
| `GOV-DISC-065` fails or manual-review | Document the acknowledgement / triage SLA either in `SECURITY.md` (keywords like "we will respond within 72 hours" are picked up as signal) or by attaching `.oss-policy-kit/evidence/disclosure-policy.json` per `evidence-disclosure-policy.schema.json`. The kit checks that an SLA is documented at all — it does not judge whether the SLA is fast enough. |
| `AUDIT-STREAM-060` missing evidence | Configure audit log streaming (CloudTrail / Azure DevOps audit streams / equivalent) and document the destination. |
| `GOV-EVIDFRESH-054` stale | Refresh `.oss-policy-kit/evidence/` artifacts before the next release. |
| `BUILD-SBOM-QUAL-003` fails | Generate a CycloneDX or SPDX SBOM at build time and attach it to the release artifact. |
| `PROV-VERIFY-061` fails (cra-eu-strict-1) | Sign release artifacts and verify with `cosign verify` / `gh attestation verify`; attach the verification block to evidence. |

None of the above produces CRA conformity on its own. They close the technical gaps the kit can observe; the regulatory determination remains with the manufacturer.

---

## Where this page sits

- `cra-eu-reporting-1` is the new bundled profile aimed at the **2026-09-11** deadline.
- `cra-eu-ready-1` and `cra-eu-strict-1` remain the broader CRA preparation profiles aimed at the **2027-12-11** deadline.
- All three are **advisory regulatory mappings**, not conformity assessments.
- For the per-framework requirement-to-control mapping, see [`framework-alignment.md`](framework-alignment.md) (EU Cyber Resilience Act section).
- For the positioning of this kit relative to other OSS security tooling, see [`positioning.md`](positioning.md).
