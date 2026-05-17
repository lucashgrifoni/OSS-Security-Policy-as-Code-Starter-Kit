# EU Cyber Resilience Act (CRA) profile family

Three EU CRA-aligned profiles ship in v5.9.0, each tied to a different obligation deadline. All three are **advisory** — the kit maps technical preconditions to CRA requirements but does **not** certify conformity. Conformity assessment is the responsibility of a competent authority or notified body.

| Profile | Obligation | Recommended `--fail-on` |
|---|---|---|
| [`cra-eu-reporting-1`](#profile-cra-eu-reporting-1) | 2026-09-11 — 24-hour reporting of actively exploited vulnerabilities | `degraded` |
| [`cra-eu-ready-1`](#profile-cra-eu-ready-1) | Broader CRA preparation (pre-2027-12-11) | `degraded` |
| [`cra-eu-strict-1`](#profile-cra-eu-strict-1) | 2027-12-11 — full obligations under CRA | `degraded` |

> **Description of `cra-eu-strict-1` was rewritten in v5.9.0** from "hard-gate-capable when evidence files are filled" to advisory. The profile is functionally unchanged (same 19 controls); only the label was corrected to match the kit's honest scope.

## Profile: `cra-eu-reporting-1`

> **New in v5.9.0.** Focused on the EU CRA's **2026-09-11** 24-hour reporting deadline for actively exploited vulnerabilities (Article 14 of Regulation (EU) 2024/2847).

- **Posture:** advisory, `--fail-on degraded` recommended.
- **Audience:** EU manufacturers preparing for the 24-hour reporting deadline.
- **Total controls:** 11. Cover disclosure channel + SLA, detection capability, audit trail, risk handling discipline, and affected-artifact identification.
- **Evidence-backed:** 18%.

### Headline control: `GOV-DISC-065`

`GOV-DISC-065` (Disclosure channel SLA documented) is the centerpiece. It reads `.oss-policy-kit/evidence/disclosure-policy.json` with schema `disclosure-policy/v1`. **All seven of these fields are required**:

- `schema_version` — literal string `"disclosure-policy/v1"`
- `attested_at` — ISO-8601 date (`YYYY-MM-DD`) of last review
- `attested_by` — username, security team, or attestation identifier
- `contact.method` and `contact.value` — e.g. `email` / `security@example.com`
- `acknowledgement_sla_hours` — committed time-to-acknowledge (integer)
- `triage_sla_hours` — committed time-to-triage (integer)
- `public_disclosure_policy.default_window_days` and `.negotiable`

See `examples/hardened-repo/.oss-policy-kit/evidence/disclosure-policy.json` for a copy-paste-ready shape.

**Signal fallback:** if the evidence file is missing, the control searches for SLA keywords in `SECURITY.md` (root, `.github/`, or `docs/`) and emits a `low` confidence pass when found.

### What this profile does NOT prove

- That the manufacturer **actually** acknowledges within the SLA (the kit reads the committed SLA, not the runtime data).
- That the 24-hour clock is met for any specific incident.
- That CE-marking or notified-body conformity has been obtained.
- That severity-of-exploitation has been correctly judged.

These are organizational and operational concerns outside the kit's static-analysis scope. The profile maps the **technical preconditions** that auditors typically ask for first.

### Quickstart

```bash
# 1. Bootstrap the evidence file
python -m oss_policy_kit scaffold-evidence --target . --platform github
# Then fill .oss-policy-kit/evidence/disclosure-policy.json with real SLAs.

# 2. Evaluate as an advisory check
python -m oss_policy_kit evaluate --target . --profile cra-eu-reporting-1 \
    --fail-on degraded --output-dir oss-policy-reports
```

## Profile: `cra-eu-ready-1`

Broader CRA-prep checklist (12 controls, 25% evidence-backed). Maps multi-platform release evidence (`branch-protection.json`, `audit-log-streaming.json`, `release-archival-policy.json`) to CRA Article 13–17 expectations. **Same advisory posture** as the other two.

## Profile: `cra-eu-strict-1`

Strictest of the three (19 controls, 37% evidence-backed). Covers the 2027-12-11 full-obligations window: design-time risk handling, SBOM, vulnerability disclosure, security update channels, audit-log streaming, and reporting. **Description corrected in v5.9.0** to advisory.

## What none of the three profiles certify

- **Conformity assessment** under CRA Annex VIII — that is a notified-body action.
- **CE-marking** — administrative procedure outside the scope of static analysis.
- **Severity classification** for the 24-hour reporting clock — judgment of "actively exploited" is the manufacturer's, not the kit's.
- **Documentation of the manufacturer** to regulators — separate workflow.

The kit's value here is to surface **the parts that adopters typically forget**: missing SLA evidence, missing disclosure channel, no audit-log streaming, no release archival policy, evidence files that have been stale for months. Use the kit's output as **input** to a CRA conformity workflow, not as a substitute.
