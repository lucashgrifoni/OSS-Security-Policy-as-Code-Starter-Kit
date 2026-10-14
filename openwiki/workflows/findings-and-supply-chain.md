---
type: workflow
title: Findings and supply-chain outputs
description: "Follow normalized scanner findings, VEX decisions and exported assessment evidence."
tags: [findings, correlation, sarif, vex, supply-chain]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T16:07:56.899Z
sources:
  - id: openwiki-source-4b653013bd51d88bf6a1f561
    resource: repo://docs/findings-correlation.md
  - id: openwiki-source-2e031b76bce7734bdf09c172
    resource: repo://src/oss_policy_kit/application/finding_correlation.py
  - id: openwiki-source-ce2a80481f4a3beba79ce37f
    resource: repo://src/oss_policy_kit/cli/emit_vex.py
  - id: openwiki-source-a349bcab989871ffb764bbb6
    resource: repo://src/oss_policy_kit/cli/export_evidence.py
generated: { by: "codex", at: "2026-10-14T16:07:56.899Z" }
---

# Findings and supply-chain outputs

Control assessment, findings correlation and evidence export are separate contracts. A consumer can combine their artifacts for review, but a deduplicated finding or exported envelope does not change an assessment verdict.

## Correlating existing scanner evidence

`correlate-findings` reads the target's scanner evidence already on disk: kit JSON evidence and supported external SARIF drops. It normalizes finding structure while preserving source-reported severity, then correlates and ranks findings in a `findings/1.0` artifact.

Correlation uses the versioned `opk-fk/v1` key. It keeps different axes and distinct or missing locations apart instead of guessing that two observations represent one issue. Vulnerability identity includes the advisory and component, so the same advisory affecting different named dependencies remains distinct.

Ranking uses source-carried KEV, EPSS and normalized severity with stable tie-breaks. The correlation module does not fetch advisories, rescan code or invent enrichment values. Deterministic findings identity and ordering are separate from the wall-clock generation timestamp.

Finding-level waiver entries use `vulnerability_ids`. They retain the finding in the artifact with its exception metadata while changing the finding gate disposition. They do not become `control_id` waivers or alter `evaluate` outcomes. The [correlation guide](../../docs/findings-correlation.md) documents source coverage, enrichment and these boundaries.

## VEX emission

`emit-vex` reads OSV-Scanner SARIF and can apply matching vulnerability waiver decisions. It emits CycloneDX VEX or OpenVEX. Unmatched findings start in triage or investigation; a matched waiver can produce a `not_affected` assertion with its justification.

This command formats the supplied analysis. It does not generate an SBOM, establish exploitability by testing, verify the manufacturer's reasoning or mutate the input SARIF. Review the waiver's authority, applicability and expiry before distributing that statement. See [VEX emission](../../docs/vex-emission.md).

## Evidence projection and SARIF

`export-evidence` projects a current `reports/2.0` assessment into a supported external format, including SARIF, SPDX, OSCAL, in-toto, Gemara and the experimental Chainloop envelope. If its default report is absent, its implementation can assess the target before export.

An exported in-toto statement is unsigned; a local Chainloop envelope is not an accepted remote attestation. Structural validation of a projection does not show that a downstream service accepted it or that a signer bound it to a release artifact. The [evidence export guide](../../docs/evidence-export.md) defines format-specific limits.

Findings SARIF identifies an aggregator and retains source attribution. Evaluation SARIF represents control outcomes. Keep these different meanings when displaying them in a scanning interface.

## Review and verification

Start with correlation determinism and fence tests, findings schema tests and the VEX/export command tests. Compare source coverage and diagnostics as well as result counts: an empty artifact with missing inputs is not a completed clean scan.

For input production, see [collectors and scanner evidence](../integrations/collectors-and-scanners.md). For status and trust interpretation, see [evidence and assurance](../concepts/evidence-and-assurance.md).
