---
type: integration
title: Collectors and scanner evidence
description: "How opt-in platform collectors and scanner adapters supply evidence to an assessment."
tags: [collectors, scanners, integrations, evidence]
sources:
  - id: openwiki-source-cd0f3c35546914b0f2774b27
    resource: repo://docs/evidence-pack.md
  - id: openwiki-source-8e30d3a7ef2e60edd5ce90bd
    resource: repo://src/oss_policy_kit/cli/evidence.py
  - id: openwiki-source-6e6709744bb74ba2ca55200e
    resource: repo://src/oss_policy_kit/cli/scan_sast.py
  - id: openwiki-source-25468338b5c07a13ddf17780
    resource: repo://src/oss_policy_kit/infrastructure/collectors/base.py
  - id: openwiki-source-bd4b20b9f2f9ab04a93c7eb0
    resource: repo://src/oss_policy_kit/infrastructure/collectors/github_collector.py
generated: { by: "codex", at: "2026-10-14T16:07:56.899Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-15T00:15:09.719Z
---

# Collectors and scanner evidence

Evaluation consumes observations already available in the target. Platform collection and scanner execution are explicit command surfaces that produce evidence for a later assessment. Their outputs need scope and availability information alongside findings or configuration.

## Platform collection

`collect-evidence` supports GitHub, GitLab, Azure DevOps and AWS. Each platform has its own credentials, repository or project identifiers, optional dependencies and endpoint limitations. The collector interface returns `CollectionResult` records with an evidence key, structured data, source URL and collection time.

GitHub collection reads configuration through authenticated HTTP requests. Optional endpoints can be unavailable: its helper distinguishes a permission error from a conservative fallback and logs skipped information. An empty fallback must be interpreted with those warnings rather than presented as complete coverage. Organization-level MFA and artifact-specific SBOM/provenance evidence have limits documented in the [evidence pack](../../docs/evidence-pack.md).

The collection command writes evidence JSON under the target's `.oss-policy-kit/evidence/`. A subsequent evaluator can consume those files. Collection alone does not show that the appropriate control was evaluated, that its evidence remains fresh, or that a release is accepted.

The `--dry-run` branch previews credential variable names and whether they are set, expected files and source hints. It does not make authenticated API calls. It is a preview, not collection evidence.

## Scaffolding and scanner adapters

`scaffold-evidence` creates schema-aligned templates for manual completion. A template or placeholder remains a different state from collected evidence. The generated shape is not proof of its values.

`scan-sast` currently wraps Semgrep, normalizes its output into an evidence file and leaves gate policy to evaluation. Missing Semgrep can still produce an evidence artifact marked `not_available` with exit zero; a scanner failure is distinct from a clean scan. The command also explains when Semgrep's engine never started, so an empty finding count is not mistaken for a completed scan.

The IaC command family covers Terraform, Kubernetes, CloudFormation, Pulumi and Bicep through their respective implementations. Parsing diagnostics and unread sources affect what those observations establish. Use the family guides under `docs/` for supported rules and inputs.

## Consumers and verification

[Evidence and assurance](../concepts/evidence-and-assurance.md) explains the provenance fields and trust ceilings. [Findings and supply-chain outputs](../workflows/findings-and-supply-chain.md) explains normalized findings and exports.

Collector tests cover permissions, network failures, unavailable endpoints and degraded responses. Scanner tests cover availability and error paths. Mocked API tests establish client behavior for those responses; live platform validation requires a separate authorized run against the intended scope.
