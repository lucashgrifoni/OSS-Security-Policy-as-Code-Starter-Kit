---
type: concept
title: Evidence, assurance and report states
description: "Interpret control states, confidence and evidence provenance without overstating what a clone proves."
tags: [evidence, assurance, reports, provenance]
sources:
  - id: openwiki-source-248b9a62bf9d97f700ae7eec
    resource: repo://src/oss_policy_kit/application/engine.py
  - id: openwiki-source-b29a48704be47b339048cbd0
    resource: repo://src/oss_policy_kit/application/evidence_projection.py
  - id: openwiki-source-adc28e55a941dffa04498dd7
    resource: repo://src/oss_policy_kit/application/loader.py
  - id: openwiki-source-45c695eef6f8b6ac1270ad2a
    resource: repo://src/oss_policy_kit/domain/models.py
generated: { by: "codex", at: "2026-10-14T17:21:37.203Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T17:21:37.203Z
---

# Evidence, assurance and report states

A control result answers a scoped question using available inputs. Status, confidence, catalog assurance and evidence provenance are different fields. A positive file-based observation does not establish that a live platform setting is enforced.

## Internal states and the wire contract

The domain defines nine statuses. JSON on the current `reports/2.0` contract projects them into six states, retaining a reason for several unknown outcomes.

| Internal status | JSON state | Interpretation |
|---|---|---|
| `pass` | `PASS` | Positive observation within the evaluator's scope |
| `attested` | `ATTESTED` | Outcome anchored on a verification record the relevant evaluator checks |
| `fail` | `FAIL` | A required condition was not satisfied |
| `manual-review-required` | `UNKNOWN` | Available evidence could not settle the control |
| `self-attested` | `SELF_ATTESTED` | Declarative evidence retains its trust limitation |
| `not-evaluated` | `UNKNOWN` | No verdict was attempted |
| `waived` | `UNKNOWN` | An applicable exception changes disposition |
| `not-observable` | `UNKNOWN` | The condition is outside local observation |
| `not-applicable` | `NOT_APPLICABLE` | The condition does not apply |

Consumers should retain the `reason` discriminator for `UNKNOWN`. Otherwise missing input, a valid exception and an unobservable platform setting become indistinguishable. The engine and report writer maintain the projection; the [results guide](../../docs/results-guide.md) explains operational examples.

## Assurance and confidence

Catalog assurance is one of `deterministic`, `signal` or `evidence-backed`. It describes the kind of observation the control expects, rather than certifying the application. `ControlResult` also normalizes confidence and removes terminal-control and invisible characters from evaluator prose before writers consume it.

The evidence projection keeps separate source type, freshness, attestation, trust level and gate role. Heuristic signals and derived data cannot exceed `inferred`; static-clone and user-supplied input cannot exceed `declared`. Status-based rules can lower these levels to `inferred` or `unobserved`. When no status override applies, an unknown source type falls to `unobserved`.

For an `api_collected` source, the projection emits `verified` only when freshness is `fresh` and its attestation field is `signed` or `self_attested`. This is the projection's metadata rule, not independent cryptographic verification performed by that function. Preserve the collection method, freshness and attestation fields when communicating the result.

## Privacy and gate behavior

Evidence references preserve repository-relative paths. The shared projection redacts host-rooted filesystem references, including cross-platform Windows, POSIX and UNC forms; report writers reuse this classification. Optional disclosure settings in a writer are a separate decision.

An exception changes disposition, not factual certainty. A schema-valid supplied document is not sufficient by itself to demonstrate deployment or enforcement. Gate policy is described in [CLI and CI decisions](../workflows/cli-and-ci.md); do not infer that all `UNKNOWN` states block it.

## Focused checks

`test_reports_v2_contract.py` exercises status mapping and rejects unsupported contracts. `test_evidence_projection_trust.py` checks source-specific trust ceilings and fresh/attested requirements. The projection helper tests cover host-path redaction. These tests define targeted verification for changes to the evidence contract.
