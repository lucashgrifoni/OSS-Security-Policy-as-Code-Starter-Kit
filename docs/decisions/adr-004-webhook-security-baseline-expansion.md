# ADR-004 — Webhook security baseline: expand from 1 advisory profile to a 6-control family

- **Status**: proposed (v6.0.0)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 2 (PR-5)
- **Related**: [`positioning.md`](../positioning.md) → *Roadmap (v6.0.0 — in development)*

## Context

v5.x ships a single webhook-receiver profile, `webhook-security-1`, that performs a small number of clone-visible signal checks (presence of an HMAC verifier import, no plaintext secret in repo, basic input validation patterns). Adopters running webhook receivers in production have flagged that the profile is too thin to anchor a release gate, especially when the receiver is part of a regulated workflow (CRA Article 11 reporting, EU AI Act post-market monitoring, internal incident webhooks).

The gap between "webhook receiver exists" and "webhook receiver is hardened" is a recurring AppSec failure pattern:

- HMAC validation present but timing-unsafe comparison (`==` instead of `hmac.compare_digest`).
- HMAC secret rotated but old keys still accepted indefinitely (no rotation cadence).
- Replay protection absent (no nonce / timestamp window check).
- Body size unbounded (DoS vector).
- Idempotency key check absent or naive (duplicate processing on retry).
- Secrets sourced from environment but logged in error paths.

None of these are exotic; they are the OWASP-API-Security-Top-10 #4 "Unrestricted Resource Consumption" and #8 "Security Misconfiguration" applied to webhooks. The kit can detect several of them from clone-visible signals.

## Decision

Introduce a **second** webhook profile, `webhook-security-2`, that bundles **six new `SEC-WEBHOOK-*` controls** plus the controls already in `webhook-security-1`. `webhook-security-1` is **kept** for compatibility (adopters who explicitly opt in to the lighter posture should not be forced to upgrade).

The six new controls (all `signal` grade unless noted):

| Control | Check |
|---|---|
| `SEC-WEBHOOK-HMAC-001` | HMAC verification function imported and called before any business logic. |
| `SEC-WEBHOOK-TIMING-002` | HMAC comparison uses a timing-safe primitive (`hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.timingSafeEqual`, or equivalent for the detected runtime). |
| `SEC-WEBHOOK-REPLAY-003` | Timestamp or nonce check present before HMAC verification (replay window enforcement). |
| `SEC-WEBHOOK-BODY-004` | Body-size or content-length cap configured at the framework / proxy level. |
| `SEC-WEBHOOK-IDEMP-005` | Idempotency key extraction and lookup present (any persistence backend acceptable). |
| `SEC-WEBHOOK-ROTATE-006` | Secret accessed via an environment / vault reference (not literal), and codebase contains at least one reference to multi-secret acceptance during a rotation window (signal heuristic only). |

`webhook-security-2` is recommended as `--fail-on degraded` initially (advisory) and may be promoted to `--fail-on fail` after at least one minor of adopter feedback.

## Alternatives considered

1. **Expand `webhook-security-1` in place.** Rejected: would silently change pass/fail outcomes for current adopters. The kit's compatibility contract treats profile control lists as part of the public surface.
2. **Single combined control.** Rejected: collapses six independent decisions into one verdict, hiding which dimension failed. The kit's value is per-control trust grading.
3. **Defer to a future release.** Rejected: webhook receivers are increasingly load-bearing for CRA reporting (`cra-eu-reporting-1`) and EU AI Act post-market monitoring (planned `cra-eu-ai-act-art11-1`); a stronger webhook baseline is a v6.0.0 dependency.

## Consequences

**Positive**

- Adopters running webhook receivers gain a defensible gate with six independent dimensions.
- `cra-eu-reporting-1` and (planned) `cra-eu-ai-act-art11-1` can reference `webhook-security-2` as a composable building block.
- Per-control trust grading preserved.

**Negative / cost**

- Six new controls increase the catalog surface by ~4 %, with corresponding test cost (hardened + vulnerable fixtures per control).
- Some signals (rotation-window heuristic) are coarse; risk of false positives until tuned with adopter data.

**Mitigations**

- Profile is advisory at GA. Promote to hard-gate only after adopter signal stabilizes.
- Each control documents its signal vs. evidence-backed posture explicitly; `SEC-WEBHOOK-HMAC-001` is the strongest deterministic check, the others are signal-grade and tunable.

## References

- v6.0.0 execution plan §4.1 PR-5
- v6.0.0 proposal §3 O-01
- OWASP API Security Top 10 (2023): API4, API8
- [`positioning.md`](../positioning.md) → *Roadmap (v6.0.0 — in development)*
