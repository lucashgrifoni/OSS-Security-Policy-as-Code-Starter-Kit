# ADR-024 - OWASP Top 10 for Agentic Applications (ASI01-10)

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-28
- **Related**: ADR-023 (MCP), ADR-016 (`ai-agent-baseline-1`)

## Context

OWASP published the Top 10 for Agentic Applications (2026, ASI01-10) covering
goal hijacking, tool misuse, memory poisoning, insecure inter-agent
communication, human-agent trust, and more. Agentic AI is now widely cited as a
top attack vector. Teams shipping agents asked for a clone-visible mapping.

## Decision

Ship five signal-grade `AGENT-ASI-*` controls and an `appsec-agentic-asi-1`
profile, each a pattern match for an OWASP-named risk family (not a verdict):

- `AGENT-ASI-GOAL-001` (ASI01) — version-controlled goal/system prompt.
- `AGENT-ASI-TOOL-002` (ASI02) — tool allowlist + least privilege.
- `AGENT-ASI-MEMORY-006` (ASI06) — memory purge / poisoning policy.
- `AGENT-ASI-INTER-007` (ASI07) — inter-agent mutual authentication.
- `AGENT-ASI-CONFIRM-009` (ASI09) — human checkpoint for destructive ops.

They return NOT_APPLICABLE when no agentic framework is detected. The profile
also bundles `MCP-TOOL-HASH-001`, `MCP-CONFIRM-001`, `LLM-218A-PO-001`, and
`AI-AGENT-002`. Advisory; `--fail-on degraded`.

## Alternatives considered

1. **Cover all ten ASI risks.** Rejected — five have clone-visible signals; the
   rest (e.g. cascading failures) need runtime telemetry the kit cannot observe.
2. **Treat signals as verdicts.** Rejected — each control is explicitly a
   "pattern match for the OWASP-named risk family", documented as such.

## Consequences

- Agent authors get a clone-visible OWASP Agentic hygiene baseline.
- Coverage is partial by design; documented honestly as advisory signals.

## References

- OWASP Top 10 for Agentic Applications (2026)
- v6.0.0 Cycle 2 plan, PR-28; ADR-023
