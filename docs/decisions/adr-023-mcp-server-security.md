# ADR-023 - MCP server security profile

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-20
- **Context window**: v6.0.0 Cycle 2, PR-27
- **Related**: ADR-016 (`ai-agent-baseline-1`), `docs/mcp-server-security.md`

## Context

The Model Context Protocol is the backbone of 2026 AI-agent tool use. Tool
poisoning (instructions hidden in a tool `description`) and indirect prompt
injection are the dominant MCP attack classes; benchmarks report high attack
success rates. Maintainers building MCP servers asked for a clone-visible
hygiene baseline.

## Decision

Ship five signal-grade `MCP-*` controls and an `appsec-mcp-server-1` profile:

- `MCP-TOOL-HASH-001` — tool descriptions hash-pinned
  (`mcp-tool-descriptions.json` with sha256), the primary tool-poisoning defense.
- `MCP-CONFIRM-001` — destructive operations require confirmation.
- `MCP-EGRESS-001` — egress allowlist documented.
- `MCP-INJECTION-TEST-001` — prompt-injection / tool-poisoning tests present.
- `MCP-SCOPE-001` — per-tool least-privilege scope documented.

All return NOT_APPLICABLE when no MCP server is detected (`mcp.json` or an MCP
dependency). Advisory; `--fail-on degraded`.

## Alternatives considered

1. **Evidence-backed verdicts.** Rejected for v6.0.0 — the MCP spec is still
   evolving; pattern-match signals plus a versioned hash evidence file are the
   pragmatic first step. Hardening is future work.
2. **Block when MCP detected but signals absent.** Rejected — manual review is
   the honest outcome for heuristic checks.

## Consequences

- MCP authors get a tool-poisoning / injection / scope / egress checklist.
- Heuristics can miss bespoke implementations; mitigated by advisory posture.

## References

- OWASP MCP Tool Poisoning; Microsoft MCP indirect-injection guidance
- v6.0.0 Cycle 2 plan, PR-27; `docs/mcp-server-security.md`
