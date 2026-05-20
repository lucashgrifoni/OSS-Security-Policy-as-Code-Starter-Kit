# ADR-016 - AI agent source-side baseline

- **Status**: accepted
- **Date**: 2026-05-19
- **Related**: `ai-agent-baseline-1`, `AI-AGENT-001..010`, `appsec-llm-ssdf-218a-1`

## Context

AI-agent repositories now mix source code, model configuration, prompts, tool
descriptions, MCP server configuration, memory policy, identity, and runtime
authorization concerns. Existing kit AI coverage focuses on LLM/GenAI system
development and EU AI Act readiness. It does not yet give maintainers a
source-side checklist for projects that build agents or MCP servers.

The kit cannot enforce runtime agent decisions. It can, however, verify whether
the repository carries the source artifacts and evidence that make agent
security review possible before release.

## Decision

Ship `ai-agent-baseline-1` as an advisory profile with ten experimental
controls:

- `AI-AGENT-001` through `AI-AGENT-004` cover MCP authn, tool allowlists,
  reviewed prompt registries, and adversarial tests.
- `AI-AGENT-005`, `AI-AGENT-007`, and `AI-AGENT-009` are evidence-backed and
  consume `ai-agent-baseline/v1` JSON evidence under
  `.oss-policy-kit/evidence/ai-agent/`.
- `AI-AGENT-006`, `AI-AGENT-008`, and `AI-AGENT-010` cover rate limits,
  dedicated agent identity, and model-version pinning.

The profile is explicitly not a runtime policy engine and must be used with
`--fail-on degraded` if teams want missing evidence/manual-review rows to block.

## Consequences

- The bundled catalog gains a source-side AI-agent family without coupling to a
  specific SDK or provider.
- Three controls require evidence files, preserving the kit's distinction
  between clone-visible signal and stronger attested posture.
- The profile may produce false positives in unconventional frameworks; this is
  acceptable for v6.0.0 because the profile is advisory and experimental.

## Alternatives Considered

1. **Fold the controls into `appsec-llm-ssdf-218a-1`.** Rejected because that
   profile is about GenAI/LLM development posture, while agent repositories have
   distinct tool, memory, identity, and MCP concerns.
2. **Wait for a runtime enforcement integration.** Rejected because source-time
   gaps are still useful to surface before release and do not require a runtime
   dependency.
3. **Create provider-specific profiles.** Rejected because the first version
   should remain framework-agnostic and work across OpenAI, Anthropic, MCP,
   LangChain-style, and custom agent implementations.

## Validation

- `tests/application/test_ai_agent_profile.py`
- `examples/ai-agent-baseline-repo/`
- `src/oss_policy_kit/data/schema/evidence-ai-agent-baseline.schema.json`
