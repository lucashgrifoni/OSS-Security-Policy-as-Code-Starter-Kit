# AI Agent Baseline Fixture

This fixture models a small source-side AI agent repository.

## AI Security Considerations

The agent uses a restricted tool allowlist, dedicated agent identity, output
sanitization, tool-call audit logging, memory exclusions, and adversarial
prompt-injection tests. It is a fixture for `ai-agent-baseline-1`, not a
production agent.

## Intended Purpose

The agent summarizes release-readiness evidence for maintainers. It must not
execute destructive operations or store secrets in long-term memory.
