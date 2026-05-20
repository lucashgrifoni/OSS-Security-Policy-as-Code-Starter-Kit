# AI agent baseline profile

`ai-agent-baseline-1` is an advisory profile for repositories that build AI
agents, tool-using LLM applications, or MCP servers. It is source-side and
build-time only: it checks files and evidence committed with the repository. It
does not enforce runtime policy, prove model safety, or replace red-team testing.

Use it with `--fail-on degraded` when you want manual-review rows to block a
promotion until the team has filled the relevant evidence. Do not present a pass
as a production safety guarantee.

## Controls

| Control | What it checks | Proof shape |
|---|---|---|
| `AI-AGENT-001` | MCP configuration has an authn signal and does not disable auth | signal |
| `AI-AGENT-002` | Agent tools are explicitly allowlisted | signal |
| `AI-AGENT-003` | System prompts live in a versioned registry covered by CODEOWNERS | signal |
| `AI-AGENT-004` | Prompt injection / adversarial tests exist | signal |
| `AI-AGENT-005` | Output sanitization is documented in evidence | evidence-backed |
| `AI-AGENT-006` | Rate limit, quota, or token-budget config exists | signal |
| `AI-AGENT-007` | Tool-call audit logging is documented in evidence | evidence-backed |
| `AI-AGENT-008` | Agent identity is separate from user credentials | signal |
| `AI-AGENT-009` | Sensitive context is excluded from long-term memory | evidence-backed |
| `AI-AGENT-010` | Model identifiers are pinned to dated/versioned releases | signal |

Evidence-backed controls read JSON files from:

```text
.oss-policy-kit/evidence/ai-agent/
  output-sanitization.json
  audit-log-config.json
  memory-policy.json
```

All three files use `schema_version: ai-agent-baseline/v1` and are validated by
`src/oss_policy_kit/data/schema/evidence-ai-agent-baseline.schema.json`.

## Design boundary

This profile is aligned with the source-detectable parts of current AI-agent
security guidance: OWASP's agentic application risks, the MCP security best
practices, and NIST AI 600-1's risk-management framing. It intentionally avoids
runtime claims. For example, the kit can detect that a repository has a tool
allowlist file, but it cannot prove the running agent enforces that allowlist
under every deployment path.

Primary references:

- OWASP Top 10 for Agentic Applications 2026: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- MCP Security Best Practices: <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>
- NIST AI 600-1 Generative AI Profile: <https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence>

## Example

The bundled fixture `examples/ai-agent-baseline-repo/` is intentionally small
and shows the expected shape:

- `mcp.json` with OAuth/audience-bound authn and named tools.
- `allowed_tools.yaml` without wildcard access.
- `prompts/` plus `CODEOWNERS`.
- `tests/test_prompt_injection.py`.
- AI-agent evidence JSON under `.oss-policy-kit/evidence/ai-agent/`.
- Source config with a dedicated agent identity, rate limits, and a pinned model.

Run:

```bash
python -m oss_policy_kit evaluate \
  --target examples/ai-agent-baseline-repo \
  --profile ai-agent-baseline-1 \
  --fail-on degraded
```
