# MCP server security baseline

> **Advisory.** Clone-visible hygiene signals for Model Context Protocol (MCP)
> servers, responding to the 2026 tool-poisoning and indirect-prompt-injection
> threat landscape. Profile: `appsec-mcp-server-1`. See ADR-023.

## Threat model

- **Tool poisoning** — malicious instructions hidden in a tool's `description`
  field, executed by the model when it reads the tool list.
- **Indirect prompt injection** — untrusted content returned by a tool steers
  the agent.
- **Over-broad tool scope** — a tool can do more than its stated purpose.
- **Unrestricted egress** — a compromised tool exfiltrates data.

## Controls

| Control | Signal | Remediation |
|---|---|---|
| `MCP-TOOL-HASH-001` | `mcp-tool-descriptions.json` pins SHA-256 of each tool description | recompute and compare in CI |
| `MCP-CONFIRM-001` | destructive-op confirmation pattern present | require explicit confirmation for state-changing tools |
| `MCP-EGRESS-001` | egress allowlist documented | deny-by-default outbound |
| `MCP-INJECTION-TEST-001` | `test_*mcp*injection*` / `test_*tool*poison*` files | add an injection test corpus |
| `MCP-SCOPE-001` | per-tool least-privilege scope documented | scope each tool minimally |

All return NOT_APPLICABLE when no MCP server is detected (no `mcp.json` and no
MCP dependency in `pyproject.toml` / `package.json` / `requirements.txt`).

## Tool-description hash pinning

The primary tool-poisoning defense. Record a hash of each tool description and
verify it in CI so a silently-changed description fails the build:

```json
// .oss-policy-kit/evidence/mcp-tool-descriptions.json
{
  "search": { "sha256": "9f2c…" },
  "delete_record": { "sha256": "1a7b…" }
}
```

Regenerate and review the hashes whenever a tool description legitimately
changes.
