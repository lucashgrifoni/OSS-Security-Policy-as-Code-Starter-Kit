# Screenshots

This directory holds sanitized PNG captures of the OSS Policy Kit CLI and report output. They are used inline by [`docs/validation-walkthrough.md`](../docs/validation-walkthrough.md) so first-time readers can see expected output before running the kit locally.

All captures show:

- public CLI commands and flags,
- bundled `examples/hardened-repo` and `examples/vulnerable-repo` fixtures,
- public report fields (status, confidence, reason, remediation),

with no internal hostnames, tokens, identifiers, or private repository content.

If you regenerate a screenshot, reproduce it against the bundled fixtures with no extra arguments so the output remains reproducible by any reader.
