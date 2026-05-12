# Vulnerable example (intentional)

> **Do not copy this folder as a baseline.** It is intentionally weak so OSS Policy Kit can demonstrate failing controls, fail-on behavior, and remediation messaging.

This minimal repository layout is bundled with the kit purely as a test fixture for `--fail-on fail` runs and for the screenshots used in `docs/validation-walkthrough.md`.

## What is intentionally weak here

- `.github/workflows/unsafe.yml` uses the `pull_request_target` trigger and checks out attacker-controlled refs without isolation — never wire this into a real repository.
- Required governance and policy files (SECURITY.md, CODEOWNERS, etc.) are deliberately absent.

Any credential-shaped string that appears in this folder, in reports generated from it, or in unit tests that exercise it is **synthetic test data**, not a real secret.

## Use it for

- Validating CI gate behavior: `python -m oss_policy_kit evaluate --target examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vuln --fail-on fail` should exit with code `1`.
- Reading the remediation field of each failing control to see what the kit recommends.

## Looking for a reference baseline?

Use [`examples/hardened-repo/`](../hardened-repo/) — that fixture passes `github-level-1` and is the layout to model your repository on.
