# Shai-Hulud defense layer (`WORM-*` controls)

> **In development (v6.0.0 Cycle 2)**. The `WORM-*` family lands with
> PR-19 on the `feat/v6.0.0-evolution` branch. This page is the design
> rationale + adopter guide. See ADR-015 for the decision-of-record.

## Background

Between March and May 2026 the OSS package ecosystem absorbed a coordinated
campaign attributed to the threat actor **TeamPCP**, deploying a
self-propagating worm variously labelled **Shai-Hulud**, **Mini Shai-Hulud**,
and **CanisterSprawl**. Confirmed compromises include the official Aqua
Security Trivy scanner distribution (2026-03-19), Checkmarx KICS Docker
images and VS Code extensions (2026-04-21), and a mass
npm-plus-PyPI-plus-Docker push on 2026-04-21..23 and 2026-05-11 that
affected over 170 npm packages plus PyPI projects from TanStack,
Mistral AI, UiPath, OpenSearch, Guardrails AI, SAP CAP, Lightning,
Intercom, and Bitwarden.

References:

- [Wiz — Shai-Hulud 2.0 Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Datadog Security Labs — Shai-Hulud 2.0 npm worm](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [SafeDep — Mass npm Supply Chain Attack: TanStack, Mistral](https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/)
- [CISA — Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Chainloop — Trivy supply chain attack post-mortem](https://chainloop.dev/blog/trivy-supply-chain-attack-best-practices/)
- [GitGuardian — Three Supply Chain Campaigns in 48 Hours](https://blog.gitguardian.com/three-supply-chain-campaigns-hit-npm-pypi-and-docker-hub-in-48-hours/)

## Attack pattern (kit-observable)

The worm operates in four stages. The kit can only detect signals of
stages 1 and 4 from a clone, but those two stages are where most
defensive value sits.

| Stage | Behaviour | Observable from clone? |
|---|---|---|
| **1. Foothold** | Malicious `postinstall` hook in `package.json` (or `pyproject.toml` build hook) runs on every `npm install`. Harvests env vars, AWS metadata, GitHub CLI tokens, K8s service account tokens, GCP / Azure secrets. | **Yes** — `WORM-POSTINSTALL-001` |
| **2. Exfiltration** | Encrypted POST to attacker C2 (often an ICP canister for resilient hosting, hence CanisterSprawl). | No — runtime only |
| **3. Lateral push** | Worm uses stolen npm token to rewrite the victim's other packages and republish them with the same payload. | **Yes — rewrite leaves a trail** — `WORM-LOCKFILE-DRIFT-001` |
| **4. Republish** | New malicious version pushed to npm via the legitimate publish path. The publish workflow is often the same one the maintainer normally uses; without scope restrictions, any branch can publish. | **Yes** — `WORM-PUBLISH-SCOPE-001` |

## Controls

### `WORM-POSTINSTALL-001` (signal, weight 3)

Reads `package.json` and inspects the `scripts.postinstall` value (case-
insensitive) for credential-harvest primitives:

- `curl ` / `wget ` / `| sh` / `| bash` (egress + execution)
- `base64 -d` / `base64 --decode` (obfuscation)
- `process.env` / `os.environ` (env-var dump)
- `eval(` / `exec(` (dynamic code execution)
- `nc -e` / `iwr ` / `invoke-webrequest` / `powershell -encoded` (reverse shells)

| Result | Meaning |
|---|---|
| `NOT_APPLICABLE` | No `package.json`. |
| `PASS` | No `postinstall` declared, **or** `postinstall` declared without any of the danger primitives. |
| `FAIL` | `postinstall` contains at least one danger primitive. |

**Remediation**: audit the postinstall body, remove the egress + env
dump, and pin it via a separate version-controlled file (so any future
mutation surfaces in `git diff`).

### `WORM-LOCKFILE-DRIFT-001` (signal, weight 2)

Compares `mtime` of manifest files against their lockfile counterparts:

- `package.json` vs `package-lock.json` / `yarn.lock`
- `pyproject.toml` vs `poetry.lock` / `uv.lock`
- `requirements.txt` vs `requirements.lock`

| Result | Meaning |
|---|---|
| `NOT_APPLICABLE` | No manifest + lockfile pair found. |
| `PASS` | Lockfile is at least as fresh as the manifest. |
| `FAIL` | Manifest modified more than 60 s after the lockfile (suggests dependency added or rewritten without regenerating the lock — a Shai-Hulud rewrite footprint). |

**Remediation**: regenerate the lockfile (`npm install`, `poetry lock`,
`uv lock`) and commit it together with the manifest change. Investigate
any unexplained drift via `git log -p package.json` against the lockfile.

### `WORM-PUBLISH-SCOPE-001` (signal, weight 2)

Inspects every workflow that contains `npm publish` / `twine upload` /
`pypi-publish` / `cargo publish` and checks whether the `on:` trigger is
restricted to `main` / `master` / `release/*` branches or to `v*` tags.

| Result | Meaning |
|---|---|
| `NOT_APPLICABLE` | No publish workflow detected. |
| `PASS` | All publish workflows have explicit branch or tag scope. |
| `FAIL` | At least one publish workflow lacks an explicit scope (any branch could trigger a publish, which the worm exploits). |

**Remediation**:

```yaml
on:
  push:
    tags: ['v*']
# or
on:
  push:
    branches: [main]
jobs:
  publish:
    environment: production   # require approvers
```

## Profile integration

The three controls are bundled into `oss-publish-readiness-1` (extended in
PR-19) alongside the existing Trusted Publishing controls. Adopters that
only need worm-aware defaults can compose their own profile referencing
the three control IDs.

## What this does NOT do

- Does **not** detect runtime exfiltration (stage 2). Pair with
  Harden-Runner audit-mode + `GH-EGRESS-HRN-001`.
- Does **not** scan the actual package contents (the kit is policy-as-code,
  not a binary / package scanner). Pair with OSV-Scanner, Socket, or Snyk.
- Does **not** verify upstream package integrity from a clone alone.
  The downstream consumer's responsibility is to enable Trusted Publishing
  (`PUBLISH-OIDC-001..003`) and to verify provenance (`PROV-VERIFY-061`).
- Does **not** detect ICP-canister C2 channels or other infrastructure
  fingerprints. That is the job of runtime EDR / SOC tooling.

## Where to file feedback

If the worm evolves (new postinstall primitives, new manifest-drift
patterns, new publish-trigger evasion), open an issue at
<https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues>
with label `area:worm-defense`. The hint sets in `WORM-*` evaluators are
intentionally expanded conservatively to balance false positives.
