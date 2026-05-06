# Azure DevOps profiles

Six profiles: `azure-level-1` through `azure-level-3` and `azure-release-hardening-1` through
`azure-release-hardening-3`.

## Usage classes

- **Daily baseline**: `azure-level-1`, `azure-level-2`, `azure-release-hardening-1`,
  `azure-release-hardening-2`.
- **Extreme hard-gate**: `azure-level-3`, `azure-release-hardening-3`.

## Ladder

- **level-1**: supported pipeline YAML paths plus security / SCA / SBOM **signals**.
- **level-2**: stronger template and identity YAML signals (**advisory**).
- **level-3**: **hard-gate** with `azure-branch-policies.json`, `azure-pipeline-governance.json`,
  artifact SBOM/provenance, **ORG-MFA-001**, **GOV-EVIDFRESH-054**, and related controls.

## Release hardening

`azure-release-hardening-3` adds the **AZ-SEC / AZ-SBOM / AZ-SCA 031..033** signal bundle for
release visibility; those controls stay **signal** grade per catalog — treat PASS as directional.

## `azure-level-3` vs `azure-release-hardening-3` — when to use which

Both are Azure DevOps extreme hard-gates and both expect live `collect-evidence --platform azure`. They differ in operational fit:

- Use **`azure-level-3`** for **steady-state Azure DevOps hardening** — branch policies, pipeline governance, federated identity (`AZ-WIFEV-057`), service connection posture, and ORG-MFA. 8 of the 27 controls are evidence-backed (the highest evidence ratio of any profile in this kit).
- Use **`azure-release-hardening-3`** when the gate runs at the **release event** — adds the `AZ-SEC / AZ-SBOM / AZ-SCA 031..033` signal bundle on top of the same hard-gate core, plus artifact-bound SBOM/provenance evidence files (`AZ-ARTSBOM-058`, `AZ-ARTPRV-059`). 8 of the 30 controls are evidence-backed; release signals stay `signal`-grade and are directional, not proof of execution.

Operational rule of thumb:

- For PR-time and steady-state CI on Azure: `azure-level-3`.
- For tag/release-time gates on Azure: `azure-release-hardening-3`.
- Both depend on `AZURE_DEVOPS_ORG` and `AZURE_DEVOPS_TOKEN` for live collection. Without it, expect `self-attested` rows on platform-evidence controls — see [L3 evidence-heavy caveat](overview.md#l3-evidence-heavy-caveat-read-before-wiring-a-hard-gate).

## When to use each profile

Pick the lowest level that actually matches how your release flow is governed today:

| You want to … | Start at |
| --- | --- |
| Prove the repository ships a supported pipeline YAML and CI scanners fire | `azure-level-1` |
| Prove template extension / identity YAML patterns are in place | `azure-level-2` |
| Prove live branch policies + pipeline governance + federated identity from REST | `azure-level-3` |
| Stack release discipline signals on top of daily baselines | `azure-release-hardening-1` / `-2` |
| Gate a release with evidence freshness and strict identity / SBOM posture | `azure-release-hardening-3` |

Move up only when the evidence for the next tier is realistically available. Climbing tiers without
running `collect-evidence` turns strict rows into `self-attested` — honest, but not the same as live
platform proof.

## What `fail == 0` means (and does not mean)

- On the **synthetic fixture** (`examples/hardened-repo`), `fail == 0` is achievable for every Azure
  profile. The fixture ships self-attested JSON aligned with the bundled `azure-pipelines.yml`.
- `fail == 0` on a real repository means every evaluated Azure control produced enough evidence to
  clear a `fail` outcome — it does **not** mean every control was API-attested.
- At `level-3` / `release-hardening-3`, rows can still come back as `self-attested` when maintainer
  JSON is present but `collect-evidence --platform azure` was not run. Treat those rows as real
  follow-up items until a live collection replaces them.
- When the Azure collector runs, every governance JSON carries `posture_support` with per-API
  reachability flags. Evaluators only accept `pass` for the strict tiers when those flags are all
  true, so partial API access is visible in the report rather than hidden.

## When synthetic evidence is enough and when live collection is required

| Situation | Acceptable input |
| --- | --- |
| Adoption demo, kit evaluation, internal review | Synthetic JSON under `.oss-policy-kit/evidence/` |
| Pipeline guardrail on a development branch | Scaffolded JSON with maintainer attestation |
| Release gate on a customer-facing artifact | `collect-evidence --platform azure` output (live) |
| Audit / compliance conversation | Live JSON + `collection.source_url` + `posture_support` flags |

Use `oss-policy-kit collect-evidence --platform azure --dry-run` to preview which files will be
written and which environment variables the tool will read before committing to a live run. The
dry-run prints presence/absence of `AZURE_DEVOPS_ORG` and `AZURE_DEVOPS_TOKEN` **without ever
printing their values**.

## Practical maturity

Azure needs more evidence discipline than the GitHub path for similar assurance. The
`examples/hardened-repo` fixture includes `azure-pipelines.yml` and synthetic JSON so
`azure-level-3` and `azure-release-hardening-3` can reach **zero `fail`** in the fixture;
**self-attested** and operational warnings remain expected.

Expectation for operators: `fail == 0` in this fixture does not mean full live-platform proof; treat
`self-attested` and warnings as real follow-up items.

## When `azure-level-3` and `azure-release-hardening-3` are honestly green

These two profiles can reach `weighted 100%` on the synthetic fixture, but that number only
represents an *honest gate* when combined with a real `collect-evidence` run for the Azure family.
Without it, several controls fall back to `self-attested` rows and the same `100%` reflects
maintainer attestation, **not** live platform proof.

To wire `azure-level-3` or `azure-release-hardening-3` as a release gate, expect `AZURE_DEVOPS_ORG`
and `AZURE_DEVOPS_TOKEN` to be available with the minimal read permissions documented in the
collector help. A typical sequence:

```bash
# only with valid credentials; verify minimum permissions first
python -m oss_policy_kit collect-evidence \
  --target . --platform azure --repo MyProject/my-repo

python -m oss_policy_kit evaluate \
  --target . --profile azure-release-hardening-3 \
  --fail-on fail --summary-only
```

`--dry-run` is safe for public CI logs (it prints presence/absence of `AZURE_DEVOPS_ORG` and
`AZURE_DEVOPS_TOKEN`, never their values) but it does **not** substitute live collection for a real
release gate. Use the dry-run to confirm the contract; use a real run to feed the gate.
