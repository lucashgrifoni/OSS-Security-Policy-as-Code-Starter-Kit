# Profiles overview

This page summarizes the bundled profile ladder. The current release bundles **56 profiles** in total; the detailed walkthrough below describes the v5.9.0 baseline ladder, and the v6.0.0+ additions (AI/LLM advisory, EU AI Act Annex IV, EU CRA Art.13/14, SLSA Source L1/L2, the full GitLab CI family — `gitlab-level-1/2/3` **plus** the `gitlab-release-hardening-1/2/3` track with a `collect-evidence --platform gitlab` collector, OSS publish readiness, AI agent baseline, OSPS Baseline 2026, MCP server, OWASP Agentic ASI) are listed in [controls-catalog.md](../controls-catalog.md) and the CHANGELOG. **GitLab is a first-class family**, mirroring the GitHub / Azure / AWS ladder + release-hardening structure — see [gitlab.md](gitlab.md). The v5.9.0 ladder: deterministic ladder profiles per platform (`github-*`, `azure-*`, `aws-*`), two **advisory-only hybrid** profiles, three **regulatory mapping** profiles for the EU Cyber Resilience Act (`cra-eu-reporting-1` for the 2026-09-11 24-hour reporting deadline — new in v5.9.0; `cra-eu-ready-1` for broader CRA preparation; `cra-eu-strict-1` for the 2027-12-11 full-obligations deadline — all three advisory), six **framework alignment** profiles introduced in v5.4.0 (`osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`), the **AppSec native bundle** `appsec-sast-sca-1` (hard-gate-capable when paired with `scan-sast`; 17 controls including the v5.9.0 SARIF adapters and v6.0.0 EPSS/KEV prioritization), the v5.5.0 **Terraform / OpenTofu IaC baseline** `iac-terraform-baseline-1` (advisory, paired with `scan-iac`), the v5.6.0 **Kubernetes manifest baseline** `kubernetes-baseline-1` (advisory, paired with `scan-k8s`), the v5.6.0 **container hardening baseline** `container-baseline-1` (advisory, clone-visible Dockerfile signals), and the v5.7.0 **webhook receiver hardening** profile `webhook-security-1`. The legacy bundled id `github-release-hardening` was **removed in v5.0.0**; passing it now returns a migration error pointing to the canonical `github-release-hardening-1`. See [docs/v5.0.0-migration-guide.md](../v5.0.0-migration-guide.md).

> **Hybrid profiles are advisory-only.** `github-aws-level-2` and `github-azure-level-2` combine GitHub SCM signals with AWS or Azure CI signals. They emit JSON `posture: multi_platform_advisory_hybrid`. **Do not use these profiles as a release or PR gate** — use the platform-specific `*-level-3` or `*-release-hardening-3` ladders instead.
>
> The non-hybrid `*-level-2` profiles (`github-level-2`, `azure-level-2`, `aws-level-2`) are also advisory-only by design (`posture: advisory`). They include several `signal` controls whose PASS is directional, not verified. Use them as scorecards, not as gates.

> **Since v6.0.0**, the kit also includes
> `ai-agent-baseline-1`, an advisory source-side profile for repositories that
> build AI agents or MCP servers. It adds ten `AI-AGENT-*` controls and three
> `ai-agent-baseline/v1` evidence files. See [ai-agent.md](ai-agent.md).

## Assurance vocabulary

The **catalog `assurance` field** classifies how a control proves its conclusion:

- **`deterministic`**: evaluated from files in the clone (YAML, manifests, paths) with structured parsing where possible.
- **`signal`**: keyword or heuristic posture in CI files; PASS is directional, not proof of execution.
- **`evidence-backed`**: requires `.oss-policy-kit/evidence/*.json` (manual attestation or `collect-evidence` API exports) for a credible PASS.

The **`reports/1.0` Evidence Model v2** (visible per result in `evaluation-report.json` when the default contract is used) projects a richer trust picture using these keys (full reference in [docs/reports-contract-v1.0.md](../reports-contract-v1.0.md)):

- **`source_type`**: where the conclusion came from — `clone_file`, `workflow_yaml`, `pipeline_yaml`, `evidence_json`, `api_collected`, `heuristic_signal`, etc.
- **`collection_method`**: how it was gathered — `clone_inspection`, `workflow_yaml_parse`, `evidence_attestation`, `api_collected`, `keyword_match`, etc.
- **`trust_level`**: derived semantic level — `verified` (high), `attested`, `observed`, `heuristic` (lowest). Keyword-only matches cap trust at `heuristic` even when the status is `pass`.
- **`attestation_status`**: `signed`, `self_attested`, `none`. Promoted from `self_attested` to `signed` only when the control source is `api_collected` and an `attested_by` value is present.
- **`freshness_status`**: `fresh`, `stale`, `unknown`. Driven by `extra.collected_at` (ISO8601) on live evidence; without it, the projection emits `unknown`.
- **`evidence_required`**: boolean — true on `evidence-backed` catalog controls; surfaces explicitly in `reports/1.0`.
- **`limitations`**: free-form strings explaining why a result cannot project to a higher trust level (for example, `keyword-only signal cannot project to verified`).

These projection fields are **read on emission** from the evaluator's existing `evidence_sources`, `evidence_collection_method`, `assurance`, `status`, and the `extra` mapping. Existing evaluator plugins do not need to change. They are not present in `reports/0.3` or `reports/0.2` payloads.

Two consequences worth keeping in mind:

- A `pass` on a `signal` control is not the same shape of proof as a `pass` on a `deterministic` or `evidence-backed` control. The Evidence Model v2 makes that explicit; the report Markdown surfaces the same idea with the assurance label per row.
- Hard-gate profiles (`*-level-3`, `*-release-hardening-3`) treat evidence freshness and attestation as part of the gate, not as a side note. If you wire `--fail-on fail` on those profiles in CI, plan for `collect-evidence` upstream (see [L3 evidence-heavy caveat](#l3-evidence-heavy-caveat-read-before-wiring-a-hard-gate)).

## Profile ladder vocabulary

- **starter** (`level-1`, `release-hardening-1`): smallest honest gate focused on clone-visible governance plus baseline CI signals.
- **advisory** (`level-2`, `release-hardening-2`): adds stricter workflow posture; still contains signal-heavy controls.
- **hard-gate** (`level-3`): evidence-first core; treat failures as merge/release blockers when your team accepts residual signal risk.
- **release-hardening**: parallel track that layers release discipline (freshness, branch protection evidence, merge queue, artifact-bound SBOM/provenance on AWS/Azure) on top of the same ladder.

Hybrid profiles **github-aws-level-2** and **github-azure-level-2** are **advisory-only by design** (they combine GitHub workflows with AWS/Azure clone signals and never replace the pure level-3 gates).

## Operational usage matrix

Use this matrix as an operator shortcut (derived from current bundled profile intent and fixture behavior):

| Usage class | Profiles | Notes |
| --- | --- | --- |
| Daily baseline | `*-level-1`, `*-level-2`, `*-release-hardening-1`, `*-release-hardening-2` | Best for routine triage and incremental hardening. |
| Extreme hard-gate | `*-level-3`, `*-release-hardening-3` (single-platform) | Evidence-first posture; treat non-pass rows and warnings as real work. |
| Advisory-only | `github-aws-level-2`, `github-azure-level-2` | Multi-platform guidance; **not** a hard-gate replacement. |
| AI agent source-side advisory | `ai-agent-baseline-1` | Checks MCP authn, tool allowlists, prompt review, audit, memory, and model-pinning evidence. |
| Legacy id (removed) | `github-release-hardening` | **Removed in v5.0.0.** Returns a migration error. Use `github-release-hardening-1`. |

## `maturity_label` glossary and recommended `--fail-on`

`python -m oss_policy_kit profiles --format json` exposes a `maturity_label` field per profile. The label is a stable operator-facing string; the table below maps each label to the gate we recommend you actually wire in CI.

| `maturity_label` | Example profiles | Recommended `--fail-on` | Evidence expectation |
| --- | --- | --- | --- |
| `starter ladder` | `github-level-1`, `azure-level-1`, `aws-level-1` | `fail` | Clone-visible signals only. |
| `advisory ladder` | `github-level-2`, `azure-level-2`, `aws-level-2` | `degraded` (treat `manual-review-required` as a gate too) | Signal-heavy; live evidence is optional. |
| `hard-gate ladder (extreme)` | `github-level-3`, `azure-level-3`, `aws-level-3` | `fail` paired with `collect-evidence` live for that family | Evidence-first; `self-attested` is not `pass` at this tier. |
| `release ladder` | `*-release-hardening-1`, `*-release-hardening-2` | `fail` (release-hardening-1) or `degraded` (release-hardening-2) | Clone signals plus minimal release evidence; freshness matters. |
| `release hard-gate (extreme)` | `*-release-hardening-3` | `fail` paired with `collect-evidence` live + artifact-bound SBOM/provenance | Strictest bundled release gate per platform. |
| `advisory hybrid (multi-platform)` | `github-aws-level-2`, `github-azure-level-2` | `degraded` only — **never** use as the hard-gate for a release | GitHub + AWS/Azure signals combined; advisory by design. |

Multi-platform hybrids deserve a short note of their own: **`github-aws-level-2`** and **`github-azure-level-2`** exist for teams whose source of truth is GitHub (repo lives on github.com) but whose CI/CD terminates on AWS CodePipeline or Azure Pipelines. They stack GitHub workflow signals on top of the platform family's clone-visible controls and are **advisory by design**. Use them as a PR-level gate with `--fail-on degraded`; when it is time to cut a release, pick the pure single-platform hard-gate (`aws-release-hardening-3` or `azure-release-hardening-3`) for the environment that actually ships the artifact.

## Hybrid (PR-time) vs single-platform extreme (release-time)

The hybrid profiles `github-aws-level-2` and `github-azure-level-2` are advisory by design. Use them as a PR-time gate when source lives on GitHub but CI/CD runs on AWS or Azure. They do not replace the single-platform extreme profile of the platform that actually ships the release artifact.

Operational rule of thumb:

- PR-time, multi-platform team: `github-aws-level-2` (or `github-azure-level-2`) with `--fail-on degraded`.
- Release-time, deterministic gate: `aws-release-hardening-3` (or `azure-release-hardening-3`) with `--fail-on fail` and a real `collect-evidence` run for that platform.

The hybrid is a triage profile; the single-platform extreme is the gate.

When you choose to wire a hybrid profile in CI, prefer `--fail-on degraded` over `--fail-on fail`. The advisory tier is signal-heavy: `manual-review-required` is the dominant useful state, and `--fail-on degraded` gates it without forcing the team to handle every signal as a blocker.

## Uniform output in `*-level-1` on bare application repos

`*-level-1` is optimized for repositories that carry their **own** governance (SECURITY.md, CONTRIBUTING, CODEOWNERS, LICENSE, CHANGELOG) and, for `github-level-1`, their own `.github/workflows/`. In a monorepo where individual sub-apps are pure code trees (no governance, no CI at the sub-app level, no `.git`), every sub-app tends to produce the **same** `*-level-1` report — most rows `fail` because the clone-visible signals simply are not there. That is **not** a bug and **not** a regression: it reflects that `*-level-1` was never designed to grade bare application code by itself.

If you hit this pattern, the honest moves are:

- keep governance in an **umbrella** repository and only run `*-level-1` against that umbrella,
- escalate bare application sub-trees to `*-level-2` with `--fail-on degraded` (advisory) so the uniform-fail tail is read as signal rather than a hard fail, or
- treat each sub-app independently with a profile that matches its real CI platform and run `evaluate` per sub-tree instead of `evaluate-many` at the parent.

### How to recognize it in a batch

If `evaluation-batch.md` shows several targets failing the same set — typically `GOV-COWN-003`, `GOV-WAIV-014`, `GOV-CON-002`, `GOV-DISC-013`, `GOV-LIC-004`, `GOV-SEC-001`, `REL-CHANGE-012` — that is the expected `*-level-1` shape on bare application code, **not** a kit defect or regression. Apply one of the moves above instead of treating it as noise.

## Profile maturity tier (read before choosing a hard gate)

The bundled profiles are not equally mature in **operational fit**. Most stable
daily/release profiles rely on clone-visible governance and CI/CD signals, while
the IaC, Kubernetes, container, webhook, AI/LLM, and AI-agent profiles include
newer experimental controls and evidence-backed expectations. Two practical
things differ between profiles:

1. how much **evidence-template work** the operator must do up front, and
2. how complete the **collector** is for the platform.

The table below is the honest current state. It does **not** modify any profile or control; it is a docs-only snapshot to set operator expectations.

| Tier | Profiles | What "mature" means here | Caveat |
|---|---|---|---|
| **Mature daily baseline** | `github-level-1`, `azure-level-1`, `aws-level-1` | Designed for routine PR triage; no evidence files needed; results are reproducible from a clone alone. | None beyond the standard `*-level-1` caveat about bare application repos (see previous section). |
| **Mature daily baseline (with caveats)** | `github-release-hardening-1`, `azure-release-hardening-1`, `aws-release-hardening-1` | Adds branch-protection evidence on top of `*-level-1`. Pass on the new evidence row requires a single small JSON file. | One control will sit at `manual-review-required` / `self-attested` until you fill the JSON or run `collect-evidence`. |
| **Mature advisory** | `github-level-2`, `azure-level-2`, `aws-level-2`, `github-aws-level-2`, `github-azure-level-2` | Designed to be advisory; **not** a release gate. Posture is `advisory` (or `multi_platform_advisory_hybrid` for hybrids). | Wiring `--fail-on fail` against an advisory profile defeats the design. Use `--fail-on degraded`. |
| **Operationally mature; collector mature** | `github-level-3`, `github-release-hardening-3` | The most mature path in the kit: deterministic + evidence-backed + GitHub collector retrieves all 4 platform evidence files. Reaches `pass` end-to-end with `collect-evidence --platform github` and a token. | Requires `GITHUB_TOKEN` with the right permissions for `branch-protection`, `rulesets`, `secret-scanning`, `environments`. |
| **Operationally mature; collector partial** | `azure-level-3`, `aws-level-3`, `azure-release-hardening-3`, `aws-release-hardening-3` | Catalog and evaluator side are stable. The collector retrieves 2-3 endpoints (vs. GitHub's 4) and several artifact-bound evidence files (`*-sbom-artifact`, `*-provenance-artifact`, `org-mfa-posture`) intentionally stay self-attested because their digests must come from the release pipeline. | Without a real `collect-evidence` run on the right project, expect a tail of `self-attested` rows; this is the current parity gap, documented in [collector-parity.md](../collector-parity.md). |
| **UX-bound (operationally mature when used right)** | `github-release-hardening-2`, `azure-release-hardening-2`, `aws-release-hardening-2` | The profile itself is mature — the issue was historically with the **recommendation heuristic** that suggested them when only evidence templates were present. Mitigated in the v5.0.0 line: `recommend-profile` rationale strings now include "(verify evidence JSONs are filled, not templates)" and `docs/cli-reference.md` + `docs/results-guide.md` carry the same caveat. | If you fill the templates (or run `collect-evidence`) the profile reaches `pass=majority` cleanly on the bundled hardened fixture; the test suite locks in those expected counts. |

### Why no new profile is being added to fix Tier 5/6

These tiers are **not** evidence of catalog immaturity — they reflect the limits of what a tool that does not control the underlying CI platform can prove from a clone or a single REST call. Adding a new profile would not change those limits. The maturity work to close them is:

- expanding `collect-evidence` for Azure/AWS to reach GitHub-level coverage (deferred follow-up listed in [profiles/deferred-followups.md](deferred-followups.md));
- emitting artifact-bound evidence (SBOM/provenance) directly from the release pipeline; and
- continuing to project `signal` controls as `inferred` trust regardless of profile (already enforced by `evidence_projection`).

### Framework alignment

Each bundled profile description (`profiles --format detailed`) points operators
at [framework-alignment.md](../framework-alignment.md), which maps the bundled
catalog to OpenSSF Scorecard, OSPS Baseline, OWASP CI/CD Top 10, SLSA, NIST SSDF
SP 800-218, Microsoft S2C2F, CIS Software Supply Chain Security Benchmark, AWS
Well-Architected (Security Pillar), Azure DevOps Security Best Practices, EU
Cyber Resilience Act, and v6 AI-security roadmap surfaces. The page documents
YES / PARTIAL / OUT / GAP coverage per framework requirement.

Starting in v5.4.0 the kit also ships **bundled framework alignment profiles** (`osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`, `cra-eu-strict-1`). They are multi-platform mappings that combine existing controls into framework-specific bundles - operators who used to rely on the mapping documentation alone can now also `evaluate --profile <id>` to get a framework-shaped report. None of these profiles introduces a new control; they reuse the existing catalog. See the per-profile mapping in [framework-alignment.md](../framework-alignment.md).

## Matrix (derived from bundled YAML + catalog assurance mix)

| Profile | Controls | Status (CLI `maturity_label`) | Extreme gate profile? | det / sig / evi |
| --- | ---: | --- | --- | --- |
| github-level-1 | 14 | starter ladder | no | 11 / 3 / 0 |
| github-level-2 | 29 | advisory ladder | no | 19 / 10 / 0 |
| github-level-3 | 33 | hard-gate ladder (extreme) | **yes** | 21 / 8 / 4 |
| github-release-hardening-1 | 16 | release ladder | no | 12 / 3 / 1 |
| github-release-hardening-2 | 30 | release ladder | no | 18 / 8 / 4 |
| github-release-hardening-3 | 32 | release hard-gate (extreme) | **yes** | 19 / 8 / 5 |
| github-aws-level-2 | 35 | advisory hybrid (multi-platform) | no | 22 / 13 / 0 |
| github-azure-level-2 | 36 | advisory hybrid (multi-platform) | no | 23 / 12 / 1 |
| azure-level-1 | 13 | starter ladder | no | 9 / 4 / 0 |
| azure-level-2 | 21 | advisory ladder | no | 15 / 5 / 1 |
| azure-level-3 | 27 | hard-gate ladder (extreme) | **yes** | 16 / 3 / 8 |
| azure-release-hardening-1 | 17 | release ladder | no | 11 / 4 / 2 |
| azure-release-hardening-2 | 24 | release ladder | no | 16 / 5 / 3 |
| azure-release-hardening-3 | 30 | release hard-gate (extreme) | **yes** | 16 / 6 / 8 |
| aws-level-1 | 12 | starter ladder | no | 8 / 4 / 0 |
| aws-level-2 | 20 | advisory ladder | no | 14 / 6 / 0 |
| aws-level-3 | 25 | hard-gate ladder (extreme) | **yes** | 15 / 3 / 7 |
| aws-release-hardening-1 | 16 | release ladder | no | 10 / 4 / 2 |
| aws-release-hardening-2 | 22 | release ladder | no | 14 / 6 / 2 |
| aws-release-hardening-3 | 29 | release hard-gate (extreme) | **yes** | 15 / 7 / 7 |
| cra-eu-reporting-1 | 11 | regulatory mapping (advisory, 2026-09-11 reporting) | no | see JSON |
| cra-eu-ready-1 | 12 | regulatory mapping (advisory) | no | 5 / 4 / 3 |
| cra-eu-strict-1 | 19 | regulatory mapping (advisory, strict track) | no | see JSON |
| osps-baseline-1 | 18 | framework alignment (advisory) | no | see JSON |
| slsa-build-l2-1 | 14 | framework alignment (hard-gate-capable) | **yes (with evidence)** | see JSON |
| ssdf-baseline-1 | 22 | framework alignment (advisory) | no | see JSON |
| cis-supply-chain-1 | 24 | framework alignment (advisory) | no | see JSON |
| owasp-cicd-top10-1 | 23 | framework alignment (advisory) | no | see JSON |
| s2c2f-l1-1 | 9 | framework alignment (advisory, OSS consumption) | no | see JSON |
| appsec-sast-sca-1 | 15 | AppSec native bundle (hard-gate-capable with scan-sast + SARIF adapters) | **yes (with scan-sast)** | see JSON |
| ai-agent-baseline-1 | 10 | AI agent source-side baseline (advisory) | no | 0 / 7 / 3 |
| iac-terraform-baseline-1 | 15 | IaC Terraform / OpenTofu baseline (advisory) | no | see JSON |
| iac-cfn-baseline-1 | 7 | CloudFormation posture (advisory, paired with scan-cfn) | no | 1 / 0 / 6 |
| iac-pulumi-baseline-1 | 7 | Pulumi Python posture (advisory, paired with scan-pulumi) | no | 1 / 0 / 6 |
| iac-bicep-baseline-1 | 7 | Bicep posture (advisory, paired with scan-bicep) | no | 1 / 0 / 6 |
| kubernetes-baseline-1 | 17 | Kubernetes manifest posture (advisory, paired with scan-k8s) | no | 1 / 0 / 16 |
| container-baseline-1 | 11 | Container hardening posture (advisory) | no | 3 / 8 / 0 |
| webhook-security-1 | 3 | Webhook receiver security (advisory, paired with the receiver) | no | 1 / 2 / 0 |
| gitlab-level-1 | 16 | GitLab CI starter ladder | no | 10 / 6 / 0 |
| gitlab-level-2 | 22 | advisory ladder | no | 10 / 12 / 0 |
| gitlab-level-3 | 29 | hard-gate ladder (extreme) | **yes** | 11 / 13 / 5 |
| gitlab-release-hardening-1 | 19 | release ladder | no | 12 / 6 / 1 |
| gitlab-release-hardening-2 | 29 | release ladder | no | 15 / 13 / 1 |
| gitlab-release-hardening-3 | 36 | release hard-gate (extreme) | **yes** | 15 / 15 / 6 |

> **Source for counts**: `python -m oss_policy_kit profiles --format json` (`controls` and `assurance_mix`) against the bundled catalog in this revision. Counts evolve as new controls are folded into existing profiles; the JSON output is the canonical source of truth for any given build.

### Framework alignment profiles (v5.4.0)

The seven profiles introduced in v5.4.0 (`osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`, `cra-eu-strict-1`) are **multi-platform mappings**: they have no platform prefix and combine controls from the current 212-control catalog (as of v6.4.0) into framework-aligned bundles. They complement (not replace) the platform ladders. Detailed per-framework mapping is documented in [framework-alignment.md](../framework-alignment.md).

One of the seven is hard-gate-capable when evidence is present (`slsa-build-l2-1`); the other six are advisory mappings (`--fail-on degraded` recommended). Both CRA profiles (`cra-eu-ready-1` for the 2026-09-11 reporting deadline and `cra-eu-strict-1` for the 2027-12-11 full obligations) are advisory regulatory mappings: the kit aligns evidence with CRA expectations but does not certify compliance, which requires a competent authority (notified body, CE-marking) outside the kit's scope. All seven trigger the `[advisory profile]` banner only when explicitly listed there; consult `src/oss_policy_kit/cli/terminal_ui.py:_ADVISORY_ONLY_PROFILE_IDS` for the live list.

The `recommend-profile` heuristic does not auto-suggest these seven framework profiles - they are deliberate operator choices, not heuristic recommendations (same pattern as `cra-eu-ready-1`).

### AppSec native bundle (v5.4.0+)

`appsec-sast-sca-1` (17 controls) is a separate multi-platform profile aimed at AppSec teams using the kit as part of pipeline AppSec, not just OSS governance. It bundles SAST (Semgrep evidence + CodeQL/equivalent signals), SCA (dependency review, auto-update, lockfile pinning), secret scanning, and dependency integrity controls. The profile is **hard-gate-capable when paired with `oss-policy-kit scan-sast`**: without the SAST evidence file, `SAST-SEMGREP-064` returns `manual-review-required` and does not trip `--fail-on fail`. With evidence, the profile reaches deterministic + evidence-backed posture and is suitable for `--fail-on fail`. See [framework-alignment.md](../framework-alignment.md) (AppSec native section) for the per-control mapping.

## ASCII decision tree (choose a profile)

```
Do you have GitHub Actions workflows in the clone?
├─ No -> you are probably not a github-* candidate; look at Azure/AWS signals.
└─ Yes
   ├─ Baseline OSS clone + CI only? -> github-level-1
   ├─ Stronger signals (merge queue, secrets hygiene) without platform evidence? -> github-level-2
   └─ Want GitHub evidence (.oss-policy-kit/evidence) + org MFA + SBOM on disk?
      ├─ Release pipeline focus -> github-release-hardening-3 (densest reference)
      └─ Repo service focus -> github-level-3

Need AWS or Azure evidence-backed gates?
└─ Use matching aws-* / azure-*; GitHub remains the most mature path *inside this kit*.
```

## Zero `fail` is not the same as all-pass

In reports, **`summary_by_status.fail == 0`** only means no control ended in **`fail`**. The same run can still contain **`self-attested`**, **`manual-review-required`**, **`not-evaluated`**, **`not-applicable`**, and operational warnings. The bundled `examples/hardened-repo` fixture is intentionally tuned so the **six single-platform GitHub/Azure/AWS extreme profiles** reach **zero `fail`** while remaining honest about non-pass rows (especially **AWS/Azure**, which lean more on self-attested evidence than **GitHub** in synthetic setups). The fixture carries no `.gitlab-ci.yml`, so the two **GitLab** extremes (`gitlab-level-3`, `gitlab-release-hardening-3`) are **not** zero-fail there — `GL-PIPE-001` fails on the missing pipeline by design. Run the GitLab gates against a repository that actually uses GitLab CI (and `collect-evidence --platform gitlab`).

## Fixture representativity (important)

The hardened fixture is strong for the single-platform extreme tracks, but it is **not** a universal “green for every profile” fixture.

- Confirmed in the 2026-04-22 validation: `github-level-2`, `github-release-hardening-2`, `github-aws-level-2`, and `github-azure-level-2` can still fail in `examples/hardened-repo` (notably on `GH-PROV-023` and/or `SEC-SECRETS-050`).
- Re-confirmed on 2026-04-24: `github-aws-level-2` keeps two fixture-only fails (`provenance/attestation` and `secret scanning keyword`); the same pattern holds for `github-azure-level-2`. The fixture remains intentional and is not a profile defect.
- That does **not** mean those profiles are broken; it means this fixture does not fully represent every L2/hybrid expectation.
- Treat fixture gaps and profile quality separately. When a profile is advisory-only by design, a non-green fixture run may still be useful for prioritization.

## Honest limits for this kit

- Evidence under `examples/hardened-repo` is **synthetic** (it does not replace `collect-evidence` with real credentials).
- **OSS-SCORECARD-001** stays **not-evaluated** until you pass `--scorecard-json`.
- Extreme AWS/Azure profiles need more **evidence discipline** than GitHub to reach the same operational confidence. See [docs/profiles/aws.md](aws.md) and [docs/profiles/azure.md](azure.md) for the explicit `collect-evidence` expectation at L3 / release-hardening-3.

## L3 evidence-heavy caveat (read before wiring a hard gate)

Extreme profiles (`*-level-3`, `*-release-hardening-3`) intentionally embed evidence-backed controls so that a `pass` on a hard gate reflects something more than clone-visible signals. The trade-off is that **without `collect-evidence` (or hand-filled evidence files matching the bundled schemas), some controls will land on `manual-review-required`, `not-applicable`, or stay at lower confidence**. That is not a defect — it is the difference between *clone-visible* checks and *evidence-backed* checks.

The proportion of evidence-backed controls per extreme profile (source: `python -m oss_policy_kit profiles --format json` against the bundled catalog in this revision):

| Profile | Total controls | Evidence-backed | % evidence-backed |
| --- | ---: | ---: | ---: |
| `azure-level-3` | 27 | 8 | 29.6% |
| `aws-level-3` | 25 | 7 | 28.0% |
| `azure-release-hardening-3` | 30 | 8 | 26.7% |
| `aws-release-hardening-3` | 29 | 7 | 24.1% |
| `gitlab-release-hardening-3` | 36 | 6 | 16.7% |
| `github-release-hardening-3` | 32 | 5 | 15.6% |
| `gitlab-level-3` | 29 | 5 | 17.2% |
| `github-level-3` | 33 | 4 | 12.1% |

Operational reading:

- If you wire one of these as `--fail-on fail` in CI without an evidence pipeline, expect a meaningful tail of `manual-review-required` rows. That output is *honest*, not a regression.
- `summary_by_status.fail == 0` does not imply *all-pass*. See [Zero `fail` is not the same as all-pass](#zero-fail-is-not-the-same-as-all-pass) on this same page.
- The intended path is `collect-evidence` for the matching family (`github`, `azure`, `aws`) before the hard gate fires. AWS and Azure extreme profiles depend on this more than GitHub by construction.

For the platform-specific `collect-evidence` expectation see [docs/profiles/aws.md](aws.md) and [docs/profiles/azure.md](azure.md). For the operator playbook see [docs/release-playbook-hardgate.md](../release-playbook-hardgate.md).

## How `recommend-profile` reads `.oss-policy-kit/evidence/`

`recommend-profile` treats JSON files under `.oss-policy-kit/evidence/` as platform signals (github-shaped JSON -> github family, azure-shaped -> azure, aws-shaped -> aws). Because of that, a repository with only a synthetic evidence pack (and no real workflow, pipeline or buildspec) can still receive a `*-release-hardening-2` suggestion. The suggestion text uses "and/or" to reflect this; the heuristic does not know whether the JSON came from a template or from `collect-evidence`.

Operational rule: treat any `*-release-hardening-*` suggestion as a hypothesis. Confirm there is a real CI workflow / pipeline / buildspec in the repository before promoting that profile to a hard gate. If you only have synthetic evidence, start at the matching `*-level-1` and let the team produce real CI signals before climbing the ladder.

## Further reading

- [GitHub profiles](github.md)
- [AWS profiles](aws.md)
- [Azure profiles](azure.md)
- [Release hard-gate playbook](../release-playbook-hardgate.md)
- [Deferred follow-ups (out of scope)](deferred-followups.md)
