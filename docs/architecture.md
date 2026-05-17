# Architecture

This document describes the runtime structure of the OSS Security Policy as Code Starter Kit and the trust boundaries behind its results.

## Design goals

- keep the implementation small and testable
- separate product meaning from low-level file parsing
- stay honest about what can and cannot be proven from a local clone
- prefer explicit degradation over optimistic false passes

## Control ID convention

Each control in `data/controls/catalog.yaml` has a globally unique `id` of the form `<PREFIX>-<TOKEN>-<NUMBER>`:

- `<PREFIX>` is one of `GOV`, `CI`, `SEC`, `REL`, `PLAT`, `GH`, `AZ`, `AWS`, `DEP`, `OSS`, `CONT`, `BUILD`, `ORG`, `AUDIT`, `PROV`, `SAST`, `RELEASE`. The prefix encodes either a category (governance, ci_cd, supply_chain, etc.) or a platform (`GH`, `AZ`, `AWS`).
- `<TOKEN>` is a short mnemonic (e.g. `WF`, `PIN`, `PIPE`, `SECRET`, `SBOM`).
- `<NUMBER>` is a 3-digit serial.

The combination is unique. **The serial number alone is not unique across families**: parallel controls for different platforms intentionally share the same serial. For example:

- `AZ-SCONN-056` (Azure DevOps service connection auth) and `AWS-PIPEIAM-056` (AWS CodePipeline IAM) both use serial `056`.
- `AZ-WIFEV-057` and `AWS-CBIDENT-057` both use `057`.
- `AZ-ARTSBOM-058` and `AWS-SBOMART-058` both use `058`.
- `AZ-ARTPRV-059` and `AWS-PROVART-059` both use `059`.

This is by design. The full ID is what is consumed by profiles, the registry, the evaluator dispatch, the reports schema, and external tooling. Reading two such IDs as if they were the same control is a reviewer mistake; the prefix differentiates them.

When proposing a new control, pick a prefix that already exists when the new control fits the same family; otherwise introduce a new prefix and document it here.

## Package layout

### Domain (`oss_policy_kit.domain`)

Core datatypes and enums:

- `ControlStatus`
- `ControlResult`
- `ExecutionReport`
- `WaiverRecord`
- `EvidenceCollectionMethod`, `LiveCollectionMetadata`, `EvalOutcome`
- plugin typing: `domain/plugin_contract.py` (`EvaluatorPlugin` protocol)

Third-party evaluators register under the **`oss_policy_kit.evaluators`** entry-point group; the application layer merges them into **`EVALUATOR_REGISTRY`** after built-ins load (no overrides).

### Application (`oss_policy_kit.application`)

Product orchestration and control semantics:

- catalog and profile loading
- waiver parsing and validation
- per-control evaluators (from **v3.1.0**, many paths downgrade or gate **confidence** when only YAML keywords or unfilled evidence digests are present, so **`signal`** vs **`evidence-backed`** in the catalog matches runtime honesty more closely)
- report assembly and status summarization
- JSON and Markdown report emission

#### Evaluator boundary modules

`evaluators.py` remains the registry owner (`EVALUATOR_REGISTRY`) and
holds the function bodies for v5.7-era controls. Public **boundary
modules** sit alongside it; each exposes a closed list of control IDs
and a `build_<bucket>_evaluators()` function that returns the same
callables as the registry (byte-equivalence guarantee). External code
that cares about a single pack should import from the boundary module
instead of reaching into `evaluators.py`:

| Module | Pack | Introduced in |
|---|---|---|
| `evaluators_governance.py` | Governance + release-changelog | v5.7.0 |
| `evaluators_supply_chain.py` | Supply chain (SBOM, Scorecard, dep-update, CodeQL, dependency review, provenance verify) | v5.7.0 |
| `evaluators_ci_cd.py` | CI/CD (workflow + Azure pipeline + AWS buildspec analysis) | v5.8.0 |
| `evaluators_platform.py` | Repo / org / platform-side controls | v5.8.0 |
| `evaluators_release.py` | Release artifacts (provenance, SBOM artifact-bound, deploy, audit stream, archive) | v5.8.0 |
| `evaluators_vuln_management.py` | In-repo secret / pin / gitignore hygiene | v5.8.0 |
| `evaluators_sast.py` | SAST adapters (Semgrep today; Trivy / Gitleaks / Grype tracked for v5.9.0) | v5.8.0 |
| `evaluators_containers.py` | Container image hardening | pre-v5.7 |
| `evaluators_k8s.py` | Kubernetes manifest posture | pre-v5.7 |
| `evaluators_iac.py` | Terraform / OpenTofu posture | pre-v5.7 |
| `evaluators_iac_cfn.py` | CloudFormation posture | v5.7.0 |
| `evaluators_iac_pulumi.py` | Pulumi Python posture | v5.7.0 |
| `evaluators_iac_bicep.py` | Bicep posture | v5.7.0 |
| `evaluators_webhook.py` | Webhook receiver security | v5.7.0 |
| `evaluators_fuzzing.py` | Fuzzing presence | pre-v5.7 |
| `evaluators_common.py` | Shared evaluator utilities | pre-v5.7 |

Moving function bodies into the new boundary modules is intentionally
incremental (one bucket per minor release) so each move can be
validated against the byte-equivalence guarantee in isolation.
Promoting the whole set into a Python package
(`oss_policy_kit.application.evaluators.*`) is tracked for v6.0 (Fase 6
of the maturity plan).

### Adapters (`oss_policy_kit.adapters`)

Boundary adapters:

- local path resolution
- optional OpenSSF Scorecard JSON ingestion

### Infrastructure (`oss_policy_kit.infrastructure`)

Low-level mechanics:

- safe YAML loading
- static GitHub Actions workflow parsing
- static Azure Pipelines workflow parsing
- static AWS CodeBuild buildspec and committed CodePipeline file discovery
- optional REST evidence collectors under **`oss_policy_kit.infrastructure.collectors`** (for example GitHub via **`httpx`**)

### CLI (`oss_policy_kit.cli`)

Typer-based command surface with:

- explicit `evaluate` subcommand
- bundled profile discovery via the `profiles` subcommand (canonical; `--show-profiles` is a deprecated alias kept for compatibility)
- compatible top-level invocation without `evaluate`
- machine-friendly summary output
- CI-friendly exit codes

## Bundled policy data

Runtime policy assets are packaged from:

- `src/oss_policy_kit/data/controls/catalog.yaml`
- `src/oss_policy_kit/data/profiles/*/profile.yaml`
- `src/oss_policy_kit/data/schema/evidence-branch-protection.schema.json`
- `src/oss_policy_kit/data/schema/evidence-github-rulesets.schema.json`
- `src/oss_policy_kit/data/schema/evidence-github-environment-protection.schema.json`
- `src/oss_policy_kit/data/schema/evidence-github-secret-scanning.schema.json`
- `src/oss_policy_kit/data/schema/evidence-azure-branch-policies.schema.json`
- `src/oss_policy_kit/data/schema/evidence-azure-pipeline-governance.schema.json`
- `src/oss_policy_kit/data/schema/evidence-aws-codebuild-project.schema.json`
- `src/oss_policy_kit/data/schema/evidence-aws-codepipeline.schema.json`

The public report schema remains under:

- `reports/schema/evaluation-result.schema.json`
- `reports/schema/evidence-branch-protection.schema.json`
- `reports/schema/evidence-github-rulesets.schema.json`
- `reports/schema/evidence-github-environment-protection.schema.json`
- `reports/schema/evidence-github-secret-scanning.schema.json`
- `reports/schema/evidence-azure-branch-policies.schema.json`
- `reports/schema/evidence-azure-pipeline-governance.schema.json`
- `reports/schema/evidence-aws-codebuild-project.schema.json`
- `reports/schema/evidence-aws-codepipeline.schema.json`

### Catalog and profile invariants

The bundled catalog and profiles are guarded by four invariant suites so
adding a new control, adding a new profile, or editing an existing entry
cannot silently break the public contract. All four run as part of
`python -m pytest`:

- `tests/application/test_profile_schemas.py` -- every `profile.yaml`
  declares the required fields (`id`, `title`, `description`,
  `audience`, `controls`), the profile `id` matches its directory name,
  every `control_id` it lists exists in `catalog.yaml`, and no
  `control_id` appears twice in the same profile.
- `tests/application/test_profile_maturity_drift.py` -- profiles
  classified as extreme hard-gate (`-level-3`, `release-hardening-3`)
  must keep at least 15% evidence-backed weight; framework-aligned
  hard-gate-capable profiles need at least 5%; advisory profiles must
  surface their disposition in title or description.
- `tests/data/test_catalog_consistency.py` -- every control in
  `catalog.yaml` exposes the required fields with values from the
  documented enum sets (`category`, `lifecycle`, `assurance`,
  `automation`, `weight`); no duplicate ids.
- `tests/data/test_evidence_schemas_versioned.py` -- every
  `*.schema.json` under `src/oss_policy_kit/data/schema/` parses as a
  JSON object, declares the JSON Schema 2020-12 draft, exposes a
  well-formed `$id` ending in the file's basename, and is UTF-8 without
  BOM (release-readiness contract).

A standalone CLI mirror of these checks ships at
`scripts/validate-bundled-profiles.py` for lightweight pre-commit / CI
use without the full pytest harness.

## Evidence and trust model

The kit evaluates a **local repository clone**. Not all controls are equally observable from local files.

### Evidence tiers

| Tier | Meaning | Typical confidence |
| --- | --- | --- |
| Local automated | Derived entirely from files in the clone | `high` or `medium` |
| Local partially observable | Visible locally, but not equivalent to live platform truth | `medium` or `low` |
| Self-attested | Maintainer-supplied evidence file with schema validation only | `low` |
| Manual review required | Not safely provable from local files | limitation is known with high confidence |
| Not observable | Structurally outside the clone | limitation is known with high confidence |

### Structured evidence

Consumer repositories may optionally include evidence files under:

- `.oss-policy-kit/evidence/`

These files are local inputs to the evaluator. Repositories may version them deliberately, but many teams will keep them untracked and generate them only for local validation or release review.

Current structured evidence supported by the kit:

| Control | Evidence file | Schema |
| --- | --- | --- |
| `PLAT-BRPROT-015` | `.oss-policy-kit/evidence/branch-protection.json` | `reports/schema/evidence-branch-protection.schema.json` |
| `GH-PLAT-024` | `.oss-policy-kit/evidence/github-rulesets.json` | `reports/schema/evidence-github-rulesets.schema.json` |
| `GH-PLAT-025` | `.oss-policy-kit/evidence/github-environment-protection.json` | `reports/schema/evidence-github-environment-protection.schema.json` |
| `GH-PLAT-026` | `.oss-policy-kit/evidence/github-secret-scanning.json` | `reports/schema/evidence-github-secret-scanning.schema.json` |
| `AZ-PLAT-034` | `.oss-policy-kit/evidence/azure-branch-policies.json` | `reports/schema/evidence-azure-branch-policies.schema.json` |
| `AZ-PLAT-035` | `.oss-policy-kit/evidence/azure-pipeline-governance.json` | `reports/schema/evidence-azure-pipeline-governance.schema.json` |
| `AWS-CP-044` | `.oss-policy-kit/evidence/aws-codepipeline.json` | `reports/schema/evidence-aws-codepipeline.schema.json` |
| `AWS-CB-045` | `.oss-policy-kit/evidence/aws-codebuild-project.json` | `reports/schema/evidence-aws-codebuild-project.schema.json` |
| `AWS-SBOMART-058` | `.oss-policy-kit/evidence/aws-sbom-artifact.json` | `reports/schema/evidence-aws-sbom-artifact.schema.json` |
| `AWS-PROVART-059` | `.oss-policy-kit/evidence/aws-provenance-artifact.json` | `reports/schema/evidence-aws-provenance-artifact.schema.json` |
| `GOV-DISC-065` (v5.9.0) | `.oss-policy-kit/evidence/disclosure-policy.json` | `reports/schema/evidence-disclosure-policy.schema.json` |
| `SAST-ZIZMOR-066` (v5.9.0) | `.oss-policy-kit/evidence/sast/zizmor.sarif.json` | (raw SARIF 2.1.0; no kit-specific schema — parsed by the shared SARIF helper) |
| `SAST-POUTINE-067` (v5.9.0) | `.oss-policy-kit/evidence/sast/poutine.sarif.json` | (raw SARIF 2.1.0) |
| `SAST-OSV-068` (v5.9.0) | `.oss-policy-kit/evidence/sast/osv-scanner.sarif.json` | (raw SARIF 2.1.0) |
| `SAST-GITLEAKS-069` (v5.9.0) | `.oss-policy-kit/evidence/sast/gitleaks.sarif.json` | (raw SARIF 2.1.0; zero-tolerance — any finding blocks) |

### Branch protection evidence

For `PLAT-BRPROT-015`, the kit validates file structure and required flags, but it does **not** call the GitHub API.

Implications:

- broken or unreadable evidence degrades to `manual-review-required`
- missing required protections do not pass silently
- self-attested evidence remains lower-trust than live GitHub confirmation
- `github-release-hardening-1` can legitimately end with `pass` plus `manual-review-required` or `self-attested`

## SARIF-ingest adapters (v5.9.0)

Fase 4 introduced four SARIF-ingest adapters that read raw SARIF 2.1.0 dropped at `.oss-policy-kit/evidence/sast/<tool>.sarif.json`:

- **`SAST-ZIZMOR-066`** — zizmor (GitHub Actions AST analysis).
- **`SAST-POUTINE-067`** — poutine (GitHub Actions + GitLab CI).
- **`SAST-OSV-068`** — OSV-Scanner v2 (reachability-aware SCA).
- **`SAST-GITLEAKS-069`** — Gitleaks (secret leak detection; zero-tolerance — any finding fails).

All four share a single helper `_parse_sarif_findings` in `evaluators.py` and a generic adapter shell `_eval_sarif_adapter`. Adding another SARIF-emitting tool follows a one-line evaluator pattern; see ADR-001 for the scanner selection rationale and `docs/positioning.md` for the broader "compose, not replace" stance.

The SAST boundary module (`evaluators_sast.py`) closes around five controls: the four new SARIF adapters plus `SAST-SEMGREP-064` (which retains its kit-emitted JSON wrapper from v5.4.0 for backward compatibility).

## `emit-vex` subcommand (v5.9.0)

`oss-policy-kit emit-vex` reads the OSV-Scanner SARIF file consumed by `SAST-OSV-068` and emits a CycloneDX VEX 1.6 document. The v0.1 surface emits every distinct vulnerability ID (CVE / GHSA / OSV / RUSTSEC) with `analysis.state: in_triage`; the manufacturer fills the analysis post-hoc. Per-CVE waiver integration is planned for v5.9.x (see [`docs/decisions/adr-002-emit-vex-scope.md`](decisions/adr-002-emit-vex-scope.md) and [`docs/vex-emission.md`](vex-emission.md)).

The subcommand is intentionally narrow: it does not generate an SBOM (delegated to Syft / Trivy), does not verify the manufacturer's analysis (auditor's job), and does not cover non-OSV findings (zizmor / poutine / Gitleaks findings are policy patterns, not CVEs).

## CLI trust boundaries

- paths are resolved and validated before evaluation
- YAML parsing uses safe loading only
- the tool does not execute repository code
- report output reflects local evidence, optional supplemental inputs, and explicit evaluator limitations

## Known limitations

The kit cannot reliably prove:

- live GitHub branch protection or rulesets
- organization-level settings outside the clone
- runtime behavior of reusable workflows, composite actions, or complex expressions
- certification or compliance against a formal framework
- live AWS CodeBuild project settings or full CodePipeline definitions unless exported or evidenced locally

Workflow analysis is static. That is a deliberate tradeoff, not an implementation accident.
