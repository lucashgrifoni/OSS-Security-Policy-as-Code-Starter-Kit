# Signal-grade controls — audit and limitations

`assurance: signal` controls produce **directional** results from clone-visible heuristics: keyword matches in workflow YAML, structural patterns, or external scorecard references. A `pass` on a signal control means *a positive marker was observed*, not that *the control is implemented end-to-end*.

This page is the v5.0.0 audit decision record for every signal-grade control bundled with the kit. It exists so users can interpret a `pass` correctly and know what additional evidence to look for before treating the result as a release gate.

## How v5.0.0 reflects signal-grade limits in reports

Under `reports/1.0`, every signal-grade result projects through `oss_policy_kit.application.evidence_projection` with these guarantees:

- `evidence.source_type = "heuristic_signal"` (when the underlying method is `static`).
- `evidence.trust_level = "inferred"` — never `"verified"`, regardless of `confidence` text.
- `evidence.limitations` always includes a string explaining that the signal cannot exceed `inferred`.

These projection rules are runtime-enforced (see `tests/application/test_evidence_projection.py::test_signal_assurance_always_carries_limitation_text` and the trust-level invariants).

## Audit decisions

Each row is the v5.0.0 disposition. None of the controls below are deprecated or upgraded in v5.0.0 — the audit confirms they are honestly described as `signal` and the evidence model surfaces their limits. Future releases may upgrade specific controls to `evidence-backed` once a corresponding API-collected evidence schema lands.

| Control | Family | Decision | Expected evidence | Known false positives | Known false negatives |
|---|---|---|---|---|---|
| **`CI-LEAST-009`** | GitHub Actions | Keep `signal`. | `permissions:` block at workflow root with restrictive scope. | A `permissions: read-all` block is detected as "permissions present" but is not least-privilege. | A workflow that *only* sets `permissions:` per job (without root-level) may be missed. |
| **`SEC-CODEQL-010`** | SAST/code scanning | Keep `signal`. Cross-references Scorecard JSON when supplied. | A workflow file referencing `github/codeql-action`, `semgrep`, `bandit`, or equivalent. | Mentioning `codeql` in a comment or env name produces a positive without any actual scan step. | Custom SAST runners not in the keyword list will not be picked up. |
| **`GOV-DISC-013`** | Governance | Keep `signal`. | Discoverable repository description, topics, or `SECURITY.md` reference to a private channel. | Boilerplate `description:` text counts as positive. | Private vulnerability reporting enabled at GitHub level cannot be inferred from a clone. |
| **`GH-REL-021`** | Release hygiene | Keep `signal`. | Tag/release workflow with `gh release` or signed-tag posture. | Workflow that only drafts releases without provenance still counts. | Manually cut releases (no workflow) miss this signal. |
| **`GH-DEPLOY-022`** | Deployment identity | Keep `signal`. | Workflow with `environment:` block and identity providers (`id-token: write`). | An `environment:` declaration without protection rules counts as positive. | Inline reusable workflows that wrap deployment may hide this signal from regex matchers. |
| **`GH-PROV-023`** | Provenance | Keep `signal`. | Workflow referencing `slsa-framework/slsa-github-generator`, `actions/attest-build-provenance`, or sigstore tooling. | Generic `cosign sign` mentions can match without producing release attestations. | Bespoke provenance scripts that don't reference well-known generators are missed. |
| **`AZ-SEC-031`** | Azure SAST | Keep `signal`. | YAML pipeline with security-scanner task references. | Variable named `secScanEnabled` matches without invoking a scanner. | Self-hosted scanners invoked through scripts may go unmatched. |
| **`AZ-SCA-032`** | Azure SCA | Keep `signal`. | YAML referencing dependency-scanning tasks. | A commented-out task is matched. | Tasks gated behind variable templates may not be inspected. |
| **`AZ-SBOM-033`** | Azure SBOM | Keep `signal`. | YAML producing a CycloneDX/SPDX SBOM. | A `name: SBOM` step that does nothing useful matches. | SBOM produced by external CI service won't show in pipeline YAML. |
| **`AWS-SEC-039`** | AWS SAST | Keep `signal`. | `buildspec.yml` referencing SAST tools. | Echoing a tool's name in `buildspec` matches. | Tool invoked through a wrapper script lookup is missed. |
| **`AWS-SCA-040`** | AWS SCA | Keep `signal`. | `buildspec.yml` referencing dependency scanners. | Same false-positive shape as `AWS-SEC-039`. | Tools invoked through `pip-audit` aliases may be missed. |
| **`AWS-SBOM-041`** | AWS SBOM | Keep `signal`. | `buildspec.yml` producing SBOM artifact. | Generic `cyclonedx` mention without artifact upload still counts. | SBOM produced outside CodeBuild (e.g., post-build job) is missed. |
| **`AWS-PROV-043`** | AWS provenance | Keep `signal`. | `buildspec.yml` referencing in-toto attestations or signed artifacts. | Generic `attest` mention can match. | Provenance posted to S3 separately is missed. |
| **`SEC-SECRETS-050`** | Secret hygiene | Keep `signal`. | Pre-commit / CI integration of `gitleaks`, `trufflehog`, etc. | A README mention of "no secrets in repo" can match weak heuristics. | Native GitHub secret scanning is platform-side and not visible from a clone. |
| **`GH-MERGEQ-053`** | Merge queue | Keep `signal`. | Workflow conditional on `merge_group` event. | A repository with `merge_group` declared but never enabled at the platform level still matches. | Merge queue toggled at the GitHub Settings UI alone is invisible to a clone. |
| **`OSS-SCORECARD-001`** | OpenSSF Scorecard | Keep `signal`. | `--scorecard-json` supplemental file. | Stale Scorecard JSON still scores; freshness is not enforced for this control. | Repositories that don't publish Scorecard JSON locally surface as `not-evaluated` (not a false negative per se). |
| **`CONT-IMAGE-003`** | Container image | Keep `signal`. | `Dockerfile` content patterns or compose file references. | Comment-only mentions of `USER nonroot` count as positive. | Multi-stage builds where final stage is constructed dynamically can hide hardening. |
| **`BUILD-SBOM-QUAL-003`** | Build SBOM quality | Keep `signal`. | Presence of CycloneDX/SPDX SBOM with required fields. | A draft SBOM with placeholder components scores positive. | SBOMs produced by external systems and not committed are invisible. |

## Hard-gate handling

Hard-gate profiles (`github-level-3`, `github-release-hardening-3`, `aws-level-3`, `aws-release-hardening-3`, `azure-level-3`, `azure-release-hardening-3`) include a mix of deterministic, evidence-backed, and signal controls. v5.0.0 enforces:

- A signal-grade `pass` projects to `trust_level: inferred` even on a hard-gate profile.
- The `evidence.limitations` array on each result explicitly states the signal-cap rule.
- The runtime `_HARD_GATE_EVIDENCE_PROFILES` warning continues to fire when `.oss-policy-kit/evidence/` is missing or contains placeholders.

A `summary_by_status.fail == 0` result on a hard-gate profile is therefore not equivalent to "platform posture verified" when signal controls are present in the profile. The Markdown `Limitations` text and the v1 JSON `evidence.limitations` field are the load-bearing surface for that distinction.

## When signal controls should be upgraded

A signal control should be promoted to `evidence-backed` (or split) only when:

1. A bundled evidence JSON schema exists for the underlying posture.
2. A collector or scaffolder can produce that evidence reliably.
3. Stale and placeholder evidence is rejected by the evaluator.
4. Promotion to `verified` trust requires `attested_by` metadata or live API collection.

Until those four conditions hold, a control stays `signal` in the catalog. Misclassifying a heuristic match as deterministic proof is the failure mode this audit is designed to prevent.

## Where this is enforced in code

- Catalog: `src/oss_policy_kit/data/controls/catalog.yaml` (`assurance: signal`).
- Projection rules: `src/oss_policy_kit/application/evidence_projection.py` (`_source_type_from_result`, `_trust_level`, `_limitations`).
- Schema: `src/oss_policy_kit/data/schema/evaluation-report-v1.schema.json` (`results[].evidence.trust_level` enum).
- Tests: `tests/application/test_evidence_projection.py` (every signal × static combination has a regression test).
