# How To Interpret Results

Each control in an evaluation report resolves to one of these states:

| Status | Meaning |
| --- | --- |
| `pass` | A positive local signal was observed |
| `fail` | A required signal was missing or a high-signal problem was detected |
| `manual-review-required` | The control cannot be safely confirmed from a clone alone; review manually |
| `self-attested` | Local evidence exists, but trust still depends on maintainer honesty or platform confirmation |
| `not-observable` | The control exists conceptually but is not locally observable |
| `not-applicable` | The control does not apply to the evaluated repository shape |
| `waived` | A documented exception overrode a non-pass outcome |

Reports include:

- evidence sources
- confidence
- reason
- remediation text
- waiver metadata when applicable

## What The Kit Can Observe Locally

- tracked governance files
- workflow YAML structure and static content
- optional local evidence files
- optional waiver registry
- optional Scorecard JSON used as supplemental evidence

## What The Kit Cannot Prove From A Clone Alone

- live GitHub branch protection or rulesets
- organization-level policies outside the clone
- runtime behavior of reusable workflows or complex expressions
- compliance or certification against a formal framework

## `all-pass` On `github-level-1` vs `github-release-hardening-1`

- `github-level-1` currently evaluates 14 active controls. `all-pass` means fourteen `pass` outcomes for that profile on the current revision.
- `github-release-hardening-1` adds `PLAT-BRPROT-015`. Branch protection is enforced on GitHub, not in the clone, so a strong local repository can still end with `pass` plus `manual-review-required` or `self-attested` for that control.

That behavior is intentional. It is the tool being honest, not a defect.

## GitHub Profile Ladder

- `github-level-1`: pragmatic baseline with clone-visible governance and CI hygiene.
- `github-level-2`: adds stricter workflow hardening (`GH-WF-018` to `GH-REL-021`).
- `github-level-3`: adds strict deployment identity and provenance expectations (`GH-DEPLOY-022`, `GH-PROV-023`).
- `github-release-hardening-1`: level-1 + branch-protection evidence/manual-review.
- `github-release-hardening-2`: level-2 + platform evidence controls (`GH-PLAT-024..026`).
- `github-release-hardening-3`: level-3 + platform evidence controls (`PLAT-BRPROT-015`, `GH-PLAT-024..026`).

## When `self-attested` Is Normal

Examples:

- `GOV-WAIV-014` as **`manual-review-required`** when no versioned in-repo waiver policy file is present (optional governance, but explicitly surfaced)
- `PLAT-BRPROT-015` when local evidence JSON exists but platform truth still needs confirmation in GitHub

## Evidence templates vs. real evidence

`scaffold-evidence` writes JSON templates with placeholder values. `evaluate` will see them as `self-attested` (or `manual-review-required` when fields are empty) — not as `pass`. This is intentional: the kit cannot distinguish a half-edited template from a completed attestation without metadata. Either fill the JSONs by hand, or use `collect-evidence` for API-backed values that carry attestation metadata.

`recommend-profile` may also suggest a `release-hardening-*` profile when it detects evidence template files under `.oss-policy-kit/evidence/`, even before those templates have been filled. Running `evaluate` against unfilled templates will surface `manual-review-required` for evidence-backed controls. Recommended flow:

1. `scaffold-evidence --target . --platform <github|azure|aws>`
2. Edit the generated JSON files to replace placeholder values.
3. Re-run `recommend-profile --target .` (the rationale is unchanged, but you can now act on the suggestion confidently).
4. `evaluate` with the suggested profile.

### SAST evidence (`scan-sast` + `SAST-SEMGREP-064`)

The same pattern applies to SAST evidence introduced in v5.4.0. `scan-sast` writes `.oss-policy-kit/evidence/sast-semgrep.json` with a status of `ok`, `not_available`, `timeout`, or `error`. The `SAST-SEMGREP-064` evaluator (experimental, evidence-backed, opt-in via external profile) consumes this file and:

- reports `pass` when Semgrep ran cleanly with no `HIGH`/`CRITICAL` findings;
- reports `fail` when there is at least one `HIGH` or `CRITICAL`;
- reports `manual-review-required` when the evidence file is missing, when Semgrep was not installed (`status: not_available`), or when the run timed out / errored.

Missing Semgrep is handled as a documented gap, not a crash. To populate real findings, install Semgrep (`pip install semgrep`, requires Python 3.12+) and re-run `scan-sast`. See `docs/cli-reference.md` for the opt-in profile template and end-to-end flow.

## Automation Limits

Local evaluation can inspect only what exists in the working tree. It cannot reliably prove:

- GitHub branch protection or rulesets
- GitHub Advanced Security feature enablement
- organization-level policies outside the clone
- runtime behavior of reusable workflows, composite actions, or expression-heavy logic

For those areas, the kit intentionally uses:

- `manual-review-required`
- optional `self-attested` evidence
- optional supplemental context such as Scorecard JSON

## Applicability

This kit evaluates OSS repository posture and clone-visible CI/CD hygiene from a local clone.

It is a good fit for repositories that want:

- explicit governance
- review ownership
- CI hygiene
- release evidence

It is not a full application security assessment.

A generic internal app, lab, or service without `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, GitHub workflows, or changelog artifacts will often show many failures by design. That means OSS-style repository evidence is missing. It does not mean the runtime system is comprehensively insecure.

Use the results to improve:

- repository hygiene
- PR and CI posture
- evidence collection
- release preparation

Do not use the results as a substitute for:

- threat modeling
- secure code review
- platform configuration review
- cloud or infrastructure assessment
- penetration testing

## Report JSON schema

Top-level keys in the current report contract:

- `schema_version`: identifies the report wire contract URL (`reports/0.1`, `0.2`, or `0.3`, or `1.0`).
- `generated_at`: UTC timestamp for report generation.
- `kit_version`: OSS Policy Kit version used in evaluation.
- `target_path`: absolute evaluated repository path.
- `profile_id`: bundled or custom profile id used in the run.
- `profile_title`: human title of the selected profile.
- `summary_by_status`: aggregate counts by status value (`pass`, `fail`, etc.).
- `results`: per-control result array (**controls live under `results`, not under `controls`**).
- `operational_warnings`: non-blocking warnings surfaced during evaluation.
- `scorecard_path`: resolved path to Scorecard JSON when provided (else null).
- `scorecard_supplemental`: summary of scorecard influence on outcomes (else null).
- `external_waiver_path`: path to externally supplied `--waivers` file (else null).
- `action_insights`: suggested next actions derived from result patterns.
- `live_collection`: metadata about API-backed evidence collection when available (else null).
- `weighted_score`: risk-adjusted scoring block (`earned`, `possible`, `percent`).
- `summary_by_gate_role`: `reports/0.3` gate-role aggregation for CI semantics.
- `gate_execution_model`: `reports/0.3` documentation object for `--fail-on` mapping.

For the full v1.0 contract details see [reports-contract-v1.0.md](reports-contract-v1.0.md); the v0.3 wire shape stays documented at [reports-contract-v0.3.md](reports-contract-v0.3.md).

## Examples And Fixtures

- `examples/hardened-repo` demonstrates a strong baseline and should pass `github-level-1`
- `examples/vulnerable-repo` demonstrates obvious gaps and is useful for testing CI gates
- `tests/fixtures/repositories/` contains edge-case repository shapes used by the test suite
