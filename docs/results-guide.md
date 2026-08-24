# How To Interpret Results

Each control in an evaluation report resolves to one of these nine states, listed in the order the
CLI summary prints them. The third column is how the state is projected into the `reports/2.0`
JSON.

| Status | Meaning | In `reports/2.0` |
| --- | --- | --- |
| `pass` | A positive local signal was observed | `PASS` |
| `attested` | A pass anchored on a verification record the kit read and checked, not on a signal it inferred | `ATTESTED` |
| `fail` | A required signal was missing or a high-signal problem was detected | `FAIL` |
| `manual-review-required` | The control cannot be safely confirmed from a clone alone; review manually | `UNKNOWN` + `reason: manual-review-required` |
| `self-attested` | Local evidence exists, but trust still depends on maintainer honesty or platform confirmation | `SELF_ATTESTED` |
| `not-evaluated` | The control was handed no input to judge, so no verdict was attempted | `UNKNOWN` + `reason: not-evaluated` |
| `waived` | A documented exception overrode a non-pass outcome | `UNKNOWN` + `reason: waived` |
| `not-observable` | The control exists conceptually but is not locally observable | `UNKNOWN` + `reason: not-observable-in-clone` |
| `not-applicable` | The control does not apply to the evaluated repository shape | `NOT_APPLICABLE` |

Five of the nine collapse into `UNKNOWN`, and the `reason` sub-field is the only thing that tells
them apart. That collapse is the one thing to know before wiring a dashboard, because the terminal
and `evaluation-report.md` count the nine states while `summary_by_status` in
`evaluation-report.json` counts the six. One run of `github-level-2` prints

```
Outcome: pass=23, fail=2, not-evaluated=1, not-applicable=4
```

and writes

```json
"summary_by_status": { "FAIL": 2, "NOT_APPLICABLE": 4, "PASS": 23, "UNKNOWN": 1 }
```

So anything branching on `UNKNOWN` alone reads "nobody passed us a Scorecard file" and "branch
protection needs a human" as the same event. Branch on `reason`.

`fail` and `manual-review-required` answer different questions, and the distinction decides what
you do next. `fail` is a statement about **your repository**: a control is not satisfied.
`manual-review-required` is a statement about the **evidence**: the kit could not establish an
answer either way.

So when an evidence file is present but does not match its schema — an outdated collector, a
hand-edit, a payload from another tool — every control answers `manual-review-required`, on every
platform, with a reason naming the schema. It would be wrong to call that `fail`: the kit did not
find the control unsatisfied, it failed to read the document that would say. See
[ADR-045](decisions/adr-045-schema-invalid-evidence-is-manual-review-everywhere.md).

If unreadable evidence should stop a build in your context, that is a gate policy rather than a
control verdict: `--fail-on degraded` exits 1 on `fail` **or** `manual-review-required`.

A related rule applies one level down, to individual **source files a scanner could not parse**.
When `scan-iac`, `scan-bicep`, `scan-cfn`, `scan-pulumi` or `scan-k8s` records entries in
`diagnostics.parse_errors` — a file saved as UTF-16 is the common cause — the family's controls
behave like this:

| What the scan managed | Verdict | Why |
|---|---|---|
| **Nothing** parsed, at least one file failed | `manual-review-required` | `not-applicable` would say *"this repository has no Terraform"*, and a decoding failure is not evidence for that. "Nothing here" and "nothing legible" are different claims. |
| Something parsed, no findings | `pass`, **and the reason names the skipped files** | The result was always true — it just never said what it covered. |
| Something parsed, a finding | `fail`, unchanged | Unread sources can only *add* violations, so a real finding stays in `--fail-on fail`. |

The middle row is deliberate rather than lenient. `scan-k8s` globs `**/*.yaml` across the whole
tree, so on a repository that keeps a malformed YAML fixture on purpose — which is ordinary —
withdrawing the verdict would turn every Kubernetes control `UNKNOWN` for a file that was never
a manifest. So an incomplete *message* gets a complete message, not a withdrawn verdict.

That has a consequence worth stating plainly: **no exit-code gate fires on the middle row.**
`--fail-on degraded` acts on `fail` and `manual-review-required`, and a `pass` is neither — so
it stops a build for the top row and does nothing for the middle one. If a skipped file must
stop your pipeline in every case, gate on the scanner instead: `scan-*` prints how many files
failed to parse, and `diagnostics.parse_errors` in the evidence file is the machine-readable
form.

### `not-evaluated` is not a verdict either

`not-evaluated` and `manual-review-required` are both `UNKNOWN` on the wire, and the `reason` is
the whole difference:

- `not-evaluated` — **no input**. The kit was never handed the thing the control reads.
- `manual-review-required` — **input, no answer**. There was a document and the kit could not
  settle the question from it, or the fact does not live in a clone at all.

It appears on ordinary runs, with stock bundled profiles and no flags:

- `OSS-SCORECARD-001` whenever `--scorecard-json` is not passed, on every bundled profile that
  carries it: `github-level-2`, `github-level-3`, `github-release-hardening-2`,
  `github-release-hardening-3`, `s2c2f-l1-1`, `s2c2f-l2-1`, `s2c2f-l3-1`
- every evidence-backed control reading a `scaffold-evidence` template that still holds `REPLACE_ME`
- `PLAT-BRPROT-015`, `GH-PLAT-024`/`025`/`026`, `GH-IMMUTREL-070` and `ORG-ACTPOL-071` when their
  evidence file does not exist yet

Which of the two you get for an absent file is per-control, not a rule: `ORG-MFA-001` and
`SAST-SEMGREP-064` answer `manual-review-required` where the controls above answer
`not-evaluated`. Read the control's message rather than assuming.

Two consequences surprise people reading a summary:

- **It trips no gate.** The exit code is decided by the `fail` and `manual-review-required` counts
  alone, so `--fail-on fail` and `--fail-on degraded` both let `not-evaluated` through. A run whose
  only non-`pass` outcomes are `not-evaluated` exits 0 under every policy.
- **It is excluded from the weighted score**, exactly like `not-applicable`. The percentage
  describes the controls the kit could reach, not the whole profile.

The fix is always to supply the input — pass `--scorecard-json`, run `collect-evidence`, or fill
the template — not to switch to a profile that does not ask for it.

### When you see `attested`

`attested` is the strongest positive state: the control's pass is anchored on a verification
record with transparency-log inclusion confirmed and a `verified_at` inside the 90-day freshness
window. Two bundled controls emit it — `PROV-VERIFY-061`, from
`.oss-policy-kit/evidence/<platform>-provenance-artifact.json`, and `GH-IMMUTREL-070`, from
`github-release-immutability.json`.

Be precise about what that buys. CI ran `gh attestation verify` or `cosign verify-bundle` and
wrote the outcome into the evidence file; the kit validated **that record**. It did not re-verify
the signature. The check is fail-closed, so any gap in the record — a missing field,
`transparency_log_inclusion: false`, a `verified_at` older than 90 days — yields `pass`, `fail` or
`manual-review-required` depending on the control and the gap, and never `attested`.

There is nothing to do about an `attested` control. It scores as a pass, so a gate that only
understands `PASS` still behaves correctly. `--no-enable-attested` reports those controls as plain
`pass` instead; the flag has been on by default since v8.0.0.

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
- `github-release-hardening-1` adds `PLAT-BRPROT-015` and `GOV-EVIDFRESH-054` (16 controls total). Branch protection is enforced on GitHub, not in the clone, so a strong local repository lands on `not-evaluated` for that control until `.oss-policy-kit/evidence/branch-protection.json` exists. With the file it reads `pass` or `fail` on what the file records — unless the file is a template that still holds `REPLACE_ME`, which stays `not-evaluated`, or the kit cannot use the document at all (unreadable, invalid JSON, a root that is not an object, or a schema violation), which is `manual-review-required`.

That behavior is intentional. It is the tool being honest, not a defect.

## GitHub Profile Ladder

- `github-level-1`: pragmatic baseline with clone-visible governance and CI hygiene.
- `github-level-2`: adds stricter workflow hardening (`GH-WF-018` to `GH-REL-021`).
- `github-level-3`: platform-evidence and attested-provenance track. It **adds** `GH-PLAT-024`/`025`/`026`, `PROV-VERIFY-061`, `ORG-MFA-001`, `GOV-EVIDFRESH-054`, `AUDIT-STREAM-060`, `BUILD-SBOM-QUAL-003`, `CI-WFCALLSHA-055` and `SEC-FUZZ-001`, and it **drops** `GH-DEPLOY-022`, `GH-PROV-023` and `SEC-SECRETS-050` — those three live in `github-level-2`. Level 3 is not a superset of level 2: it trades the level-2 provenance control for the attested `PROV-VERIFY-061`. Run both if you want the union.
- `github-release-hardening-1`: level-1 + branch-protection evidence/manual-review (`PLAT-BRPROT-015`) + evidence-freshness (`GOV-EVIDFRESH-054`).
- `github-release-hardening-2`: level-2 + platform evidence controls (`GH-PLAT-024..026`).
- `github-release-hardening-3`: level-3 + platform evidence controls (`PLAT-BRPROT-015`, `GH-PLAT-024..026`).

## When `self-attested` Is Normal

`self-attested` records a claim the kit cannot check from the clone. It scores as a pass and it
never elevates a `fail`. On stock profiles:

- `ORG-MFA-001` when `.oss-policy-kit/evidence/org-mfa-posture.json` was written by hand. The same
  file produced by `collect-evidence` is API-backed and reads `pass` instead — the state is about
  how the evidence was obtained, not about what it says.
- the Azure and AWS platform-evidence controls (`AZ-*`, `AWS-*`), which are maintainer-written JSON
  asserting a platform setting
- `GOV-DISC-013`, `CRA-ART14-COORD-002` and `GOV-DISC-065` under `--use-insights-evidence`, when the
  target's `SECURITY-INSIGHTS.yml` declares a vulnerability-reporting channel (ADR-033)

## When a non-`pass` Is The Honest Answer

- `GOV-WAIV-014` reads **`manual-review-required`** when no versioned in-repo waiver policy file is
  present (optional governance, but explicitly surfaced rather than skipped)
- `PLAT-BRPROT-015` reads **`not-evaluated`** until platform evidence exists, then `pass` or `fail`
  on what that evidence records, or `manual-review-required` when the file cannot be read.
  Confirming branch protection in GitHub is what produces the file; it is not a separate state.

## Evidence templates vs. real evidence

`scaffold-evidence` writes JSON templates with `REPLACE_ME` placeholder values. `evaluate` reads
them as `not-evaluated` — never as `pass`, and never as `self-attested`. Every control that reads
one lands there, and the control's message names the placeholder token it found. This is
intentional: the kit cannot distinguish a half-edited template from a completed attestation
without metadata, so it declines to score either. Either fill the JSONs by hand, or use
`collect-evidence` for API-backed values that carry attestation metadata. A control that goes back
to `not-evaluated` after you thought you had filled its file means a placeholder survived
somewhere in it.

`recommend-profile` may also suggest a `release-hardening-*` profile when it detects evidence template files under `.oss-policy-kit/evidence/`, even before those templates have been filled. Recommended flow:

1. `scaffold-evidence --target . --platform <github|azure|aws>`
2. Edit the generated JSON files to replace placeholder values.
3. Re-run `recommend-profile --target .` (the rationale is unchanged, but you can now act on the suggestion confidently).
4. `evaluate` with the suggested profile.

### SAST evidence (`scan-sast` + `SAST-SEMGREP-064`)

SAST evidence works the same way, with one difference in the missing-file case. `scan-sast` writes `.oss-policy-kit/evidence/sast-semgrep.json` with a status of `ok`, `not_available`, `timeout`, or `error`. The `SAST-SEMGREP-064` evaluator (experimental, evidence-backed, opt-in via external profile) consumes this file and:

- reports `pass` when Semgrep ran cleanly with no `HIGH`/`CRITICAL` findings;
- reports `fail` when there is at least one `HIGH` or `CRITICAL`;
- reports `manual-review-required` — not `not-evaluated` — when the evidence file is missing, when Semgrep was not installed (`status: not_available`), or when the run timed out / errored. So an absent SAST evidence file trips `--fail-on degraded`, where an absent platform-evidence file does not.

Missing Semgrep is handled as a documented gap, not a crash. To populate real findings, install Semgrep (`pip install semgrep`, requires Python 3.12+) and re-run `scan-sast`. See `docs/cli-reference.md` for the opt-in profile template and end-to-end flow.

## Automation Limits

Local evaluation can inspect only what exists in the working tree. It cannot reliably prove:

- GitHub branch protection or rulesets
- GitHub Advanced Security feature enablement
- organization-level policies outside the clone
- runtime behavior of reusable workflows, composite actions, or expression-heavy logic

For those areas, the kit intentionally uses:

- `not-evaluated` while the platform evidence file is absent or still a template
- `manual-review-required` where the evidence exists but cannot be read, or the question cannot be
  settled from a clone at all
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

Top-level keys in the report contract (`reports/2.0`):

- `schema_version`: the report wire-contract URL (ends in `/reports/2.0`).
- `contract_version`: the contract id string, `"reports/2.0"`.
- `generated_at`: UTC timestamp for report generation.
- `kit_version`: OSS Policy Kit version used in evaluation.
- `target_path`: evaluated repository path (basename by default; full path with `--include-absolute-path`).
- `profile`: object describing the selected profile (`id`, `title`, `family`, `level`, `posture`, `is_release_track`, `recommended_gate`).
- `summary_by_status`: aggregate counts keyed by the six wire states (`PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`, `ATTESTED`, `SELF_ATTESTED`) — not the nine states the terminal prints. See the status table at the top of this page for which collapses into which.
- `controls_total`: total number of evaluated controls.
- `controls`: per-control result array — each entry carries `id`, `title`, `state`, `assurance`, `message`, `remediation`, the projected `evidence` object, and a stable `finding_id`.
- `results_digest`: `sha256:` fingerprint over canonical control fields, stable across runs.
- `operational_warnings`: non-blocking warnings surfaced during evaluation.
- `scorecard`: summary of supplied OpenSSF Scorecard JSON and its (never grade-elevating) influence, when provided.
- `external_waiver_path`: path to an externally supplied `--waivers` file, when used.
- `action_insights`: suggested next actions derived from result patterns.
- `live_collection`: metadata about API-backed evidence collection, when available.
- `weighted_score`: risk-adjusted scoring block (`earned`, `possible`, `percent`).

The full contract is documented in [reports-contract-v2.0.md](reports-contract-v2.0.md). The removed legacy contracts (`reports/1.0`, `reports/0.3`) are kept only as historical references.

## Examples And Fixtures

- `examples/hardened-repo` demonstrates a strong baseline and should pass `github-level-1`
- `examples/vulnerable-repo` demonstrates obvious gaps and is useful for testing CI gates
- `tests/fixtures/repositories/` contains edge-case repository shapes used by the test suite
