# Profile maturity - deferred follow-ups

Items intentionally deferred in earlier documentation rounds. Several items below are **targeted for the v4.0.0 major** on this branch; treat user-facing guarantees as tied to **`CHANGELOG.md`** and the eventual **`v4.0.0` tag**, not an implied PyPI publication date.

## CLI and listing

- *(Targeted for v4.0.0)* `profiles` flags `--only-extreme`, `--advisory-only`, `--family`, plus JSON `profile-list/v2` posture metadata.
- New mandatory fields on bundled `profile.yaml` beyond what the loader already tolerates.

## Reports and scoring

- *(Targeted for v4.0.0)* JSON report contract **`reports/0.3`** with `summary_by_gate_role` and `gate_execution_model` (see **`docs/reports-contract-v0.3.md`**).
- Score aggregation or merged role of gate beyond current `fail-on` mapping.

## Policy data

- New controls to represent live-only posture where the kit today documents an honest limit.
- Changing bundled `controls:` lists or turning `github-aws-level-2` / `github-azure-level-2` into hard-gates.

## Evidence

- Synthetic evidence that would require inventing unsupported JSON fields or declaring PASS without schema-backed content.

## Repository hygiene (resolved for the example fixture)

- The root `.gitignore` still ignores `.oss-policy-kit/` **globally**, except under **`examples/hardened-repo/.oss-policy-kit/`** via negated patterns scoped to **`evidence/`**. A nested **`examples/hardened-repo/.oss-policy-kit/.gitignore`** ignores everything in that directory except `.gitignore` itself and **`evidence/**`**, so only the synthetic JSON bundle is meant to be committed. Other paths named `.oss-policy-kit/` remain ignored.

Revisit the sections above only when the product owner accepts the corresponding scope expansion.

## Future considerations (post-v5.0.0, not in current scope)

These are conceptual follow-ups identified during the 2026-05-06 raio-x. They are **not** scheduled and **not** part of v5.0.0. They are listed here to make the boundary between current behavior and possible future work explicit.

- Renaming hybrid profiles (`github-aws-level-2`, `github-azure-level-2`) to make their advisory-only intent unambiguous in the name. This would be a breaking change requiring a deprecation window.
- Automatic verification that evidence JSON files have been filled (vs. still containing template placeholders). Today this is surfaced by `evaluate` as `manual-review-required`; making it a precondition would require either a new control or a new flag.
- A `--strict` or `--require-filled-evidence` flag for `recommend-profile` so it suppresses `release-hardening-*` suggestions when evidence files appear unfilled. The current rationale text now warns about this, but does not enforce it.
- Closing the AWS / Azure collector parity gap with the GitHub collector (additional `collect-evidence` endpoints for richer attestations).
- Runtime enforcement of `posture: advisory` so `--fail-on fail` paired with an advisory profile emits an explicit warning instead of silently honoring the threshold.
- A regenerable `docs/controls-catalog.md` script (currently the page is regenerated manually when the catalog changes).

## `emit-vex` subcommand v0.1 (shipped v5.9.0) — extensions planned for v5.9.x

The v0.1 of `emit-vex` ships in v5.9.0; see [`../vex-emission.md`](../vex-emission.md). It emits every OSV-Scanner finding as `analysis.state: in_triage` — the manufacturer fills the analysis post-hoc.

Planned additive extensions for v5.9.x (non-breaking):

1. **Per-CVE waivers** — extend `waivers/waivers.yaml` schema with `vulnerability_ids: [...]`. `emit-vex` then auto-populates `analysis.state: not_affected` plus a CycloneDX `analysis.justification` enum value derived from the waiver text.
2. **`--validate`** — round-trip output through CycloneDX 1.6 JSON Schema before exit (currently the operator runs `cyclonedx validate` manually).
3. **`--include-references`** — embed advisory URLs (`osv.dev`, `github.com/advisories/...`) where OSV-Scanner provides them in SARIF `helpUri` / `properties`.

Tracked in [`../decisions/adr-002-emit-vex-scope.md`](../decisions/adr-002-emit-vex-scope.md).

## GitLab CI support (`gitlab-level-1` profile, planned)

A `gitlab-level-1` profile aligned with the existing GitHub / Azure / AWS ladders is planned but **not yet implementable** with the current evaluator infrastructure. Existing CI controls (`CI-WF-005`, `CI-PERM-006`, `CI-DANGER-007`, `CI-PIN-008`, `CI-LEAST-009`, `CI-WFCALLSHA-055`) parse GitHub Actions YAML specifically — they cannot meaningfully evaluate a `.gitlab-ci.yml` without a new parser.

The work split for landing GitLab support honestly:

1. New `.gitlab-ci.yml` parser in `oss_policy_kit/infrastructure/` (mirrors `workflow_parser.py` / `azure_pipeline_parser.py`).
2. New GitLab-prefixed controls (`GL-CI-*` family) for permissions, includes, image pinning, secret handling, runner tags, and merge-request rules.
3. The composite parser plus the new controls populate a real `gitlab-level-1` bundled profile.
4. Tests parallel to `tests/cli/test_evaluate_*.py` for the new platform.

Until that infrastructure exists, the kit will **not** ship a placeholder `gitlab-level-1` profile composed from GitHub-only controls — that would be misleading at the assurance-grade level the kit promises.

## GitHub native security platform features (GA-dependent, planned)

The GitHub 2026 Security Roadmap announced four native platform features that overlap with controls this kit currently expresses indirectly. Implementation is **deferred until GitHub ships GA** of each feature — building against preview/beta APIs would force rewrites once the final surface lands.

- **`GH-EGRESS-001`** — Native Layer-7 egress firewall (operates outside the runner VM). The kit currently has no direct control for this; `signal`-grade detection of [Harden-Runner](https://github.com/step-security/harden-runner) usage is the interim recommendation expressed via documentation, not a control. When the native feature reaches GA, this control will read the workflow-level egress allowlist and surface it as `evidence-backed` for hosted runners.
- **`GH-SECRETS-SCOPED-001`** — Scoped secrets. Today the kit covers token-permissions breadth via `CI-PERM-006`, `CI-LEAST-009`, and `GH-WF-020`; scoped secrets is a separate concept (which secrets are reachable from a job) that requires the native scoping feature to be observable from the workflow YAML.
- **`GH-WF-LOCKED-001`** — Workflow dependency locking. Complements `CI-PIN-008` and `CI-WFCALLSHA-055` by adding lockfile-style guarantees beyond SHA pinning. Will be introduced once the lockfile format is published.

The kit will register these as `deterministic` or `evidence-backed` (not `signal`) once the underlying GitHub features are GA, to preserve the project's stance that new controls should not inflate maturity with directional-only signals.
