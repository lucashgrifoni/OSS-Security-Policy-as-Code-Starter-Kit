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
