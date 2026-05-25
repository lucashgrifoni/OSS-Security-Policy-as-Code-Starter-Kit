# Policy data lifecycle

Bundled controls and profiles live under `src/oss_policy_kit/data/`. Lifecycle markers are part of the catalog contract: see `CHANGELOG.md` for when they were introduced. From **v3.0.1**, each control also carries an **`assurance`** label (`deterministic`, `signal`, `evidence-backed`); **v3.1.0** tightened several evaluators so outcomes and **confidence** better match that taxonomy. Every control in `catalog.yaml` carries an explicit `lifecycle` label. This label is surfaced
in evaluation reports (JSON `lifecycle` field and Markdown detail rows) so adopters can make
informed decisions about which controls to gate on.

## Lifecycle states

| State | Meaning |
| --- | --- |
| `stable` | Intended stable semantics for the current major.minor kit line. Safe to use in strict CI gates when pinned to a kit version. |
| `experimental` | Semantics may change between minor releases. Do not gate strict CI pipelines on experimental controls without pinning the exact kit version. |
| `deprecated` | Retained for compatibility. Evaluator returns `NOT_EVALUATED` — no PASS/FAIL logic runs. Remove from any custom profile before the next major release. |

## Current catalog summary

As of **v6.4.0**, the bundled catalog contains **212** controls: **70** are `lifecycle: stable` and **142** are `lifecycle: experimental`. There are no `deprecated` controls in the current catalog.

The large experimental share reflects the families added across v6.0.0–v6.4.0 (AI/LLM, EU AI Act, `WORM-*`, MCP, OWASP Agentic ASI, EU CRA, SLSA Source, and GitLab parity). Experimental semantics may change between minor releases, so pin the exact kit version before gating a strict CI pipeline on them. The two YAML-heuristic controls below were carried as **deprecated** through **v3.x** and **removed** as part of the **v4.0.0** preparation.

### Removed controls (historical — targeted for **v4.0.0**)

These IDs **do not exist** in `catalog.yaml` on the **v4.0.0** preparation branch. External profiles that reference them **fail at load time** — see **`docs/v4.0.0-migration-guide.md`**.

| ID | Title | Why removed | Replacement |
| --- | --- | --- | --- |
| `SEC-AUDIT-016` | Dependency vulnerability scan (pip-audit or SCA) in CI | Keyword detection in workflow YAML cannot prove that scans executed on real dependency graphs, enforced thresholds, or produced actionable results. | CI execution logs, SARIF gates, or platform-native dependency insights; map to **`SEC-CODEQL-010`**, **`SEC-SECRETS-050`**, **`DEP-UPDATE-001`**, **`BUILD-SBOM-QUAL-003`** as described in the migration guide. |
| `CI-SBOM-017` | SBOM generation in release or package workflow | Keyword detection does not validate SBOM format, completeness, signing, or linkage to released artifacts. | **`BUILD-SBOM-QUAL-003`**, **`GH-PROV-023`**, **`AWS-SBOMART-058`**, **`AZ-ARTSBOM-058`**, **`AWS-PROVART-059`**, **`AZ-ARTPRV-059`** depending on platform. |

## Assurance classification

In addition to lifecycle, every control carries an `assurance` label that describes the strength of the proof method:

| Assurance | Meaning |
| --- | --- |
| `deterministic` | Strong local proof via filesystem checks or structural YAML/JSON parsing. High-confidence PASS/FAIL with no platform API calls required. |
| `signal` | Heuristic or keyword-based detection in repository files. PASS means the signal is present; it does not verify execution or configuration correctness. Suitable for advisory profiles. |
| `evidence-backed` | Requires validated `.oss-policy-kit/evidence` JSON produced by `collect-evidence` or manual attestation. PASS/FAIL depends on the evidence file content and schema validation. |

## Assurance progression history

| Release | Change |
| --- | --- |
| v3.0.1 | `assurance` field introduced for all controls. |
| v3.1.0 | Evaluator confidence and `operational_warnings` tightened to match assurance labels. |
| Unreleased / post-v3.1.0 | Further assurance refinements (evaluator confidence, structural YAML coverage, lifecycle for specific controls) ship in tagged releases; see **`CHANGELOG.md`** for the authoritative record rather than assuming a future version number here. |

## Changelog discipline for policy data

Control or profile changes that alter evaluation outcomes must be reflected in `CHANGELOG.md`
with a note describing:

- which control IDs are affected
- what the semantic change is (new control, outcome behaviour, confidence, remediation wording)
- whether the change is backward-compatible (new optional control) or breaking (removed control,
  changed pass/fail outcome for an existing control)

## Compatibility guidance for adopters

- Pin a specific `oss-policy-kit` version in your CI, whether you install from a GitHub Release wheel
  or a package index you control, to prevent silent evaluation drift when the kit is updated.
- Treat `signal` controls as advisory: review their output but do not fail pipelines on
  them in isolation — combine with `evidence-backed` controls for hard-gate use.
- When a control is marked `deprecated`, remove it from any custom profile. The evaluator will
  return `NOT_EVALUATED` rather than PASS/FAIL, which may affect weighted scores in reports.
- Golden-fixture tests (like those in `tests/application/test_report_regression.py`) are the
  recommended mechanism for detecting unintentional semantic drift in your own fork or downstream
  policy pack.
