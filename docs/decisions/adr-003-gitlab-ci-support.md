# ADR-003 — GitLab CI support: parser, controls, profile

- **Status**: accepted; **initial 6-control subset shipped in v5.9.0** (`GL-PIPE-001..006` + `gitlab-level-1` profile + `gitlab_ci_parser` infrastructure). Remaining 6 controls and the `-level-2` / `-level-3` ladder profiles deferred to subsequent minor releases.
- **Date**: 2026-05-16
- **Context window**: v5.9.0 (Fase 4 closure) → v5.10 / v5.11 planning
- **Related**: ADR-001 (SCA scanner choice — `SAST-POUTINE-067` already supports GitLab CI pipelines via SARIF ingestion); `docs/profiles/deferred-followups.md` "GitLab CI support" entry

## Context

The kit's `STATUS-2026-05-11.md` Fase 4 plan listed `F4-04 GitLab CI baseline (gitlab-level-1)`. v5.9.0 ships everything else in Fase 4 (ADRs, SARIF adapters, CRA reporting profile, emit-vex, pre-commit hooks, etc.) but **deliberately omits a fake `gitlab-level-1`** built from GitHub-only controls. The current evaluators (`CI-WF-005`, `CI-PERM-006`, `CI-DANGER-007`, `CI-PIN-008`, `CI-LEAST-009`, `CI-WFCALLSHA-055`) parse GitHub Actions YAML — they cannot meaningfully evaluate a `.gitlab-ci.yml` without a new parser.

`SAST-POUTINE-067` (v5.9.0) does cover GitLab CI when an adopter runs poutine and supplies its SARIF — but that is *scanner-output ingest*, not the kit's own parse. A true `gitlab-level-1` profile needs native controls that read `.gitlab-ci.yml` structure.

## Decision

Implement GitLab CI support across four artifacts in a dedicated session:

### 1. New infrastructure module — `src/oss_policy_kit/infrastructure/gitlab_ci_parser.py`

Mirrors `workflow_parser.py` (GitHub Actions) and `azure_pipeline_parser.py` (Azure DevOps). Public types:

```python
@dataclass(slots=True)
class GitLabCiAnalysis:
    """Aggregated signals from a .gitlab-ci.yml plus its includes."""
    pipeline_paths: list[Path]
    includes_remote: list[tuple[Path, str]]            # includes referencing remote YAML (supply-chain risk)
    image_refs_unpinned: list[tuple[Path, str]]        # image: ubuntu (no tag/digest)
    image_refs_pinned: list[tuple[Path, str]]          # image: ubuntu@sha256:...
    script_uses_curl_pipe_shell: list[Path]            # script: curl ... | sh
    jobs_with_id_tokens: list[Path]                    # OIDC for cloud auth
    jobs_with_inherit_secrets: list[Path]              # inherit: secrets: true
    jobs_with_tag_self_hosted: list[Path]              # tags: [self-hosted]
    jobs_with_rules_only_or_except: list[Path]         # trigger restrictions present
    jobs_without_when_manual_on_protected: list[Path]  # missing manual approval for protected branches
    parse_errors: list[tuple[Path, str]]
```

Parse approach: safe-load `.gitlab-ci.yml` plus any `include:` files (only when local; remote includes are recorded as supply-chain signal but not fetched — the kit never executes remote network IO during parse).

### 2. EvalContext extension

Add `gitlab_ci: GitLabCiAnalysis` (default-empty) to `EvalContext`. Every existing call site stays valid because the default factory returns an empty analysis. Tests already pass `workflows=...`, `azure_pipelines=...`, `aws_ci=...` — adding one more field follows the same shape.

The single load-bearing call site is `engine.evaluate_repository`, which runs all parsers in parallel.

### 3. New control family — `GL-PIPE-001..012`

| Control | Title | Assurance |
|---|---|---|
| `GL-PIPE-001` | GitLab CI pipeline files present and parseable | `deterministic` |
| `GL-PIPE-002` | `image:` references pinned to a specific tag or digest | `signal` (tag-only) → `deterministic` (digest). Mutable / floating tags (`:latest`, `:edge`, `:stable`, `:main`, `:master`, `:nightly`, `:lts`) are explicitly classified as **not pinned** and trigger a fail with confidence `high`. |
| `GL-PIPE-003` | No `curl ... \| sh` in `script:` blocks | `signal` |
| `GL-PIPE-004` | OIDC (`id_tokens:`) used for cloud authentication | `signal` |
| `GL-PIPE-005` | No `inherit: secrets: true` (broad secret exposure) | `deterministic` |
| `GL-PIPE-006` | Protected branches require `when: manual` for sensitive jobs | `signal` |
| `GL-PIPE-007` | `include:` does not reference remote URLs (or pins them) | `signal` |
| `GL-PIPE-008` | Self-hosted runners restricted to non-public jobs | `signal` |
| `GL-PIPE-009` | `rules:` / `only:` restrict triggers (no naked `on:`) | `signal` |
| `GL-PIPE-010` | Artifact / cache configuration scoped | `signal` |
| `GL-PIPE-011` | SAST / SCA / secret scan templates included | `signal` |
| `GL-PIPE-012` | Audit-log / pipeline-event streaming evidence | `evidence-backed` |

Categories: `ci_cd` for `001..011`, `governance` for `012`. Lifecycle: `experimental` for the whole family at introduction; promote to `stable` after one minor cycle.

### 4. New bundled profile — `gitlab-level-1`

Mirrors `github-level-1` in size and assurance mix. Bundles:

- Governance core: `GOV-SEC-001`, `GOV-CON-002`, `GOV-COWN-003`, `GOV-LIC-004`, `GOV-DISC-013`, `GOV-WAIV-014`.
- Pipeline native: `GL-PIPE-001`, `GL-PIPE-002`, `GL-PIPE-005`, `GL-PIPE-007`, `GL-PIPE-008`, `GL-PIPE-009`.
- Multi-platform supply chain: `DEP-UPDATE-001`, `SEC-DEPREV-011`, `REL-CHANGE-012`, `BUILD-SBOM-QUAL-003`.

Total: 16 controls. `--fail-on fail`. Add `gitlab-level-2` and `gitlab-level-3` in subsequent minors, paralleling the GitHub ladder.

## Why this is deferred (not shipped in v5.9.0)

The work splits cleanly:

- **Parser module**: 200-300 lines of YAML parsing with edge-case handling for GitLab's `include:` semantics (local / remote / template / project) and `extends:` job inheritance.
- **EvalContext mutation**: invasive — every test fixture that constructs an `EvalContext` would need updating, even if just to accept the default. The audit cost is real.
- **12 new evaluator functions**: each one is small but compounding. Tests must cover both empty-pipeline and adversarial cases.
- **Test fixtures**: need a `tests/fixtures/repositories/gitlab-hardened-target/` and `gitlab-vulnerable-target/` to parallel the existing GitHub / Azure / AWS fixtures.

Shipping a partial implementation (parser without evaluators, evaluators without profile, profile without fixtures) would either break adopter expectations or generate misleading evaluations. The honest path is to dedicate a session to it.

## Reversibility

This ADR is **fully reversible** until the implementation lands. Once `GL-PIPE-*` controls ship and the `gitlab-level-1` profile is published, the control IDs and profile ID become part of the public contract and require deprecation cycles to change.

The naming convention (`GL-PIPE-` prefix paralleling `AZ-PIPE-`, the platform-prefixed pattern) is the load-bearing decision. The specific 12 controls listed above are a starting set; the dedicated session may consolidate or split items as the parser shape becomes clearer.

## References

- `docs/profiles/deferred-followups.md` — "GitLab CI support" entry tracking this work.
- `src/oss_policy_kit/infrastructure/workflow_parser.py` — template for the new module.
- `src/oss_policy_kit/infrastructure/azure_pipeline_parser.py` — template for the new module.
- `SAST-POUTINE-067` (v5.9.0) — already covers GitLab CI when an adopter supplies poutine SARIF. Complementary to native parser, not a replacement.
- GitLab CI/CD documentation: https://docs.gitlab.com/ee/ci/yaml/
