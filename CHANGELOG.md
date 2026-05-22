# Changelog

All notable public changes to this project are summarized here.

This changelog follows the same public-facing format used by the GitHub release notes. It intentionally focuses on release outcomes, user-facing changes, and adoption impact instead of internal implementation logs.

---

## Unreleased — v6.x

### Highlights

* **Input size limits (local CI DoS hardening).** User-controlled inputs are now size-capped before being read into memory: evidence JSON / `--scorecard-json` / `--waivers` at 5 MiB and SARIF inputs (`--sarif-output` ingestion, `emit-vex --osv-sarif`, SAST `*.sarif.json` evidence) at 20 MiB. Evidence/SARIF-backed controls degrade to `manual-review-required`; CLI inputs fail with a clear validation error (exit 2). Documented in `docs/cli-reference.md`.
* **Third-party evaluator plugin load visibility.** Broken custom-evaluator plugins (entry-point group `oss_policy_kit.evaluators`) used to be skipped silently. Built-in evaluation is still never affected, but `evaluate --verbose` now reports each plugin load problem (`load` / `not-callable` / `builtin-precedence` / `discovery`) on stderr so operators can tell whether a custom control is actually active.

### Fixes

* fix SARIF `tool.driver.semanticVersion`: it was empty while `version` carried the kit SemVer. GitHub code scanning and other SARIF consumers use `semanticVersion` to correlate/dedupe alerts across tool versions, so it is now populated with the kit version. Covered by `tests/application/test_sarif_output.py`.
* fix `scripts/migrate-1.0-to-2.0.py`: it read a top-level `controls` key, but a reports/1.0 document emits `results`, so its output was not a schema-valid reports/2.0 document. It now reshapes `results` into the 2.0 `controls` array (mapping status → state via the same table the engine uses) and produces a `reports/2.0`-schema-valid document matching the kit's native serialization. Covered by `tests/contract/test_report_migration.py`.
* remove `paths-ignore: gitpage/**` from the `GitHub CI/CD` workflow so the required Quality check (which includes the gitpage guardrail test) runs on gitpage-only pull requests too. Previously such PRs skipped Quality, which let a broken gitpage change reach `master`.

### CLI / DX

* add an opt-in global `--debug` flag (`oss-policy-kit --debug <subcommand> ...`) that emits per-control diagnostics — which evaluator ran, each outcome, its evidence-collection method and source count — to stderr via the stdlib `logging` module. Without `--debug` the output is byte-identical to before.

### Documentation

* fix the documentation index so it matches reality: link previously-orphaned guides (`container-image`, `dev-environment`, `sigstore-rekor-v2`, `testing-strategy`) and list all migration guides (v3 → v6.0.0); document the `emit-insights` and `export-evidence` subcommands in `cli-reference.md`, which were missing.

### Internal

* split the ~8,800-line `application/evaluators.py` monolith into an `evaluators/` package with family submodules (governance, cicd, github, azure, aws, gitlab, supply_chain, ai, cra) over a shared `_shared.py`, with the registry and plugin loaders in `__init__.py` (ADR-026). Functions were moved verbatim: the `EVALUATOR_REGISTRY` ID set, evaluation reports, and public imports are unchanged. See `docs/architecture.md`.
* extract the duplicated evidence-schema loading boilerplate (repeated across 19 `_*_schema()` helpers) into a single `load_evidence_schema()` in `application/evidence_loading.py`. Behavior is byte-identical (evaluation reports unchanged); only the duplication is removed.

### Quality / Tests

* enforce a test-coverage floor in CI (`fail_under = 72`, combined unit + property runs) so coverage cannot silently regress.
* remove conditional `skipif`/`skip` guards on fixtures that are versioned in the repo (`invalid-workflow-target`, `repo with spaces`, `azure-/aws-hardened-target`). Those tests now always run; if a fixture goes missing the test fails clearly instead of turning into a silent green.
* add property-based invariants over the entire evaluator registry (every `eval_*` returns a valid, deterministic `EvalOutcome` and never writes to the target) and a `reports/1.0`→`reports/2.0` migration roundtrip validated against the report schema.
* enable a cyclomatic-complexity gate (ruff `C90`, `max-complexity = 12`) so new functions cannot grow unbounded. The functions already above the threshold are baselined with `# noqa: C901` and tracked for incremental reduction.

### Security / Supply Chain

* run `pip-audit` (dependency vulnerability audit, `--strict`) and `bandit` (Python SAST, gated at medium+ severity and confidence) on every push and pull request in `Security CI/CD`. Both tools were already declared dev dependencies but were not enforced in the pipeline; the kit now audits its own dependency tree and source the same way it asks adopters to.

### CI/CD

* bump remaining GitHub Actions to Node 24 runtime ahead of the 2026-06-02 deprecation: `download-artifact` v4→v8.0.1, `deploy-pages` v4→v5.0.0, `dependency-review-action` v4→v5.0.0, and `docker/{setup-qemu,setup-buildx,login,build-push}` to their Node 24 majors. All re-pinned by immutable SHA; no workflow logic changed. `gitleaks-action` stays on Node 20 (no upstream Node 24 release yet).

## [6.2.0](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/compare/v6.1.0...v6.2.0) (2026-05-22)


### Highlights

* enforce input size limits on user-controlled SARIF and evidence inputs ([5cbc9ab](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/5cbc9abdc2d7a404b5175c9c8ae1dba3e99c113b))
* surface third-party evaluator plugin load failures via evaluate --verbose ([a2d0f4f](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/a2d0f4f127fbdda8aaf6d1b4ad9a5f38bc231d2c))


### Improvements

* **ci:** stop pip-audit failing on the first-party package ([#43](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/43)) ([e8b2ffb](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/e8b2ffb564d89bafd2369976373bec2de4ac6811))
* populate SARIF tool.driver.semanticVersion ([a8702b4](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/a8702b4aa42c1bcc614f9a7f3fabd9fcb4b228c2))


### Notes

* document input size limits and plugin load visibility (v6.2.0) ([3fc9c9a](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/3fc9c9a61d3f5a886883c74da556777f60e4a4dc))
* run gitleaks-action on Node 24 (deprecation opt-in) ([#44](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/44)) ([de72903](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/de72903c8615a82cf9d17055a229d6176b3589f4))

## [6.1.0](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/compare/v6.0.1...v6.1.0) (2026-05-21)


### Highlights

* **cli:** add opt-in --debug diagnostics flag (M10) ([#38](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/38)) ([d57c583](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/d57c583dae9ceb6669352c8396e65fe2816da7a9))


### Improvements

* extract evidence-schema loading helper (M7) ([#35](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/35)) ([915b6f3](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/915b6f354c5160732899d29f0af3b3cf00dd96f1))
* migrate-1.0-to-2.0.py reads results, emits schema-valid 2.0 ([#40](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/40)) ([2fd182e](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/2fd182ea0aeb15369fabc2b26622e39d3327c0c3))
* split evaluators.py monolith into evaluators/ package (M8) ([#36](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/36)) ([a1a214d](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/a1a214dbd3dc2856e1c4db14b635bfb0bb4cc088))


### Notes

* add coverage floor + remove false-green test skips (M4-A, M6) ([#33](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/33)) ([12892fb](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/12892fb44fa55c2c01ba141e1e4939d9fa886233))
* bump remaining GitHub Actions to Node 24 runtime (M1) ([#30](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/30)) ([e5b9563](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/e5b956333cb6165714dae64cd1320fbf9c773b37))
* **deps:** bump aquasecurity/trivy-action from 0.35.0 to 0.36.0 ([#23](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/23)) ([f81c6ec](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/f81c6ec1763b3dccbc74536d3b4254e7bc7e5a1c))
* **deps:** bump devops-actions/actionlint from 0.1.3 to 0.1.12 ([#22](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/22)) ([483ff8c](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/483ff8c0940387cfb8ca2f39256d75a449ddb6e5))
* **deps:** bump docker/login-action from 3.4.0 to 3.7.0 ([#25](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/25)) ([7db23be](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/7db23be92bdaa1f9faf74321b7e988fc0353b1cd))
* **deps:** bump step-security/harden-runner from 2.19.0 to 2.19.3 ([#27](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/27)) ([4a54483](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/4a5448369c077696e5679500c4c2405dca9e2b21))
* enable ruff C90 cyclomatic-complexity gate (M4-B) ([#39](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/39)) ([697babb](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/697babb06fb2476fcce8e3fe057712f837fd20d0))
* fix documentation index + cli-reference drift (M9) ([#37](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/37)) ([351157d](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/351157d0190e19812ff0b66fe319b46fe5426174))
* **gitpage:** migrate Tailwind CSS v3 -&gt; v4 ([#29](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/29)) ([d67ec04](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/d67ec044c864672f3a6fe0f47b9228ff1b83b56f))
* run pip-audit + bandit in Security CI/CD (M2) ([#32](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/32)) ([9e96c98](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/9e96c98461f304b10089e75cf65174794539b7cb))
* run Quality on gitpage PRs (close paths-ignore gap) ([#41](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/41)) ([d2209a6](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/d2209a6ccde489f57d01048c9beeeac2e7c96894))

## [6.0.1](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/compare/v6.0.0...v6.0.1) (2026-05-20)


### Improvements

* harden container image and clear IaC scanner gate findings ([2b132bf](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/2b132bf8ccd26472bde4677ff7b59e8849761159))
* make SARIF deep-nesting guard portable (deterministic depth pre-scan) ([9c1a216](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/9c1a21616c9fb7d66e17ca134fc7deb69105be65))


### Notes

* add OpenSSF Scorecard workflow + automated release-notes workflow ([e6c4ffa](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/e6c4ffa3767334edb08aea467ec37d56f1796c81))
* add releasing guide (release-please + release.yml flow) ([0207187](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/0207187789e98a6cff2c9586ddd97c75ad64ae46))
* **changelog:** drop obsolete 'ADRs to be written before tagging' follow-up (PR-33 backfilled 009/010/013) ([386210d](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/386210d66b16adaeb54089eb2ce58d099f78ee03))
* **deps:** bump docker/build-push-action from 6.9.0 to 6.19.2 ([#15](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/15)) ([46b9bd5](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/46b9bd5558f1263e5511bbbbd4ecc20cf2a1205e))
* **deps:** bump docker/setup-buildx-action from 3.10.0 to 3.12.0 ([#16](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/16)) ([4b82b31](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/4b82b31e39c54dddedcec278b84ad960a6464504))
* **deps:** bump docker/setup-qemu-action from 3.6.0 to 3.7.0 ([#13](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/13)) ([337dc8f](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/337dc8fc75bbde68f708ea871d57c54b2bbc87dc))
* **deps:** bump sigstore/cosign-installer from 3.9.2 to 3.10.1 ([#17](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/17)) ([0f35170](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/0f35170578907c63e4d8cfcddd8d051f36fb9179))
* **deps:** bump step-security/harden-runner from 2.19.0 to 2.19.3 ([#14](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/14)) ([44125cf](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/44125cf518d228c2bd36538a2696b36841396045))
* harden v6.0.1 release maturity (release assets, image digest, CI fix) ([#21](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/issues/21)) ([92ffd2f](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/92ffd2f177ad9b4aafa7a5877c54317d70f9a982))
* keep release process notes local ([30391ab](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/30391abe55d17805528a589be38381ea130aa728))
* keep roadmap local only ([edf692a](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/edf692a838cdcc058060c596a01fa7d6aca56cfb))
* **kics:** accept apt-pin finding via exclude_queries (inline disable unreliable) ([fb82497](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/fb824970c045ae8dd82959003d992b969d29c9c1))
* pin ruff and move remaining actions off Node 20 ([73761fd](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/73761fd3986dd7007ffd593a05454ed27c97a6d2))
* **release:** add release-please (version-bump PR + tag) composing with release.yml ([b0daf36](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/b0daf36d520de4126ef2e82d9362e2144fa17ff0))
* **release:** bump release-please-action v4.1.3 -&gt; v5.0.0 (Node 24) ([a817689](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/a817689f6be72802999338fda13239daa34fb613))
* **release:** use create-github-app-token client-id input (app-id deprecated) ([0dcbe54](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/0dcbe5450fc4b926ef07d5dfc272b2b4b33f7877))
* **scorecard:** drop redundant top-level read-all permissions ([229e610](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/229e610c6d85c3d386122674a57f50cbfc88ac72))
* simplify README structure ([ba765f1](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/ba765f172761628ad57c454cb41773baf0a00c60))
* trim repository layout ([e1c8483](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/commit/e1c84837ad6af08c3b20ce95badebdaeceb4dde6))

## [6.0.0] - 2026-05-20

The v6.0.0 release (Cycle 1 + Cycle 2). Version `6.0.0` in `pyproject.toml` and `src/oss_policy_kit/__init__.py`. Tagged from `master`. See `docs/v6.0.0-migration-guide.md` for the three breaking changes (M-003, B-001, B-002).

### Highlights — full v6.0.0 scope (14 base PRs + Cycle 2 PR-19..PR-33 + AI agent baseline landed locally)

**+14 profiles, +76 controls, +2 CLI subcommands, 3 breaking changes, 22 new ADRs, 12+ new docs.**

| | v5.9.x | v6.0.0 (this branch) |
|---|---|---|
| Profiles | 38 | **52** |
| Controls | 136 | **212** |
| CLI subcommands | 15 | **17** |
| Breaking changes | 0 | **3** (M-003, B-001, B-002) |
| ADRs | 3 | **25** (3 existing + 22 new) |

**New profiles**: `webhook-security-2`, `s2c2f-l2-1`, `s2c2f-l3-1`, `oss-publish-readiness-1`, `slsa-source-l1-1`, `gitlab-level-2`, `appsec-llm-ssdf-218a-1`, `cra-eu-ai-act-art11-1`, `ai-agent-baseline-1`, `osps-baseline-2026-1`, `cra-eu-ready-2-1`, `slsa-source-l2-1`, `appsec-mcp-server-1`, `appsec-agentic-asi-1`.

**New control families**: `SEC-WEBHOOK-HMAC..ROTATE-006` (6), `GH-EGRESS-HRN-001` (1), `PUBLISH-OIDC-001..003` (3), `SLSA-SRC-001..008` (8), `GL-PIPE-007..012` (6), `AIBOM-PRESENT-001` (1), `LLM-218A-PO..RV-001` (7), `LLM-AI-ACT-001..003` + `LLM-AI-ACT-{DEV,PERF,CYBER,CHANGE,STD,PMM}-*` (9), `WORM-*` (3), `AI-AGENT-001..010` (10), `OSPS-SCORECARD-V6-001` (1), `CRA-ART13/14/PRODUCT-*` (5), `SCA-EPSS/KEV-*` (2), `MCP-*` (5), `AGENT-ASI-*` (5), `GH-EGRESS-NATIVE-001`, `GH-WF-LOCKFILE-001`, `CONT-DISTROLESS-001`, `SCANNER-INTEGRITY-001`.

**New CLI subcommands**: `emit-insights` (OpenSSF Security Insights 1.0 YAML emission), `export-evidence --format chainloop|sarif` (experimental format registry).

**Breaking changes**:
- **M-003** — `recommend-profile/v2.schema_version` is now an absolute URL. Legacy shorthand accepted for one minor (removed in v6.1.0). See ADR-008, PR-15.
- **B-001** — `reports/2.0` contract registered with the Scorecard-v6-aligned 5-state vocabulary (`PASS / FAIL / UNKNOWN / NOT_APPLICABLE / ATTESTED`). Default REMAINS `1.0` in v6.0.0; default-switch deferred to a v6.x point release per ADR-013. Standalone `scripts/migrate-1.0-to-2.0.py` converts offline reports.
- **B-002** — `export-evidence --format chainloop` is **experimental**; output shape may change inside the v6.0.x line. See ADR-012, PR-17.

**Assurance-mix shift (A-001)**: `GH-PROV-023` promoted from `signal` to `evidence-backed` (catalog), with backward-compat runtime fallback (signal PASS when no evidence file is present). Affected profiles: `github-release-hardening-1/2/3`, `slsa-build-l2-1`. See ADR-007, PR-12.

**Window-blocking content (EU AI Act Article 11 + Annex IV — effective 2026-08-02)**: both `appsec-llm-ssdf-218a-1` (PR-10, NIST 800-218A) and `cra-eu-ai-act-art11-1` (PR-11, EU AI Act) are advisory profiles. The kit does NOT substitute for a conformity assessment — see `docs/eu-ai-act-readiness.md`.

### PR-by-PR delta

| Wave | PR | Title | Delta |
|---|---|---|---|
| 1 | PR-1 | docs: correct v6 positioning and public hygiene | docs only |
| 1 | PR-2 | docs(framework-alignment): +3 Roadmap sections | docs only |
| 1 | PR-3 | feat(adapters,emit-vex): zizmor severity properties + CISA VEX minimum tests | +24 tests |
| 1 | PR-4 | feat(sbom): SPDX 3.0.1 detection + BSI TR-03183-2 v2.1.0 validation | +19 tests |
| 2 | PR-5 | feat(webhook): webhook-security-2 + 6 SEC-WEBHOOK-* dimensions | +1 profile, +6 controls |
| 2 | PR-6 | feat(profiles): s2c2f-l2-1 + s2c2f-l3-1 (recomposition only) | +2 profiles |
| 2 | PR-7 | feat(evaluators,schemas): GH-EGRESS-HRN-001 + verification.source enum | +1 control |
| 2 | PR-8 | feat(cli): emit-insights subcommand | +1 subcommand |
| 2 | PR-9 | feat(profiles,evaluators): oss-publish-readiness-1 + PUBLISH-OIDC-* | +1 profile, +3 controls |
| 3 | PR-12 | feat(controls): GH-PROV-023 promotion signal→evidence-backed | assurance shift |
| 3 | PR-13 | feat(profiles,evaluators): slsa-source-l1-1 + SLSA-SRC-* | +1 profile, +5 controls |
| 3 | PR-14 | feat(profiles,evaluators): gitlab-level-2 + GL-PIPE-007..012 | +1 profile, +6 controls |
| 3 | PR-10 | feat(profiles,evaluators): appsec-llm-ssdf-218a-1 + LLM-218A-* + AIBOM | +1 profile, +8 controls |
| 3 | PR-11 | feat(profiles,evaluators): cra-eu-ai-act-art11-1 + LLM-AI-ACT-* | +1 profile, +3 controls |
| 4 | PR-15 | feat(recommend): recommend-profile/v2 schema_version → absolute URL | breaking M-003 |
| 4 | PR-17 | feat(cli): export-evidence --format chainloop (experimental) | +1 subcommand |
| 4 | PR-16 | feat(reports): reports/2.0 contract URL + status mapping + migration | breaking B-001 |
| 4 | PR-18 | release prep: version bump + counts refresh + CHANGELOG summary | this entry |
| C2 | PR-19 | feat(profiles,evaluators): WORM-* publish-defense controls | +3 controls, +1 ADR, +1 doc |
| C2 | AI agent baseline | feat(profiles,evaluators): ai-agent-baseline-1 source-side checks | +1 profile, +10 controls, +1 ADR, +1 doc |
| C2 | Supply-chain hardening | chore(release): PyPI dist attestations + source-built container image | closes PyPI/GHCR race |
| C2 | Public launch assets | docs: README rewrite, public ROADMAP, sample reports, first-PR tutorial | P0 product/DX |
| C2 | GitHub Pages hardening | docs(site): bundled Tailwind CSS + static JS bundle with pinned npm dependencies plus comparison/sample/roadmap sections | removes runtime Tailwind and Babel CDN dependencies |
| C2 | Property testing | test(property): Hypothesis coverage for waivers, profile/catalog loading, EvalOutcome roundtrip, and report contracts | adds edge-case coverage for v6.x hardening |
| C2 | PR-20 | feat(profiles,evaluators): osps-baseline-2026-1 + OSPS-SCORECARD-V6-001 | +1 profile, +1 control, ADR-018 |
| C2 | PR-21 | feat(evaluators,schema): EU AI Act Annex IV expansion (LLM-AI-ACT-{DEV,PERF,CYBER,CHANGE,STD,PMM}) | +6 controls, +1 schema, ADR-019 |
| C2 | PR-22 | feat(profiles,evaluators): cra-eu-ready-2-1 + CRA-ART13/14/PRODUCT-* | +1 profile, +5 controls, ADR-020 |
| C2 | PR-23 | feat(evaluators): SCA-KEV-001 + SCA-EPSS-001 (SARIF property triage) | +2 controls, ADR-021 |
| C2 | PR-24 | feat(schema): verification.source += rekor-v2-tile-inclusion | enum + doc, ADR-025 |
| C2 | PR-25 | feat(profiles,evaluators): slsa-source-l2-1 + SLSA-SRC-006..008 | +1 profile, +3 controls, ADR-022 |
| C2 | PR-26 | feat(evaluators): CycloneDX 1.7 + ML-BOM recognition in AIBOM-PRESENT-001 | additive, ADR-025 |
| C2 | PR-27 | feat(profiles,evaluators): appsec-mcp-server-1 + MCP-* | +1 profile, +5 controls, ADR-023 |
| C2 | PR-28 | feat(profiles,evaluators): appsec-agentic-asi-1 + AGENT-ASI-* | +1 profile, +5 controls, ADR-024 |
| C2 | PR-29..32 | feat(evaluators): GH-EGRESS-NATIVE-001, GH-WF-LOCKFILE-001, CONT-DISTROLESS-001, SCANNER-INTEGRITY-001 | +4 controls, ADR-025 |
| C2 | PR-33 | docs(adr,framework): ADR-009/010/013 backfill + 8 Cycle 2 ADRs + OSPS/CRA/MCP/EPSS/Rekor docs | docs + ADRs |

### Validation summary (end of this PR)

- `ruff check src/ tests/`                                       All checks passed
- `mypy src/`                                                    Success (93 source files)
- `scripts/check_public_hygiene.py`                              OK
- `scripts/validate-bundled-profiles.py`                         OK
- `yamllint` on publish/security workflows from prompt scope       OK
- `npm run build` in `gitpage/`                                   OK
- GitPage Lighthouse (local JSON report)                          87 perf / 100 accessibility / 100 best-practices / 100 SEO
- `pytest -q --tb=no -p no:cacheprovider`                        2994 passed, 1 skipped, 0 failed
                                                                 (+519 over v5.9.x baseline of 2191)

### Known follow-ups (not blocking v6.0.0 GA)

- `reports/2.0` default-switch (currently 1.0 remains default; snapshots will be regenerated when the switch lands).
- External launch content and community activation remain pending product/DX work before broad v6.0.0 promotion.

### Docs

- **`docs/positioning.md`** — rewritten to (a) describe only capabilities present in the v5.9.x build, (b) list v6.0.0 plans explicitly under a `Roadmap (v6.0.0 — in development)` section so adopters can see direction without confusing roadmap with shipped capability, (c) correct the SARIF-adapter inventory (`SAST-SEMGREP-064`, `SAST-ZIZMOR-066`, `SAST-POUTINE-067`, `SAST-OSV-068`, `SAST-GITLEAKS-069`; no Trivy adapter is shipped today), (d) describe the actual `PROV-VERIFY-061` `verification:` block schema (`method`, `verified_at`, `transparency_log_inclusion`, optional `issuer` / `subject_alternative_name` / `bundle_digest` / `tool_version`) and place the planned `verification.source` enum under Roadmap, (e) correct `--fail-on` to the implemented values `none / fail / degraded`, and (f) remove links to documents that do not exist yet.
- **`README.md`** — rewritten for the v6 launch surface: hero, concise value proposition, public badges, factual v6.0.0 counts (52 profiles, 212 controls, 17 CLI subcommands), inline comparison table, sample output embeds, supply-chain verification wording, and links to moved detail pages.
- **`docs/at-a-glance.md` / `docs/release-state.md`** — moved detailed snapshot and release-state material out of the root README.
- **`ROADMAP.md`** — new public Now / Next / Later roadmap with explicit non-goals and no shipped-capability overclaims.
- **`docs/sample-reports/`** — generated hardened and vulnerable `github-level-1` Markdown/JSON example reports with local paths sanitized for public viewing.
- **`docs/tutorial-first-pr-gate.md`** — new first-time adopter tutorial from install to pull-request gate, with screenshot references and troubleshooting.
- **`docs/supply-chain-verification.md`** — new verifier guide for PyPI artifacts, GHCR images, cosign, GitHub Artifact Attestations, and the current non-SLSA-L3 trust model.
- **`gitpage/`** — removed the runtime Tailwind CDN and Babel standalone dependencies. Tailwind and JSX are now built locally through pinned npm dependencies into committed `site.css` and `bundle.js`, with the build boundary documented in `gitpage/README.md`.
- **`docs/profiles/ai-agent.md`** — new adopter guide for `ai-agent-baseline-1`, with evidence paths and explicit runtime-enforcement caveats.
- **`docs/framework-alignment.md`** — refresh stale counts (now `136 controls` / `38 profiles`); add three `Roadmap` sections for v6.0.0 framework expansion: NIST SP 800-218A (Generative AI SSDF), EU AI Act Article 11 + Annex IV, and OpenSSF Security Insights 1.0 emit. Every planned control / profile / subcommand is explicitly tagged as not present in v5.9.x.
- **`docs/decisions/adr-001-sca-scanner-choice.md`** and **`docs/framework-alignment.md`** — removed references to the project-local planning directory name from public-facing prose. The local planning artifacts remain gitignored and are not part of the public repository; the prose now says so without naming the directory.
- **New ADRs** under `docs/decisions/`:
  - **`adr-004-webhook-security-baseline-expansion.md`** — design rationale for `webhook-security-2` profile + `SEC-WEBHOOK-*` family (six new signal-grade controls).
  - **`adr-005-s2c2f-l2-l3-recomposition.md`** — decision to ship `s2c2f-l2-1` and `s2c2f-l3-1` as recomposition of existing controls, zero new evaluators.
  - **`adr-006-slsa-source-l1-profile.md`** — design rationale for `slsa-source-l1-1` profile + `SLSA-SRC-*` family (5–6 controls).
  - **`adr-007-gh-prov-023-evidence-backed-promotion.md`** — `GH-PROV-023` promotion from `signal` to `evidence-backed`; assurance-mix shift documented (A-001).
  - **`adr-008-recommend-profile-v2-schema-url.md`** — `recommend-profile/v2.schema_version` becomes an absolute URL (breaking, M-003).
  - **`adr-011-emit-insights-subcommand.md`** — design rationale for `emit-insights` subcommand emitting OpenSSF Security Insights 1.0 YAML.
  - **`adr-012-export-evidence-chainloop-experimental.md`** — design rationale for `export-evidence --format chainloop` (experimental in v6.0.0).
  - **`adr-014-oss-publish-readiness.md`** — design rationale for `oss-publish-readiness-1` profile + `PUBLISH-OIDC-*` family (three signal-grade controls).
  - **`adr-015-worm-aware-publish-defense.md`** — design rationale for `WORM-*` publish-defense controls in `oss-publish-readiness-1`.
  - **`adr-016-ai-agent-baseline-source-side.md`** — design rationale for `ai-agent-baseline-1` and its source-side/runtime-boundary posture.
  - **`adr-017-source-built-container-release.md`** — decision to build GHCR images from the checked-out release source tree instead of waiting on PyPI propagation.
- **Six new doc stubs** under `docs/` describing v6.0.0 features marked clearly as in-development:
  - **`docs/eu-ai-act-readiness.md`** — adopter guide for the planned `cra-eu-ai-act-art11-1` profile; explicit caveat that the kit does not substitute for a conformity assessment.
  - **`docs/insights-emission.md`** — design and adopter guide for the planned `emit-insights` subcommand.
  - **`docs/evidence-export.md`** — design and adopter guide for the planned `export-evidence` subcommand, including Chainloop experimental-format details.
  - **`docs/reports-contract-v2.0.md`** — full spec for the planned `reports/2.0` contract (five-state vocabulary aligned with Scorecard v6).
  - **`docs/v6.0.0-migration-guide.md`** — consolidated migration guide for the three v6.0.0 breaking changes (M-003, B-001, B-002) plus the `GH-PROV-023` assurance-mix shift (A-001).
  - **`docs/shai-hulud-defense.md`** — adopter guide for the `WORM-*` controls added to `oss-publish-readiness-1`.

### Repository hygiene

- **`.gitignore`** — added `.tmp/` so local snapshots such as `.tmp/profiles-v5.9.0.json` are not surfaced as untracked. The earlier `.tmp-v6/` entry was replaced with the more general `.tmp/`, which subsumes the v6.0.0 execution-plan use case.
- **`.dockerignore` / `Dockerfile`** — container publication now installs from the checked-out release source tree instead of PyPI, eliminating the tag-push race where GHCR build could start before the PyPI artifact was visible.
- **`.github/workflows/publish-pypi.yml`** — distribution artifacts under `dist/*` now receive GitHub Artifact Attestations before the publish jobs upload them to TestPyPI/PyPI; PyPA Trusted Publishing attestations are explicitly enabled for both TestPyPI and PyPI publish jobs.
- **`.github/workflows/security-ci-cd.yml`** — refreshed `github/codeql-action/*` pins to the current `v3` peeled commit after API validation showed the previous SHA did not resolve.
- **`.yamllint`** — added a repository-level YAML lint profile so workflow validation accepts pinned-action SHA line lengths and existing mixed line endings while still enforcing YAML checks.
- **`src/oss_policy_kit/__init__.py`** — bumped `__version__` from `5.9.0` to `5.9.1` to match `pyproject.toml` and the published `v5.9.1` tag. This corrects a version-drift the public hygiene review surfaced; it is not a release in itself.
- **`scripts/check_public_hygiene.py`** — added narrow allowlist entries for `.dockerignore` (the exclusion rule for the project-local planning directory is protective, not a leaked path) and `Dockerfile` (the conventional non-root home under the standard POSIX system user tree is a generic container pattern, not a real maintainer home directory). Allowlist comments explain the justification so the scanner does not weaken its detection of real sensitive paths.
- **`README.md`** — corrected three stale references that still pointed at v5.9.0 after v5.9.1 shipped: the "Current release" table row, the "Package" / "GitHub Release" rows in *Current Release State*, the "Two-line bootstrap (v5.4.0+; available in current v5.9.x)" wording, and the CLI subcommand count (now 15, was 13). Added a one-line "In development" note at the top pointing to the positioning Roadmap.

### Notes

- This is still an unreleased development branch. Public release remains `v5.9.x` until maintainer review, remote push, release tagging, PyPI publish, and container publish complete.
- `reports/2.0` exists as an opt-in contract; `reports/1.0` remains the default during the `6.0.0` line.
- Test, lint, type-check, hygiene-scan, and bundled-profile-validation must remain green before tagging; the validation summary above captures the latest local full-suite signal for this branch.

---

## OSS Security Policy as Code Starter Kit v5.9.1 — 2026-05-18

A patch release that fixes two invalid action SHAs in `.github/workflows/publish-container.yml`. The v5.9.0 container publish workflow was discovered, after release, to pin two action SHAs that do not exist in the upstream repositories:

- `sigstore/cosign-installer@d7d6e4dc...` — not a valid commit.
- `actions/attest-build-provenance@2ce9eaf7...` — not a valid commit (the value used was a tag-object SHA, not the peeled commit SHA, and was inconsistent with the upstream).

As a result, the workflow never ran on the `v5.9.0` tag push, and a follow-up manual `workflow_dispatch` against the same ref failed at job setup with `Unable to resolve action`. No container image was published to GHCR for `v5.9.0`.

### Fixed

- **`.github/workflows/publish-container.yml`** — pin `sigstore/cosign-installer` to `d58896d6a1865668819e1d91763c7751a165e159` (`v3.9.2`, peeled commit) and `actions/attest-build-provenance` to `96278af6caaf10aea03fd8d33a09a777ca52d62f` (`v3.2.0`, peeled commit). Both SHAs were validated against the upstream `git/tags` API before pinning.

### Notes

- The workflow already pinned the other five actions to valid SHAs (`actions/checkout`, `docker/setup-qemu-action`, `docker/setup-buildx-action`, `docker/login-action`, `docker/build-push-action`); those are unchanged.
- The release pushes `ghcr.io/lucashgrifoni/oss-policy-kit:5.9.1` and `:latest`. The `:5.9.0` tag remains absent from GHCR; the source tree and PyPI artifact for `v5.9.0` are unchanged and remain valid.
- No code, profile, control, evaluator, evidence schema, report contract, or CLI surface changes.
- `pyproject.toml` version bumped to `5.9.1`.

---

## OSS Security Policy as Code Starter Kit v5.9.0 — 2026-05-16

A minor release that lands **Fase 4** of the v5 trajectory: new SARIF-ingest adapters for the de-facto OSS scanner ecosystem, a CRA-reporting-readiness profile aligned with the 2026-09-11 deadline, a new evidence-backed disclosure-SLA control, the first two ADRs, a public positioning page, and a pre-commit hook surface for downstream adopters.

**Development Status promoted to `Production/Stable`** (`pyproject.toml` classifier). The kit has been usable as a release gate for several minor versions; v5.9 makes that posture explicit.

### Highlights

- **Four new SARIF-ingest adapters** in the SAST family — `SAST-ZIZMOR-066`, `SAST-POUTINE-067`, `SAST-OSV-068`, `SAST-GITLEAKS-069`. They read raw SARIF 2.1.0 dropped at `.oss-policy-kit/evidence/sast/<tool>.sarif.json` and surface findings by severity. zizmor / poutine / OSV pass on warning-only output; Gitleaks treats any finding as a block (secrets are zero-tolerance). All four are bundled into `appsec-sast-sca-1` (which grows from 11 to 15 controls).
- **Native GitLab CI support** — new infrastructure parser (`gitlab_ci_parser.py`), six new controls (`GL-PIPE-001..006`), and the first bundled `gitlab-level-1` profile. The parser surfaces pipeline presence, `image:` pinning, `curl|sh` script patterns, broad `inherit: secrets: true`, unpinned remote `include:`, and trigger restrictions (`rules:` / `only:` / `except:` / `when:`). The initial 6-control subset closes the most common GitLab CI hardening gaps; the remaining 6 from the ADR-003 design (`GL-PIPE-007..012` — OIDC tokens, self-hosted-runner restrictions, audit-log streaming, etc.) ship in subsequent minors. `gitlab-level-2` and `-3` ladder profiles follow as the parser surface widens.
- **Official `Dockerfile` + GHCR publish workflow.** Multi-stage Dockerfile in the working tree (`Dockerfile`) builds a non-root, container-baseline-1-compliant image. The new `.github/workflows/publish-container.yml` workflow builds multi-arch (`linux/amd64`, `linux/arm64`), signs with cosign (keyless via Sigstore Public Good + GitHub OIDC), generates a CycloneDX SBOM via Buildx, and produces a GitHub Artifact Attestation pushed to the registry. Triggered by `v*` tags. Verify with `cosign verify` or `gh attestation verify`. See [`docs/container-image.md`](docs/container-image.md).
- **New bundled profile `cra-eu-reporting-1`** focused on the EU CRA's 2026-09-11 24-hour reporting deadline. Eleven controls covering disclosure channel + SLA, detection capability, audit trail, risk handling discipline, and affected-artifact identification. Advisory (`--fail-on degraded`). Distinct from `cra-eu-ready-1` (broader preparation) and `cra-eu-strict-1` (2027-12-11 full obligations).
- **New evidence-backed control `GOV-DISC-065`** — disclosure channel SLA documented. Reads `.oss-policy-kit/evidence/disclosure-policy.json` (schema `disclosure-policy/v1`) with required fields `schema_version`, `attested_at`, `attested_by`, `contact.method/value`, `acknowledgement_sla_hours`, `triage_sla_hours`, and `public_disclosure_policy.{default_window_days, negotiable}`. Signal fallback: looks for SLA keywords in `SECURITY.md` (root, `.github/`, `docs/`) when no evidence file is present.
- **First two ADRs (`docs/decisions/`)**:
  - `adr-001-sca-scanner-choice.md` — OSV-Scanner v2 selected as SCA primary (reachability-aware in JAR/Go), Trivy repositioned as future container-scanning candidate.
  - `adr-002-emit-vex-scope.md` — scope and design for the planned `emit-vex` subcommand (CycloneDX VEX 1.6 from OSV-Scanner findings + waivers). Implementation deferred to a v5.9.x point release after adopter SARIF fixtures are available.
- **`docs/positioning.md`** (new) — public positioning page answering "why use this kit if Scorecard v6 / zizmor / OSV-Scanner / Harden-Runner exist". Honest boundary-drawing: what the kit does (composable profiles, evidence trust grading, multi-platform gates, waiver registry) and what it deliberately does not (universal scanner, deep AST analysis, runtime egress enforcement, OSPS certification engine, SBOM generator, compliance guarantee).
- **`docs/cra-readiness.md`** (new) — walks both CRA deadlines (2026-09-11 24-hour reporting, 2027-12-11 full obligations), maps each of the three bundled CRA profiles, and is explicit about what the kit does **not** prove (the actual 24-hour clock, conformity assessment, CE-marking, severity-of-exploitation judgement).
- **New `emit-vex` subcommand** — emits a CycloneDX VEX 1.6 document from OSV-Scanner SARIF. Every distinct vulnerability ID (CVE / GHSA / OSV / RUSTSEC) appears in `analysis.state: in_triage`; the manufacturer fills in the analysis post-hoc. Conservative v0.1 surface — per-CVE waiver integration is tracked for v5.9.x (see ADR-002). Documented in [`docs/vex-emission.md`](docs/vex-emission.md).
- **Pre-commit hook surface (`.pre-commit-hooks.yaml`)**. Three hooks shipped: `oss-policy-kit-evaluate` (hard-gate ladders), `oss-policy-kit-evaluate-degraded` (advisory profiles), `oss-policy-kit-validate-profiles` (maintainers). Wiring documented in [`docs/pre-commit-integration.md`](docs/pre-commit-integration.md).

### Breaking — `cra-eu-strict-1` description rewrite

`cra-eu-strict-1` previously self-described as "hard-gate-capable when evidence files are filled" while its CLI maturity label was "framework-aligned advisory (regulatory)". The inconsistency was resolved in favor of advisory: the kit does not certify CRA conformity (which requires a competent authority / notified body), and "hard-gate-capable" overpromised what evidence alone can demonstrate. The profile is **functionally unchanged** (same 19 controls, same `--fail-on degraded` recommendation); only the description and the test carve-out were updated.

This may surface in adopter dashboards that parse the profile description string. The profile id, control list, and report contracts are unchanged.

### Added

- New control `GOV-DISC-065` — Disclosure channel SLA documented (evidence-backed, weight 2, category governance).
- New control `SAST-ZIZMOR-066` — zizmor SARIF findings on GitHub Actions workflows (evidence-backed, weight 2, experimental).
- New control `SAST-POUTINE-067` — poutine SARIF findings on GitHub Actions / GitLab CI pipelines (evidence-backed, weight 2, experimental).
- New control `SAST-OSV-068` — OSV-Scanner v2 SARIF findings (evidence-backed, weight 3, experimental).
- New control `SAST-GITLEAKS-069` — Gitleaks SARIF findings (evidence-backed, weight 3, experimental).
- New controls `GL-PIPE-001..006` — GitLab CI native checks: pipeline presence (deterministic, w1), image pinning (signal, w2 — includes mutable-tag detection for `:latest`, `:edge`, `:stable`, `:main`, `:master`, `:nightly`, `:lts`), `curl|sh` (signal, w3), broad `inherit: secrets: true` (deterministic, w2), unpinned remote `include:` (signal, w2), trigger restrictions (signal, w1). All experimental, category `ci_cd`.
- New profile `cra-eu-reporting-1` (advisory, regulatory, 11 controls).
- New profile `gitlab-level-1` (starter ladder, 16 controls, `--fail-on fail` recommended).
- New evidence schema `disclosure-policy/v1` packaged at `src/oss_policy_kit/data/schema/evidence-disclosure-policy.schema.json` with byte-identical mirror at `reports/schema/`.
- New infrastructure parser `gitlab_ci_parser.py` with `GitLabCiAnalysis` dataclass; integrated into `engine.evaluate_repository` and `EvalContext.gitlab_ci` (default empty for backward compatibility).
- New CLI subcommand **`emit-vex`** (CycloneDX VEX 1.6 from OSV-Scanner SARIF; per-CVE waivers, `--validate`, `--include-references`).
- New CLI flag **`init --interactive`** that prompts the operator to confirm or override the recommended profile before writing `oss-policy-kit.yaml`. Opt-in; non-interactive when stdin is not a TTY.
- New `Dockerfile` (multi-stage, non-root uid 10001) and `.github/workflows/publish-container.yml` (multi-arch + cosign + Artifact Attestation + SBOM).
- New public docs: `docs/positioning.md`, `docs/cra-readiness.md`, `docs/pre-commit-integration.md`, `docs/vex-emission.md`, `docs/container-image.md`, `docs/v5.9.0-migration-guide.md`.
- New ADRs: `docs/decisions/adr-001-sca-scanner-choice.md`, `docs/decisions/adr-002-emit-vex-scope.md`, `docs/decisions/adr-003-gitlab-ci-support.md`.
- `.pre-commit-hooks.yaml` with three published hooks.
- Example fixtures: `examples/hardened-repo/.oss-policy-kit/evidence/disclosure-policy.json` plus four empty-findings SARIF stubs under `evidence/sast/` (zizmor, poutine, osv-scanner, gitleaks).

### Changed

- `appsec-sast-sca-1` profile expanded from 11 to 15 controls (adds the four v5.9 SARIF adapters).
- `cra-eu-strict-1` profile description rewritten as advisory (no functional / control change).
- `GL-PIPE-002` now flags mutable / floating image tags (`:latest`, `:edge`, `:stable`, `:main`, `:master`, `:nightly`, `:lts`) as fail with `high` confidence instead of treating them as pinned. Specific tags (e.g. `python:3.12-slim`) and digests still pass. Closes the v0.1 limitation noted in ADR-003. (MELHORIA-005)
- `recommend-profile`: when GitHub/Azure/AWS evidence files exist but the matching CI signal (workflow / pipeline / buildspec) is missing AND no other platform's CI signal exists either, the recommender now emits the `*-level-1` starter profile with an explicit "evidence is currently unused" rationale instead of returning an empty `suggestions[]`. Prevents the silent-no-suggestion UX gap. (MELHORIA-001 / F-001)
- `recommend-profile`: the `evidence_json_non_bundled_filenames` signal was renamed to `evidence_json_unrecognized_filenames` and now correctly excludes platform-agnostic bundled filenames (`disclosure-policy.json`, `audit-log-streaming.json`, `release-archival-policy.json`, `iac-*.json`, `k8s-baseline.json`, `org-mfa-posture.json`, `github-provenance-artifact.json`, `runner-groups.json`). The detail message also states explicitly that unrecognized files are ignored by `evaluate`. (MELHORIA-006 / F-008)
- `evaluate-many --skip-non-repos` now also skips meta / output / cache directory names (`out`, `dist`, `build`, `_output`, `.tmp`, `node_modules`, `venv`, `.venv`, `target`, `site`, `coverage`, `htmlcov`, plus `out-*` / `out_*` / `build-*` / `dist-*` / `output-*` / `_output*` prefixes) even when they happen to contain a package manifest from a build artifact. Adopters can still force-evaluate via `evaluate --target <path>`. (MELHORIA-002 / F-007)
- `emit-vex --waivers` now emits a stderr warning when waiver `vulnerability_ids` do not match any SARIF finding, listing the unmatched IDs so adopters can spot typos or CVE↔GHSA alias mismatches. (MELHORIA-008)
- New adopter-facing docs `docs/profiles/gitlab.md`, `docs/profiles/cra-eu.md`, `docs/profiles/appsec-sast-sca.md` covering the v5.9.0 surface in depth.
- `init --dry-run` now accepts a target path that does not exist yet, so adopters can preview the plan before creating the directory. The plan is printed, nothing is written, and an explicit note ("Target directory does not exist yet: <path>. Running init without --dry-run will require you to create it first.") is appended to `notes` in both human and JSON output. Without `--dry-run`, the legacy guard remains: a missing target still exits 2 with the same actionable message. (OP-001 / MELHORIA-011)
- `docs/framework-alignment.md` header counts refreshed (65 → 125 controls, 20 → 36 profiles, v5.0.0 → v5.8.1), Decision 4 "future work" section refreshed to mark items shipped in v5.1.0 / v5.6.0 / v5.9.0 and to list the six new post-v5.0.0 candidates with regulatory-urgency ranking. CRA section now documents all three CRA-aligned profiles distinctly (reporting / ready / strict).
- `docs/profiles/overview.md` references to `cra-eu-strict-1` aligned with the advisory rewrite.
- `docs/profiles/deferred-followups.md` extended with GitHub native security platform features (GA-dependent), `emit-vex` subcommand (planned per ADR-002), and GitLab CI support (`gitlab-level-1`, planned — needs a `.gitlab-ci.yml` parser first).
- Test file `tests/application/test_profile_maturity_drift.py` lost its `cra-*` regulatory carve-out; the advisory rule applies uniformly now.

### Maintenance

- Test suite grew from 1958 to 2191 (+233 tests covering the new controls, the new profiles, the four SARIF adapters, the GitLab CI parser including a realistic ~120-line fixture, the GL-PIPE-* evaluators, the `emit-vex` v0.2 surface including unmatched-waiver warning, mutable-tag detection, evaluate-many meta-directory filter, recommend-profile fallback, the .pre-commit-hooks.yaml structural contract, init --dry-run accepting a missing target, and parametrized cross-profile invariants that auto-detected the new bundles).
- `Development Status :: 4 - Beta` → `5 - Production/Stable` in `pyproject.toml`.
- Version bump `5.8.1` → `5.9.0`.
- `GOV-EVIDFRESH-054` now skips `.oss-policy-kit/evidence/sast/*.sarif.json` files (scanner outputs have their own freshness contract via SARIF `invocations[].startTimeUtc`; the kit's `attested_at` / `collected_at` check applies only to attestation-style evidence).

### Deferred to v5.9.x

- `emit-vex` extensions: full CycloneDX 1.6 JSON Schema validation (today `--validate` is structural / required-field only), `response.type` mapping from waiver fields, multi-source ingest for zizmor / poutine / Gitleaks SARIF.
- `GL-PIPE-007..012` (the remaining 6 controls of the ADR-003 design) and `gitlab-level-2` / `gitlab-level-3` ladder profiles.
- `F4-05` interactive wizard for `init`.
- `F4-06` official container image distribution.
- GitHub 2026 native security platform features (egress firewall, scoped secrets, workflow dependency locking) — registered as GA-dependent; will be added when each feature reaches GitHub GA.

### Documentation references

- See `docs/cra-readiness.md` for the CRA deadline framing.
- See `docs/positioning.md` for the kit's position relative to Scorecard v6, zizmor, poutine, OSV-Scanner, Harden-Runner, and the broader OSS security ecosystem.
- See `docs/decisions/adr-001-sca-scanner-choice.md` for why OSV-Scanner v2 was chosen over Trivy / Grype / Snyk OSS as the SCA primary.

---

## OSS Security Policy as Code Starter Kit v5.8.1 — 2026-05-12

UX, contract, and privacy fixes following an internal audit. No new controls, profiles, flags (other than one privacy opt-in), schemas, or subcommands.

### ⚠️ Breaking default change — `target_path` (M-002)

`evaluation-report.json` and `evaluation-report.md` previously stored `target_path` as the resolved **absolute** path of the target on the operator's machine. When a report was attached to a PR artifact, GitHub Release, or vulnerability write-up, that value leaked the auditor's home directory and login name (the Windows and POSIX flavors of an operator's user directory both produce identifiable strings).

**New default (privacy-by-default):**

- `target_path` is the target's basename (e.g. `"hardened-repo"`)
- when the target is the current working directory, `target_path` is `"."`
- stdout / stderr operator messages still show the absolute path (local-only)
- SARIF already emitted `uri: "."` for repo-level findings and is unchanged

**Affected:** any pipeline / dashboard / database that parses `target_path` and expects an absolute path. Both contracts `reports/1.0` and `reports/0.3` (and `0.2`) are sanitized.

**Migration — opt back into the legacy behavior:**

```bash
python -m oss_policy_kit evaluate --target <repo> --profile <id> \
  --output-dir <dir> --include-absolute-path
```

Use `--include-absolute-path` only when downstream tooling specifically expects an absolute path; do not enable it for reports that will be published or shared.

### Fixed

- **Privacy: `target_path` no longer leaks the auditor's home directory.** See the breaking-default section above for details and the `--include-absolute-path` opt-in. (M-002)
- **`recommend-profile` no longer suggests `release-hardening-2` from a single workflow alone.** The heuristic now requires BOTH a CI signal (workflow / pipeline / buildspec) AND release-shaped evidence JSON to be present in the clone. Repositories with only one of the two signals fall back to `*-level-1`. The previous behavior over-recommended `release-hardening-2` for any repo carrying a single workflow file — including the intentionally-unsafe `examples/vulnerable-repo`. (M-005)
- **`collect-evidence --dry-run` no longer requires the target to exist.** Dry-run is preview-only; the existence check now only applies to the real collection path. (M-003)
- **`evaluate --output-dir` returns EXIT=2 (not EXIT=3) when the path is unwritable.** Permission errors, missing parents, or a non-directory at the path now surface as `Error: Cannot write to --output-dir '<path>': <reason>` instead of `Unexpected error: <OS message>`. (M-004)

### Added

- **`controls_total` in the `reports/1.0` file payload.** The compact stdout JSON summary already exposed this field; the file did not. The new top-level integer equals `sum(summary_by_status.values())`. Contracts `0.3` and `0.2` are not touched. Schema (`evaluation-report-v1.schema.json`) updated accordingly. (M-001)

### Deprecated

- **`--show-profiles` (root option).** Still works, but emits a deprecation warning on stderr. Use the `profiles` subcommand: `python -m oss_policy_kit profiles` (default compact), `--format detailed`, or `--format json`. (M-006)

### Docs

- `docs/cli-reference.md`: the "Quick reference" table now lists all 12 subcommands. The previous table omitted `scan-bicep`, `scan-cfn`, `scan-pulumi`, and `scan-k8s`. Notes for `evaluate`, `recommend-profile`, `collect-evidence`, and the root `--show-profiles` row updated to reflect the M-002 / M-005 / M-003 / M-006 fixes above.
- `docs/adoption-guide.md`, `docs/validation-walkthrough.md`, `docs/architecture.md`: switch examples and references to the `profiles` subcommand and document `--show-profiles` as a deprecated alias. The `recommend-profile` honesty callout is rewritten to reflect the AND requirement.
- `pipelines/README.md` (new): clarifies that `pipelines/azure/azure-pipelines.yml` is the project's own Azure DevOps self-config, not an example.
- `waivers/README.md` (new): clarifies the boundary between `waivers.example.yaml` (template for consumers) and `waivers.yaml` (the project's own, currently empty).

---

## OSS Security Policy as Code Starter Kit v5.8.0

This minor release continues the v5.7 catalog-quality and refactor trajectory. It is fully backwards-compatible: no profile id, control id, evaluator function object, report contract, or CLI surface changed. `EVALUATOR_REGISTRY` remains byte-equivalent across the v5.7 -> v5.8 transition (validated by dedicated invariant tests).

### Highlights

- **Catalog and profile invariant test suites.** Three new test modules pin properties that previously had to be checked by hand:
  - `tests/data/test_catalog_consistency.py` — every catalog control has a unique id, a known category, a recognized `lifecycle` / `assurance` value, and is either referenced by at least one bundled profile or marked deprecated.
  - `tests/data/test_evidence_schemas_versioned.py` — every packaged `evidence-*.schema.json` declares a `$schema` and an explicit `oss-policy-kit/evidence/.../v<n>` `schema_version`, and the packaged copy under `src/oss_policy_kit/data/schema/` matches the mirror under `reports/schema/` byte-for-byte.
  - `tests/application/test_profile_maturity_drift.py` — guards the `docs/profiles/overview.md` maturity matrix against silent drift (every bundled profile row reflects the profile's actual lifecycle composition).

- **`evaluators.py` decomposition steps 4-8 — five new public package boundaries.** Following the v5.7 introduction of `evaluators_governance.py` / `evaluators_supply_chain.py`, this release adds:
  - `evaluators_ci_cd.py` — workflow / pipeline / build CI controls (`CI-*`, platform-agnostic).
  - `evaluators_platform.py` — platform settings controls (`PLAT-*`, `GH-PLAT-*`, `AZ-PLAT-*`).
  - `evaluators_release.py` — release-process controls (`REL-*`, `GH-REL-*`, release-archive).
  - `evaluators_vuln_management.py` — vulnerability-management controls (`DEP-UPDATE-*`, dependency review, fuzzing aggregation).
  - `evaluators_sast.py` — dedicated SAST adapter boundary. `SAST-SEMGREP-064` moved here from `evaluators_supply_chain.py` so future v5.9 adapters (Trivy, Gitleaks, Grype) plug into a single surface.

  All five modules **re-export** the existing callables from `evaluators.py` — every shim returns `EVALUATOR_REGISTRY[cid] is fn`, so the registry is identity-equivalent to v5.7.0. A new test module (`tests/application/test_evaluators_v58_shims.py`) pins both the byte-equivalence guarantee and a disjointness guarantee across all eight pack boundaries (governance, supply-chain, ci_cd, platform, release, vuln_management, sast, containers).

- **Advisory profile banner expanded to the full bundled set.** Previously the `[advisory profile]` operator banner fired only for the IaC posture profiles. It now fires for every bundled advisory profile (`iac-terraform-baseline-1`, `iac-cfn-baseline-1`, `iac-pulumi-baseline-1`, `iac-bicep-baseline-1`, `kubernetes-baseline-1`, `container-baseline-1`, `webhook-security-1`, `appsec-sast-sca-1`, plus all `osps-*` / `slsa-*` / `ssdf-*` / `cis-*` / `owasp-*` / `s2c2f-*` / `cra-*` framework profiles). Operators now get consistent guidance to run `--fail-on degraded` (not `fail`) on every advisory profile.

- **Profile maturity matrix completed to all 36 bundled profiles.** `docs/profiles/overview.md` now lists every bundled profile with its `lifecycle` blend, `assurance` blend, recommended `--fail-on` setting, and adoption stage. The matrix is locked by `tests/application/test_profile_maturity_drift.py` so future profile additions or lifecycle promotions cannot silently desync from the docs.

- **15-minute quickstart guide.** New `docs/quickstart-15-min.md` walks a brand-new adopter from `pip install` to a passing gate against the hardened example in under 15 minutes (install -> `init` -> first `evaluate` -> read the report -> wire a CI gate -> add the first waiver). Cross-linked from the README and the documentation hub.

- **`scripts/validate-bundled-profiles.py`.** New maintainer-side validator that loads every bundled profile, checks each `control_ids` member against the catalog, surfaces unknown ids / removed ids / orphan controls, and emits a non-zero exit code on any drift. Wired into the maintainer self-check flow; the test suites covering the same invariants are the authoritative gate in CI.

### Documentation

- `docs/architecture.md` — new sections covering the eight v5.8 evaluator package boundaries (governance, supply-chain, ci_cd, platform, release, vuln_management, sast, containers) and the catalog / profile / evidence invariant test suites. The trust model and evidence semantics sections are unchanged.
- `docs/quickstart-15-min.md` — new (see above).
- `docs/profiles/overview.md` — maturity matrix now complete for all 36 bundled profiles.
- `waivers/waivers.example.yaml` — two new posture-control waiver examples (Kubernetes baseline + container baseline) to demonstrate the registry pattern for non-platform profiles.

### Fixes

- **Stripped UTF-8 BOM from three GitHub evidence schemas.** `evidence-github-environment-protection.schema.json`, `evidence-github-rulesets.schema.json`, and `evidence-github-secret-scanning.schema.json` carried a leading BOM that broke strict JSON Schema loaders on some toolchains. Both the packaged copies under `src/oss_policy_kit/data/schema/` and the public mirrors under `reports/schema/` are now plain UTF-8 without BOM.
- **README factual drift corrected.** "Current release" row, "Profiles" count (32 -> 36 bundled), "What's new" anchor, two-line bootstrap blurb, and pipeline exit codes (`0 / 1 / 2 / 3`) are now consistent with the published surface.
- **Helm pre-pass tmp directory leak.** `HelmRenderOutcome` now exposes the `tempfile.mkdtemp` directory created for `helm template --output-dir`; `scan-k8s` cleans it up in a `try/finally` after the K8s rule engine consumes the rendered manifests. Previous behavior left one `oss-policy-kit-helm-*` directory per `scan-k8s --helm-render` invocation under the system tmp dir.
- **`engine.evaluate_repository` default contract documented.** The signature still defaults `report_json_contract` to `"0.3"` (programmatic API stability for v4.x callers), but the parameter now carries an explicit comment pointing v5+ programmatic callers at `"1.0"`. The CLI, `oss-policy-kit.yaml` config loader, and `init` template continue to default to `"1.0"` as documented.
- **Bandit B506 suppressed with rationale on `cfn/scanner.py`.** The CloudFormation parser uses `yaml.load(..., Loader=_CfnSafeLoader)` where `_CfnSafeLoader` is a `SafeLoader` subclass that only adds CFN short-form intrinsic constructors. `yaml.safe_load` cannot accept a custom Loader, so the explicit `# nosec B506` keeps Bandit output clean without masking real findings.

### Breaking changes

None. v5.8.0 is fully backwards-compatible with v5.7.0:

- `reports/1.0`, `reports/0.3`, `reports/0.2` shapes remain byte-stable.
- All v5.7.0 profile ids and control ids remain.
- `EVALUATOR_REGISTRY` is identity-equivalent across the v5.7 -> v5.8 transition (the five new shims re-export the same function objects).
- No new hard dependencies. The five new evaluator modules use only stdlib and existing internal imports.

### Notes

- Suite total: **1953 passed, 1 skipped** (full test run on Python 3.12 / Windows).
- `python -m ruff check src tests` clean. `python -m mypy --strict src` clean (88 source files).
- Bandit: 0 High, 0 Medium, 50 Low (informational; the previous Medium on the CFN parser is now an annotated false positive).

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v5.7.0

This minor release lands the four roadmap items declared in the v5.7 (Unreleased) section of the v5.6.0 changelog:

1. **Three new cloud-platform IaC parsers** — Pulumi (Python), CloudFormation (YAML + JSON), and Bicep — sharing the v5.5 Terraform evidence contract shape and the same honesty rules.
2. **Opt-in Helm template pre-pass for `scan-k8s`** — charts are now rendered through the system `helm` CLI instead of being silently skipped.
3. **Webhook receiver security pack** — `SEC-WEBHOOK-001` (signature validation) and `SEC-WEBHOOK-002` (replay defense) bundled into the new `webhook-security-1` profile.
4. **`evaluators.py` decomposition steps 2 & 3** — `evaluators_governance.py` and `evaluators_supply_chain.py` modules introduced as public package boundaries; `EVALUATOR_REGISTRY` is byte-equivalent across the v5.6 -> v5.7 transition (validated by a dedicated invariant test).

`reports/1.0`, `reports/0.3`, `reports/0.2` shapes remain byte-stable. No new hard dependencies were added; the new IaC scanners use stdlib (`ast`, `re`) or already-vendored deps (`PyYAML`).

---

### Highlights

- **New `scan-cfn` subcommand + 6 `IAC-CFN-*` controls.** `scan-cfn` walks `*.yaml` / `*.yml` / `*.json` / `*.template` files (skipping vendored / cache dirs), parses every CloudFormation template via PyYAML (with a tolerant loader that decodes short-form intrinsics like `!Ref`, `!Sub`, `!GetAtt` into the long-form dict shape), runs the bundled rule pack, and writes evidence under `.oss-policy-kit/evidence/iac-cfn.json` (schema `oss-policy-kit/evidence/iac-cfn/v1`). The 6 rules cover: public S3 (`IAC-CFN-001`), open management ports on `AWS::EC2::SecurityGroup` (`IAC-CFN-002`), IAM `AdministratorAccess` / wildcard Action+Resource (`IAC-CFN-003`), missing encryption-at-rest on S3 / RDS / EBS / DynamoDB / SNS / SQS (`IAC-CFN-004`), audit/logging gaps (`IAC-CFN-005`), and accidental public IPs (`IAC-CFN-006`). All 6 ship as `lifecycle: experimental`, `assurance: evidence-backed`. New advisory bundled profile `iac-cfn-baseline-1` (7 controls = 6 IAC-CFN-* + `GOV-EVIDFRESH-054`). No new dependency — PyYAML is already a hard dep.

- **New `scan-pulumi` subcommand + 6 `IAC-PUL-*` controls.** `scan-pulumi` walks `*.py` files, uses the stdlib `ast` module to extract Pulumi resource constructors (e.g. `aws.s3.Bucket(...)`, `pulumi_aws.iam.RolePolicyAttachment(...)`), and writes evidence under `.oss-policy-kit/evidence/iac-pulumi.json` (schema `oss-policy-kit/evidence/iac-pulumi/v1`). Best-effort by design: unresolved variable references and non-literal kwargs are treated as indeterminate (no false positives). The 6 rules cover: public storage (`IAC-PUL-001`), open management ports (`IAC-PUL-002`), IAM wildcards (`IAC-PUL-003`), missing encryption-at-rest (`IAC-PUL-004`), default network primitives (`IAC-PUL-005`), accidental public IPs (`IAC-PUL-006`). All 6 ship as `lifecycle: experimental`, `assurance: evidence-backed`. New profile `iac-pulumi-baseline-1`. **Scope:** Pulumi Python programs only; TypeScript / Go / .NET are out of scope for v5.7 and tracked for a future release.

- **New `scan-bicep` subcommand + 6 `IAC-BICEP-*` controls.** `scan-bicep` walks `*.bicep` files and uses a pure-Python regex tokenizer (no `bicep` CLI required, no extra deps) to extract `resource <symbolic> '<type>@<ver>' = { ... }` declarations with their literal property bodies, then runs the bundled rule pack. Evidence is written under `.oss-policy-kit/evidence/iac-bicep.json` (schema `oss-policy-kit/evidence/iac-bicep/v1`). The 6 rules cover: public storage accounts (`IAC-BICEP-001`), NSG security rules with management ports open to `*` (`IAC-BICEP-002`), high-privilege Azure role assignments (Owner / Contributor / User Access Administrator, by their built-in roleDefinition GUIDs) (`IAC-BICEP-003`), missing encryption on Storage / SQL / Disk (`IAC-BICEP-004`), sensitive resources without paired `diagnosticSettings` (`IAC-BICEP-005`), and direct `publicIPAddresses` declarations (`IAC-BICEP-006`). All 6 ship as `lifecycle: experimental`, `assurance: evidence-backed`. New profile `iac-bicep-baseline-1`.

- **Helm template pre-pass for `scan-k8s` (opt-in via `--helm-render`).** `scan-k8s --helm-render` discovers every `Chart.yaml` under the target, invokes the system `helm template` for each chart (no network access, no install — operates on the chart sources already in the clone), and merges the rendered manifests into the regular K8s scan. Charts that fail to render are recorded in `helm_render_errors` and the scan continues with what it could parse. When the `helm` CLI is not on `PATH`, the scanner records a diagnostic and continues without rendering (graceful degradation; never crashes). Six new fields are added to the `k8s-baseline.json` evidence shape: `helm_render_attempted`, `helm_available`, `helm_version`, `helm_charts_discovered`, `helm_charts_rendered`, `helm_render_errors`. Default behavior is unchanged (rendering is off unless `--helm-render` is passed).

- **Webhook receiver security pack** (`SEC-WEBHOOK-001`, `SEC-WEBHOOK-002`). Two new clone-visible signal controls covering the two most common webhook-receiver weaknesses: missing signature validation and missing replay defense. The kit walks up to 400 source files of recognized server-side languages (`.py`, `.js`, `.ts`, `.go`, `.rb`, `.java`, `.cs`, `.php`, `.rs`) and looks for the conjunction of (a) a webhook route declaration and (b) a recognized signature / replay primitive (e.g. `X-Hub-Signature-256`, `Stripe-Signature`, `X-Signature-Ed25519`, `hmac.compare_digest`, `X-GitHub-Delivery` dedupe, `idempotency-key`, …). Both controls return `not-applicable` when no webhook route is found in the clone (so non-receiver repositories are never penalized). Both ship as `lifecycle: experimental`, `assurance: signal`. New profile `webhook-security-1` (3 controls = `SEC-WEBHOOK-001` + `SEC-WEBHOOK-002` + `GOV-EVIDFRESH-054`).

- **`evaluators_governance.py` + `evaluators_supply_chain.py` package boundaries** (refactor steps 2 & 3). These modules are the new public surface for the governance and supply-chain control packs. They re-export the existing callables from `evaluators.py` via `build_governance_evaluators()` / `build_supply_chain_evaluators()` so that **`EVALUATOR_REGISTRY` stays byte-equivalent** across the v5.6 -> v5.7 transition. A dedicated invariant test (`test_governance_shim_returns_identical_callables` / `test_supply_chain_shim_returns_identical_callables`) pins the guarantee by asserting `EVALUATOR_REGISTRY[cid] is fn` for every shim-built entry. Future v5.8 work will move the function bodies into these modules incrementally so each move can be validated against the same guarantee in isolation.

---

### Catalog & profiles

- Bundled profiles: **32 -> 36** (added `iac-cfn-baseline-1`, `iac-pulumi-baseline-1`, `iac-bicep-baseline-1`, `webhook-security-1`).
- Catalog total: **+20 controls** (6 CFN + 6 PUL + 6 BICEP + 2 WEBHOOK). All 20 ship as `lifecycle: experimental`. CFN / Pulumi / Bicep are `assurance: evidence-backed`; SEC-WEBHOOK is `assurance: signal`.
- `recommend-profile` heuristic is unchanged for v5.7.0 — the four new profiles are deliberate operator choices, not auto-suggested. The `[advisory profile]` banner fires when one of the new IaC profiles is selected.

---

### CLI changes

- `evaluate` honors the v5.6 evidence-missing banner for the three new evidence files (`iac-cfn.json`, `iac-pulumi.json`, `iac-bicep.json`) — operators who run an evaluate against one of the four new profiles without first running the matching `scan-*` command get a prominent stderr note pointing them at the right command.
- `scan-k8s --helm-render` is the only behavioral switch on an existing CLI; default behavior is byte-stable.
- `scan-cfn`, `scan-pulumi`, `scan-bicep` are new positional-friendly subcommands (the leading-path dispatch in `prepare_cli_args` recognizes them so `python -m oss_policy_kit scan-cfn` works the same as `python -m oss_policy_kit scan-iac`).

---

### Breaking changes

None. v5.7.0 is fully backwards-compatible with v5.6.0:

- `reports/1.0`, `reports/0.3`, `reports/0.2` shapes are byte-stable.
- All v5.6.0 profile IDs and control IDs remain.
- `EVALUATOR_REGISTRY` is byte-equivalent across the v5.6 -> v5.7 transition — the governance / supply-chain extraction is a re-export, not a move.
- All new controls are `experimental` and only fire when included in a profile (the four bundled `*-baseline-1` / `webhook-security-1` profiles are the only profiles that include them today).
- No new hard dependencies. CFN uses PyYAML (already a hard dep); Pulumi uses stdlib `ast`; Bicep is pure regex; the Helm pre-pass shells out to the system `helm` CLI only when `--helm-render` is explicitly requested.

---

### Notes

- New tests: 59 new cases across `tests/application/test_evaluators_iac_cfn.py`, `tests/application/test_evaluators_iac_pulumi.py`, `tests/application/test_evaluators_iac_bicep.py`, `tests/application/test_evaluators_webhook.py`, `tests/application/test_evaluators_governance_shim.py`, `tests/application/test_helm_renderer.py`, and `tests/cli/test_scan_cfn_pulumi_bicep.py`. Suite total: **870 -> 929 passed**, 1 skipped.
- Active runtime probes remain explicitly **out of scope**. The kit stays clone-visible by design.

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v5.6.0

### Added (already landed in this dev cycle)

- **Native Kubernetes manifest coverage + new `kubernetes-baseline-1` advisory profile.** New `scan-k8s` subcommand walks `*.yaml` / `*.yml` files under the target (skipping `.git`, `.terraform`, `node_modules`, `.venv`, `__pycache__`, `dist`, `build`, `.oss-policy-kit`), detects Helm templates by their `{{ ... }}` markers and skips them with a diagnostic, parses every multi-doc YAML via PyYAML's `safe_load_all`, runs the bundled rule pack, and writes evidence under `.oss-policy-kit/evidence/k8s-baseline.json` (schema `oss-policy-kit/evidence/k8s-baseline/v1`). Sixteen new `K8S-*` controls split as: ten Pod Security Standards rules (`K8S-PSS-001..010` covering privileged containers, hostPID/hostNetwork/hostPath usage, capability adds, runAsRoot, privilege escalation, read-only root filesystem, automountServiceAccountToken pinning, and floating image tags); five RBAC rules (`K8S-RBAC-001..005` covering wildcard verbs, cluster-admin bindings, default ServiceAccount in default namespace, ClusterRole wildcard resources, and broad secrets reads); and one NetworkPolicy presence rule (`K8S-NETPOL-001`). All sixteen ship as `lifecycle: experimental`, `assurance: evidence-backed`. New advisory bundled profile `kubernetes-baseline-1` (19 controls = 16 K8S-* + 3 sustaining governance). Bundled profiles: **31 → 32**. Lives in `application/evaluators_k8s.py` + `infrastructure/k8s/scanner.py` and is wired via `_load_k8s_evaluators()`. PyYAML is already a hard dependency, so no `not_available` path is needed (unlike `scan-iac`). Test surface: 44 new cases in `tests/application/test_evaluators_k8s.py` plus 4 CLI smoke cases in `tests/cli/test_scan_k8s.py`. Suite total after this commit: **820 passed**.

- **Container hardening pack + new `container-baseline-1` advisory profile.** Seven new experimental controls extending the existing `CONT-IMAGE-001/002/003` family with clone-visible Dockerfile / workflow signals: `CONT-RUNTIME-001` (multi-stage build), `CONT-RUNTIME-002` (HEALTHCHECK declared), `CONT-RUNTIME-003` (no `curl|bash` / `wget|sh` patterns in RUN), `CONT-RUNTIME-004` (`.dockerignore` present), `CONT-RUNTIME-005` (apt-get hygiene: `--no-install-recommends` or cache cleanup), `CONT-RUNTIME-006` (OS package versions pinned in apt/apk install), and `CONT-SIGN-001` (image signed via cosign or GitHub artifact attestations: `sigstore/cosign-installer`, `actions/attest-build-provenance`, `actions/attest-sbom`, `gh attestation`). Each rule degrades to `NOT_APPLICABLE` when there is no Dockerfile in the clone (so non-containerized repos do not penalty themselves). All seven ship as `lifecycle: experimental`, `assurance: signal`. Bundled into the new `container-baseline-1` advisory profile (13 controls total, including `CONT-IMAGE-001/002/003` and three sustaining governance controls). Bundled profiles: **30 → 31**. Lives in `application/evaluators_containers.py` and is wired via `_load_container_evaluators()`. Test surface: 33 new cases in `tests/application/test_evaluators_containers.py`.

- **Internal `evaluators_common.py` extraction (refactor step 1).** Extracted the small set of cross-module helpers (`evidence_is_api_backed`, `evidence_placeholder_outcome`, `validate_json_evidence`, `is_valid_sha256_digest`, `load_packaged_schema`) plus the placeholder/invalid-digest reason strings into `application/evaluators_common.py`. `evaluators.py` re-imports them under their underscore-prefixed legacy names so every existing call site keeps byte-equivalent semantics. Net effect: `evaluators.py` shrinks ~123 lines (4926 → 4803) and the new evaluator modules (`evaluators_iac`, `evaluators_fuzzing`, and the upcoming `evaluators_containers` / `evaluators_k8s`) can import shared utilities without going through the megafile. `EVALUATOR_REGISTRY` membership unchanged; suite passes 731/731.

- **`SEC-FUZZ-001` — fuzzing presence signal.** New experimental control under the `vulnerability_management` category that PASSes when any of the following clone-visible signals is detected: a populated `fuzz/` / `fuzzing/` / `fuzzers/` / `tests/fuzz/` directory; a fuzz-target filename (`fuzz_target*`, `_fuzz.py`, `_fuzz.go`, `fuzz.cc`, …); a known fuzzing-runner reference inside the first 4 KiB of code/config files (`atheris`, `libfuzzer`, `honggfuzz`, `cifuzz`, `go-fuzz`, `oss-fuzz`, `cargo-fuzz`, `clusterfuzzlite`); or an OpenSSF Scorecard `Fuzzing` check with `score >= 7` from the optional Scorecard JSON evidence already wired through `EvalContext.scorecard`. Without any of those, the control returns `manual-review-required` with remediation pointing to OSS-Fuzz / ClusterFuzzLite / cifuzz / atheris. Lifecycle `experimental`, assurance `signal`, weight `2`. Bundled into `github-level-3`, `azure-level-3`, `aws-level-3`, `github-release-hardening-3`, `azure-release-hardening-3`, and `aws-release-hardening-3`. Lives in its own module (`application/evaluators_fuzzing.py`) and is wired via `_load_fuzzing_evaluators()` so the import-time registry stays small.

### Removed (already landed in this dev cycle)

- **`AWS-CC-046` deleted (and the entire CodeCommit collector path that fed it).** Deprecated in v5.4.0; AWS CodeCommit upstream entered maintenance mode in 2024-07 and is closed to new customers. This release removes:
  - The `AWS-CC-046` catalog entry, its evaluator (`eval_aws_cc_046`), the schema-loader helper (`_aws_codecommit_review_schema`), and its `EVALUATOR_REGISTRY` slot.
  - The `evidence-aws-codecommit-review-posture.schema.json` schema (both the packaged copy and the `reports/schema/` mirror).
  - The CodeCommit branch of `AWSEvidenceCollector` (`_collect_codecommit`, `_normalize_codecommit_name`, the approval-rule template helpers, and the integration in `collect()`).
  - The CodeCommit entry in `evidence_scaffold.py` (`aws-codecommit-review-posture.json` template) and the matching member of `AWS_EVIDENCE_FILENAMES` in `profile_hints.py`.
  - The CodeCommit row in `collect-evidence --platform aws --dry-run` and the `--repo` requirement on the AWS path. `--repo` is still accepted on the CLI for GitHub / Azure DevOps; AWS now drives only off `AWS_CODEBUILD_PROJECT` and `AWS_CODEPIPELINE_NAME`.
  - All AWS-CC-046 references from `docs/controls-catalog.md`, `docs/architecture.md`, `docs/adoption-guide.md`, `docs/collector-parity.md`, `docs/osps-mapping.md`, `docs/profiles/overview.md`, `docs/profiles/release-hardening-3-howto.md`, `docs/profiles/aws.md`, `docs/azure-aws-collector-privacy.md`, and `docs/evidence-pack.md`, plus the descriptive prose in `aws-level-3` / `aws-release-hardening-3` profile YAMLs.
  - Suite total: **720 → 717** (3 CodeCommit-specific tests removed; no test failures introduced).

  External profiles still referencing `AWS-CC-046` should pin to v5.5.x or migrate to a different SCM signal. The other AWS controls (`AWS-CP-044`, `AWS-CB-045`, `AWS-PIPEIAM-056`, `AWS-CBIDENT-057`) continue to cover the dominant AWS CI/CD path.

`reports/1.0`, `reports/0.3`, `reports/0.2` shapes remain byte-stable. No new hard dependencies.

---

## OSS Security Policy as Code Starter Kit v5.5.0

This minor release adds **native Terraform / OpenTofu IaC posture coverage** as the headline feature. The kit now ships an in-process HCL parser, a 12-rule pack covering the highest-leverage clone-visible IaC risks, a new `scan-iac` subcommand, and an advisory bundled profile (`iac-terraform-baseline-1`). Mirrors the v5.4.0 SAST integration shape exactly: same evidence contract, same honesty when the parser library is missing.

---

### Highlights

- **New `scan-iac` subcommand + 12 `IAC-TF-*` controls.** `scan-iac` walks `*.tf` files (skipping `.terraform`, `node_modules`, `.git`, `.venv`, `__pycache__`, `dist`, `build`, `.oss-policy-kit`), parses HCL via `python-hcl2`, runs the bundled rule pack, and writes evidence under `.oss-policy-kit/evidence/iac-terraform.json` (schema `oss-policy-kit/evidence/iac-terraform/v1`). Each `IAC-TF-*` control is a thin reader of that evidence file. The 12 rules cover: object storage public access (`IAC-TF-001`), open management ports (`IAC-TF-002`), IAM AdministratorAccess / wildcard Action+Resource (`IAC-TF-003`), missing encryption-at-rest (`IAC-TF-004`), audit/logging gaps (`IAC-TF-005`), default-VPC reliance (`IAC-TF-006`), accidental public IPs (`IAC-TF-007`), missing owner/cost_center tags (`IAC-TF-008`), unpinned providers (`IAC-TF-009`), local backend state (`IAC-TF-010`), production data stores missing `lifecycle.prevent_destroy` (`IAC-TF-011`), and `data.aws_iam_policy_document` wildcard principals (`IAC-TF-012`). All 12 ship as `lifecycle: experimental`, `assurance: evidence-backed`. `python-hcl2` is **not** a hard dependency; install the iac extra (`pip install 'oss-policy-kit[iac]'`) when you want real findings, otherwise evidence is written with `status: not_available` and evaluators report `manual-review-required`.

- **New bundled profile `iac-terraform-baseline-1`** (15 controls = 12 IAC-TF-* + 3 sustaining governance). Multi-platform, advisory by design. Recommended `--fail-on degraded` only. The `[advisory profile]` banner fires when this profile is selected. Total bundled profiles: **29 → 30**.

- **Documentation:** new `docs/iac-terraform.md` with the full adoption playbook (rule reference, CLI flags, honesty contract, composition patterns with existing platform ladders, waiver guidance, roadmap).

---

### Improvements

- `pyproject.toml` adds the `iac` extra (`python-hcl2>=6.1`) and rolls it into `all` and `dev`.
- `EvalContext`-shaped evaluators are wired via a separate `_load_iac_evaluators()` loader so the existing import-time registry stays small and the package boundary is clean (preview of the v5.6 evaluators-package refactor).
- `oss-policy-kit/evidence/iac-terraform.schema.json` ships under `data/schema/` for downstream consumers that want to validate the evidence shape.

---

### Breaking changes

None. v5.5.0 is fully backwards-compatible with v5.4.0:

- `reports/1.0`, `reports/0.3`, `reports/0.2` shapes are byte-stable.
- All v5.4.0 profile IDs and control IDs remain.
- `IAC-TF-*` controls are `experimental` and only fire when included in a profile (the bundled `iac-terraform-baseline-1` is the only profile that includes them today).
- `python-hcl2` is an optional extra. Existing installs continue to work without it; the IaC controls degrade to `manual-review-required`.

---

### Notes

- Removal of `AWS-CC-046` (deprecated in v5.4.0) is still scheduled for v5.6.0.
- The internal refactor of `application/evaluators.py` into a category-based package is staged for v5.6 alongside additional cloud-platform IaC parsers (Pulumi / CloudFormation / Bicep).
- New tests: 23 invariants in `tests/application/test_evaluators_iac.py` (including parametrized vulnerable+hardened pairs for every rule) and 4 CLI smoke cases in `tests/cli/test_scan_iac.py`. Suite total: **689 → 720 passed**.

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v5.4.0

This minor release moves the kit from "evaluator only" to "starter kit you can actually adopt": it adds the `init` wizard, makes `evaluate` config-aware, ships an official **GitHub Action** for the Marketplace, and introduces the first **real SAST integration** (Semgrep) with a stable evidence contract. Existing contracts (`reports/1.0`, profile IDs, control IDs, evidence schemas) are unchanged.

---

### Highlights

- **Seven new bundled framework-alignment profiles** (multi-platform, no platform prefix): `osps-baseline-1` (OpenSSF OSPS Baseline), `slsa-build-l2-1` (SLSA v1.1 Build L2), `ssdf-baseline-1` (NIST SP 800-218), `cis-supply-chain-1` (CIS Software Supply Chain Security Benchmark v1.0), `owasp-cicd-top10-1` (OWASP CI/CD Top 10 2022), `s2c2f-l1-1` (Microsoft S2C2F Level 1, OSS consumption baseline), and `cra-eu-strict-1` (EU CRA full-obligations track for 2027-12-11). All seven combine existing controls from the 70-control catalog into framework-specific bundles; **no new control IDs were added**. Two profiles are hard-gate-capable when evidence is present (`slsa-build-l2-1`, `cra-eu-strict-1`); the other five are advisory mappings (`--fail-on degraded` recommended). Detailed mapping per framework documented in `docs/framework-alignment.md`. The `recommend-profile` heuristic does not auto-suggest these profiles - they are deliberate operator choices, mirroring the existing pattern for `cra-eu-ready-1`.

- **`SAST-SEMGREP-064` promoted to `lifecycle: stable`** and new bundled profile **`appsec-sast-sca-1`** (11 controls) introduced as the first profile to consume it. The AppSec native bundle combines SAST (`SEC-CODEQL-010`, `SAST-SEMGREP-064`), SCA (`SEC-DEPREV-011`, `DEP-UPDATE-001`, `SEC-PINLOCK-052`), secret scanning (`SEC-SECRETS-050`, `SEC-GITIGNORE-051`, `GH-PLAT-026`), and dependency integrity controls (`CI-PIN-008`, `CI-WFCALLSHA-055`), plus governance sustaining (`GOV-WAIV-014`). It is **hard-gate-capable when paired with `oss-policy-kit scan-sast`**; without the SAST evidence file, `SAST-SEMGREP-064` returns `manual-review-required` (does not trip `--fail-on fail`). Total bundled profiles: **21 → 29**.

- **New `init` subcommand**: zero-friction project bootstrap.
  - Detects the CI platform (GitHub / Azure / AWS) and primary language stack from the repository layout, reusing the same heuristic that powers `recommend-profile`.
  - Writes a persisted `oss-policy-kit.yaml` config (schema `oss-policy-kit/config/v1`) capturing the chosen profile, fail-on policy, output directory, detected signals, and generator metadata.
  - Optional flags compose into a single run: `--with-waivers`, `--with-evidence`, `--with-workflow`.
  - Idempotent by default; `--dry-run` previews every action; `--format json` emits a stable JSON shape (`oss-policy-kit/init-result/v1`).

- **`evaluate` is now config-aware**. When `--profile` is omitted, `evaluate` looks for `oss-policy-kit.yaml` under `--target` and uses the recorded profile. The fallback is logged on stderr (`Using profile from oss-policy-kit.yaml: ...`) so operators always know which profile is being applied. Explicit `--profile` always wins.

- **GitHub Action published as a composite action** (`action.yml` at repository root). Inputs map 1:1 to CLI flags; outputs expose absolute paths to the generated reports and the captured exit code. SARIF is opt-in. Pinning by tag (`@v5.4.0`), branch (`@v5`), or commit SHA all work.

- **New `scan-sast` subcommand + `SAST-SEMGREP-064` control**. `scan-sast` runs Semgrep (when installed) against the target and writes a normalized evidence file (`.oss-policy-kit/evidence/sast-semgrep.json`, schema `oss-policy-kit/evidence/sast-semgrep/v1`). `SAST-SEMGREP-064` (lifecycle: `stable`, assurance: `evidence-backed`) consumes that evidence: HIGH/CRITICAL findings → `fail`; missing or `not_available` evidence → `manual-review-required` with explicit remediation. Semgrep is **not** a hard dependency: `pip install semgrep` is documented but optional.

- **`AWS-CC-046` deprecated; scheduled for removal in v5.6.0.** AWS CodeCommit entered maintenance mode upstream in 2024-07 and is closed to new customers. The control is not bundled into any profile, so default flows are unaffected. The catalog entry now carries `lifecycle: deprecated` and a `deprecation_note` pointing to v5.6.0 removal. External profiles that reference `AWS-CC-046` should pin to v5.5.x or migrate to a different SCM signal before v5.6.0. The other AWS controls (`AWS-CP-044`, `AWS-CB-045`, `AWS-PIPEIAM-056`, `AWS-CBIDENT-057`) remain stable and continue to cover the dominant AWS CI/CD path.

---

### Improvements

- `prepare_cli_args` allowlists `init` and `scan-sast` so positional invocations dispatch correctly.
- `docs/cli-reference.md` gains a "Project Initialization" section and updated quick-reference table.
- `docs/github-action.md` documents the Marketplace action with inputs, outputs, permissions, and SARIF forwarding.
- `templates/workflows/oss-policy-kit-marketplace-action.yml` is a copy/paste reusable workflow that consumes the published action.
- Plugin entry-point loader for external evaluators is preserved unchanged; built-in IDs cannot be overridden.

---

### Breaking changes

None. v5.4.0 is fully backwards-compatible with v5.3.0:

- `reports/1.0`, `reports/0.3`, `reports/0.2` shapes are byte-stable.
- All v5.3.0 profile IDs and control IDs remain.
- The new `oss-policy-kit.yaml` config is **optional**: existing pipelines that pass `--profile` explicitly behave identically.
- `SAST-SEMGREP-064` is `stable` and is bundled into `appsec-sast-sca-1`. Profiles that omit the control retain v5.3.0 behavior; existing reports do not change shape.

---

### Notes

- This is a minor release in the `5.x` line.
- New tests:
  - `tests/cli/test_init.py` — 12 cases for `init`.
  - `tests/application/test_config_loader.py` — config parsing happy/sad paths.
  - `tests/cli/test_evaluate_with_config.py` — integration tests for `evaluate` reading `oss-policy-kit.yaml`.
  - `tests/application/test_profile_schemas.py` — 5 parametrized invariants validating every bundled profile (required fields, id matches directory, controls exist in catalog, no duplicates, floor of 21 profiles).
- `appsec-sast-sca-1` is shipped in this release alongside the promotion of `SAST-SEMGREP-064` to `stable`; both items are documented above under Highlights and `docs/profiles/overview.md` / `docs/framework-alignment.md`.
- New tests covering the AppSec native bundle: `tests/application/test_appsec_sast_sca_1.py` (profile invariants and honest-gap behavior when SAST evidence is absent).

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v5.3.0

This minor release is a **maturity / metadata** release: it promotes the four `experimental` controls introduced in v5.1.0 / v5.2.0 to `stable`, sharpens the **CRA boundary** of the two hybrid profiles, and documents the concrete plan for the next collector parity expansion.

---

### Highlights

- **Lifecycle promotion**: `AUDIT-STREAM-060`, `PROV-VERIFY-061`, `GH-RUNNER-062`, `RELEASE-ARCHIVE-063` move from `experimental` → `stable`. After a full minor cycle (v5.1.0 + v5.2.0) of maintainer validation against the bundled hardened fixture, the contracts are solid enough to commit to `5.x` wire stability.
- **Hybrid profile sharpening**: `github-aws-level-2` and `github-azure-level-2` `description:` fields gain an explicit **CRA caveat**: "this hybrid does not satisfy EU Cyber Resilience Act single-product evidence; CRA expects per-product SBOM and provenance bound to one shipping pipeline. Run `cra-eu-ready-1` or one of the platform-specific `*-release-hardening-3` profiles for CRA-aligned posture." This matches the existing `posture: multi_platform_advisory_hybrid` honesty contract.
- **Collector parity plan**: `docs/collector-parity.md` documents the next collector expansion targets (audit-log streaming on GitHub / Azure / AWS, runner-groups on GitHub, provenance verification via `gh attestation verify`).

---

### Improvements

- Catalog `lifecycle` for the four v5.1.0 / v5.2.0 controls is now `stable`. `profiles --format json` continues to expose `lifecycle` per control as before.
- `docs/collector-parity.md` "Planned collector additions (post-v5.2.0)" section makes the operator expectation explicit until the next collector implementation lands.

---

### Breaking changes

None. v5.3.0 is fully backwards-compatible with v5.2.0:

- `reports/1.0`, `reports/0.3`, `reports/0.2` shapes are byte-stable.
- All v5.2.0 profile IDs and control IDs remain.
- Lifecycle change from `experimental` → `stable` is a tightening of the maintainer commitment, not a behavioral change.

---

### Notes

- This is a minor release in the `5.x` line.
- Collector implementations for the new endpoints are tracked for v5.3.x or v5.4.x (separate work; not in this release).
- No new tests were added for v5.3.0 — the existing 539 pass with the lifecycle metadata change.

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v5.2.0

This minor release introduces the **first non-platform-prefixed profile** (`cra-eu-ready-1`), adds two evidence-collectable controls, and matures the loader / `profiles --format json` to surface multi-platform regulatory profiles. EU CRA reporting deadline (2026-09-11) is the driver.

---

### Highlights

- New profile **`cra-eu-ready-1`** — multi-platform advisory profile mapping the kit's existing controls to **EU Cyber Resilience Act** preparation. 12 controls covering CycloneDX SBOM, vulnerability handling, branch-protection (history integrity), audit-log streaming, signed-provenance verification, and 10-year release archival. Posture: `advisory`. Recommended `--fail-on degraded` only. **First non-platform-prefixed profile in the catalog.**
- Added control **`GH-RUNNER-062`** (lifecycle: `experimental`, assurance: `signal`) — closes OWASP CICD-SEC-7 (Insecure System Configuration) on the GitHub side. Direct response to the 2026-03 trivy-action force-push incident: detects PR-triggered self-hosted workflows (FAIL), self-hosted without `ephemeral` label (manual-review-required), and uniform `[self-hosted, ephemeral]` posture (PASS at signal grade). Evidence-backed promotion via `.oss-policy-kit/evidence/runner-groups.json`.
- Added control **`RELEASE-ARCHIVE-063`** (lifecycle: `experimental`, assurance: `signal`) — closes NIST SSDF PS.3 (Archive & protect each release) GAP. Signal layer detects `RELEASE_ARCHIVAL.md`, `.github/release-archival.yml`, or "release archival" / "retention policy" sections in `docs/release-readiness.md`. Evidence-backed via `.oss-policy-kit/evidence/release-archival-policy.json` with `retention_years` (≥10 aligns with EU CRA), `archive_destination`, and `vulnerability_handling_doc`.

---

### Improvements

- **Loader** now accepts profile IDs without a platform prefix. `profile-list/v2` emits `family: "multi"` for those profiles; the existing 20 profiles continue to emit `family: github | azure | aws`.
- **`profiles --format json`** gains `posture: "framework_aligned_advisory"` and `live_signal_posture: "regulatory_mapping_no_release_gate"` for regulatory profiles.
- **`profiles --family multi`** filter is now valid (in addition to `github | azure | aws`).
- **`recommend-profile`** does not suggest non-platform profiles — they are regulatory mappings, not heuristic recommendations.
- **`docs/framework-alignment.md`** EU CRA section now references `cra-eu-ready-1` directly.
- New JSON Schema `evidence-runner-groups.schema.json` (v1) and `evidence-release-archival-policy.schema.json` (v1) (mirrored under `reports/schema/`).
- Bundled hardened fixture grew two synthetic evidence files (`runner-groups.json`, `release-archival-policy.json`) so `*-release-hardening-3` profiles continue to reach `summary_by_status.fail == 0`.

---

### Breaking changes

None. v5.2.0 is fully backwards-compatible with v5.1.0:

- `reports/1.0`, `reports/0.3`, `reports/0.2` shapes are byte-stable.
- All v5.1.0 profile IDs and control IDs remain.
- v5.0.0 / v5.1.0 evidence files continue to validate.

The new control IDs (`GH-RUNNER-062`, `RELEASE-ARCHIVE-063`) only appear when a profile that includes them is selected.

---

### Notes

- This is a minor release in the `5.x` line.
- The two new controls and the new profile are marked `lifecycle: experimental`. They will be promoted to `stable` after one minor cycle of operator feedback.
- `cra-eu-ready-1` is **not** a CRA certification claim. Honesty contract is in the profile YAML `description:` and in `docs/framework-alignment.md` (EU Cyber Resilience Act section).
- Suite: 539 passed, 1 skipped (vs. 519 in v5.1.0).

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v5.1.0

This minor release closes two long-standing framework-alignment gaps in the bundled catalog without breaking any existing contract: **OWASP CICD-SEC-10 (logging/visibility)** and **SLSA Build L2 "Provenance signed"** both move from PARTIAL/GAP to YES via two new evidence-backed controls.

---

### Highlights

- Added control **`AUDIT-STREAM-060`** (lifecycle: `experimental`, assurance: `evidence-backed`) — verifies organization-level audit log streaming to a centralized SIEM / object store. Closes OWASP CICD-SEC-10, AWS Well-Architected "Enable Traceability" (PARTIAL), and Azure DevOps "Audit logs / SIEM" (GAP→YES). Signal-grade fallback when no evidence file is present.
- Added control **`PROV-VERIFY-061`** (lifecycle: `experimental`, assurance: `evidence-backed`) — verifies that the build provenance attestation is independently verifiable (sigstore / `gh attestation verify`). Closes SLSA Build L2 PARTIAL → YES. Reads a new optional `verification:` block on `*-provenance-artifact.json` files.
- Both new controls are wired into all 6 hard-gate profiles (`*-level-3`, `*-release-hardening-3`).
- Refreshed `docs/framework-alignment.md` with SLSA v1.2 Source Track section, EU CRA section (with honesty contract), and a "NIST SP 800-218A AI" out-of-scope acknowledgement.
- Added `docs/v5.1.0-migration-guide.md` documenting the additive changes.

---

### Improvements

- New JSON Schema `evidence-audit-log-streaming.schema.json` (v1) for the `audit-log-streaming.json` evidence file.
- New JSON Schema `evidence-github-provenance-artifact.schema.json` (v1), mirroring the Azure/AWS shape.
- Existing `evidence-azure-provenance-artifact.schema.json` and `evidence-aws-provenance-artifact.schema.json` gain an optional `verification:` block (additive; old files still validate).
- `docs/release-readiness.md` adds an explicit **EU CRA awareness — 2026-09-11 reporting deadline** block calling out SBOM, retention, and vulnerability-handling requirements that the kit's existing controls support technically (without claiming legal compliance).
- The bundled hardened fixture grew three synthetic evidence files (`audit-log-streaming.json`, `github-provenance-artifact.json`, plus `verification:` blocks added to the existing Azure/AWS provenance files) so the 6 hard-gate profiles still reach `summary_by_status.fail == 0` end-to-end.

---

### Breaking changes

None. v5.1.0 is fully backwards-compatible with v5.0.0:

- `reports/1.0`, `reports/0.3`, `reports/0.2` shapes are byte-stable.
- The 20 existing profile IDs and 65 v5.0.0 control IDs are unchanged.
- v5.0.0 evidence files continue to validate.

The two new control IDs (`AUDIT-STREAM-060`, `PROV-VERIFY-061`) appear as new rows in `results[]` only when a profile that includes them is selected (i.e. one of the 6 hard-gate profiles).

---

### Notes

- This is a minor release in the `5.x` line.
- The two new controls are marked `lifecycle: experimental` — they will be promoted to `stable` after one minor cycle of operator feedback.
- The kit does **not** claim CRA certification; the framework-alignment table is mapping documentation, not a compliance attestation.
- Review `docs/v5.1.0-migration-guide.md` for the verification recipe.

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v5.0.0

This major release graduates the evaluation report to a stable wire contract (`reports/1.0`), introduces the Evidence Model v2 with explicit trust semantics, adds SARIF 2.1.0 output for direct ingestion by code-scanning systems, removes the legacy profile alias `github-release-hardening`, and tightens the public-hygiene posture of the repository. Older report contracts remain selectable for the entire `5.x` line so downstream parsers can migrate at their own pace.

---

### Highlights

- Promoted the evaluation JSON report to the new default contract `reports/1.0`, decoupled from the package version
- Introduced the Evidence Model v2 with structured per-result `evidence` objects, explicit trust levels, freshness and attestation status, and limitation text
- Added SARIF 2.1.0 output via `--sarif-output PATH` on `evaluate`, with stable per-finding fingerprints and honest repository-level vs file-level location handling
- Removed the legacy bundled profile alias `github-release-hardening`, with an actionable migration error pointing to the canonical `github-release-hardening-1`
- Removed `reports/0.1` from the CLI selector, replaced by an explicit migration error
- Re-encoded the bundled v3 evaluation-report schema as UTF-8 without BOM for cleaner downstream validation
- Added a public-hygiene scanner (`scripts/check_public_hygiene.py`) used as a release gate
- Added a documented signal-control audit so a `pass` on a signal-grade control is never confused with end-to-end proof

---

### Improvements

- Better wire stability for downstream tooling through a strict (`additionalProperties: false`) report schema with explicit `extensions.x_*` growth surface
- Stronger trust semantics: keyword-only matches map to `heuristic_signal` evidence and cannot project to `verified` trust, even when status is `pass`, even on hard-gate profiles
- Clearer profile metadata in the v1 report (`profile.{id, title, family, level, posture, is_release_track, recommended_gate}`) and consolidated `scorecard.{path, supplemental}` block
- Deterministic `results_digest` (sha256 over canonical control-result fields) for drift comparison across runs
- Confidence enum normalization (`high|medium|low|none`) on emission for `1.0`; `0.3`/`0.2` payloads remain byte-for-byte unchanged
- Honest SARIF projection: repository-level findings emit `uri: "."` and omit `region` (no fake line ranges); file-backed findings emit paths relative to `%SRCROOT%`; `properties.security-severity` is derived from weight × status
- Stable SARIF deduplication via `partialFingerprints.controlAndProfile/v1`
- Hard-gate profiles continue to fire the runtime `_HARD_GATE_EVIDENCE_PROFILES` warning when evidence is missing or contains placeholders, and the `evidence.limitations` array now surfaces the signal-cap rule per result
- Migration guidance is first-class: the report payload includes a `migration` block when legacy artifacts are encountered during evaluation
- Public-facing documentation expanded with the v5.0.0 migration guide, the `reports/1.0` contract reference, the signal-control audit, and the Azure/AWS collector privacy boundary

---

### Onboarding, docs, and CI diagnostics

- Reorganized the public documentation surface so onboarding stays in `README.md` while reference material lives in `docs/`. The README is now ~190 lines and links to dedicated pages for the validation walkthrough, the full CLI reference, and how to interpret report statuses
- Added `docs/validation-walkthrough.md` with the step-by-step demo (CLI help, profile discovery, fixture comparison, controls table, CI gating) preserving the existing screenshots
- Added `docs/cli-reference.md` consolidating the public CLI surface (subcommands, flags, exit codes, examples) in one place
- Added `docs/results-guide.md` covering result statuses, automation limits, applicability, and the v1.0 report top-level keys
- Updated `docs/README.md` so the documentation hub points at the new walkthrough/reference/results-guide trio without losing existing entries
- CI diagnostics: the `quality` job in `.github/workflows/github-ci-cd.yml` now uploads `./out/**` as an `oss-policy-kit-ci-out-${{ github.run_id }}` artifact with `if: always()`, `if-no-files-found: warn`, and 14-day retention. Reports remain available even when the self-check gate fails, using the same SHA-pinned `actions/upload-artifact@v4` already in use elsewhere

---

### Internal CLI maintenance

- Modularized `src/oss_policy_kit/cli/main.py` (formerly ~1,700 lines) into focused modules without changing the public CLI contract: `cli/help_text.py` (epilogs), `cli/common.py` (shared Typer app, console plumbing, `execute_evaluate`), `cli/profiles.py`, `cli/evaluate.py`, `cli/batch.py`, `cli/evidence.py`, `cli/reports.py`, and `cli/recommend.py`
- `cli/main.py` is now a slim entrypoint (≈40 lines) that re-exports `app` and `prepare_cli_args` so existing imports such as `from oss_policy_kit.cli.main import app, prepare_cli_args` keep working
- All seven subcommands (`profiles`, `evaluate`, `evaluate-many`, `scaffold-evidence`, `collect-evidence`, `diff-reports`, `recommend-profile`) plus the root-callback compatibility entry retain the same flags, exit codes, and report shapes
- No new flags, schemas, control IDs, profile IDs, or behaviors were introduced by the refactor; `ruff check`, `ruff format --check`, `mypy --strict`, and the full pytest suite (494 passed, 1 skipped) continue to pass

---

### Post-raio-x docs and CI uplift (no behavior change)

- Documented `evaluate-many --skip-non-repos` contract: the heuristic requires a primary signal **at the child root**; modern monorepos with manifests in subfolders are correctly skipped (`docs/cli-reference.md`)
- Added a defensive caveat to `recommend-profile` in `docs/cli-reference.md` and `docs/results-guide.md`: presence of `release-hardening-*` evidence templates can trigger a release-hardening suggestion even before the templates are filled. The same hint is now appended to the `release-hardening-2` rationale strings emitted by `application/profile_hints.py` so the warning travels with the recommendation
- Added `docs/controls-catalog.md`: single-page catalog of all 65 controls (category, assurance, weight, profile membership) with a per-control profile membership index. Linked from `docs/README.md`
- Cross-linked the v3.0.0 → v4.0.0 → v5.0.0 migration guides via "See also" sections; added a Migration guides block to `docs/README.md`
- Added a header docstring to `scripts/demo-video.ps1` clarifying it is a maintainer convenience script (not used by tests, CI, or packaging) and listed it explicitly in the README's Maintainer Self-Check section together with the other maintainer-only scripts
- Added a callout to `docs/profiles/overview.md` and reinforced the README At-A-Glance row stating that `github-aws-level-2` and `github-azure-level-2` are advisory-only and must not be wired as a release or PR gate
- Expanded `docs/profiles/deferred-followups.md` with a "Future considerations (post-v5.0.0, not in current scope)" section summarizing conceptual follow-ups identified during the 2026-05-06 audit
- CI: the `quality` job now also runs smoke steps for `evaluate-many`, `scaffold-evidence`, `collect-evidence --dry-run`, and `diff-reports`, exercising the four subcommands previously not exercised in public CI

---

### Profile maturity uplift (no behavior change)

- Added an explicit "Profile maturity tier" section to `docs/profiles/overview.md` classifying the 20 bundled profiles into six tiers (mature daily baseline, with-caveats baseline, advisory, GitHub L3 collector-mature, Azure/AWS L3 collector-partial, UX-bound `release-hardening-2`). The tiering is descriptive only — no profile, control, or assurance changed
- Added `docs/collector-parity.md` documenting the concrete endpoint coverage of `GitHubEvidenceCollector` (4 endpoints), `AzureDevOpsEvidenceCollector` (2 endpoints), and `AWSEvidenceCollector` (up to 3 endpoints), plus the artifact-bound files that are self-attested by design
- Locked the post-raio-x mitigations into the test suite: a new test asserts that every `release-hardening-2` rationale string in `recommend-profile` contains "verify evidence JSONs are filled, not templates"; three new tests in `test_hardened_repo_cloud_profiles.py` pin the invariants for `github/azure/aws-release-hardening-2` against the bundled hardened fixture; and a new `test_hardened_repo_evidence_purity.py` blocks regressions where the fixture evidence is silently re-templated (placeholder tokens / template digests / missing attested metadata)
- The hardened fixture's evidence files were not modified; the README under `examples/hardened-repo/.oss-policy-kit/evidence/` remains the source of truth for why those files are intentionally self-attested

---

### Framework alignment (no behavior change, no new profiles)

- Added `docs/framework-alignment.md`: a master cross-framework mapping covering OpenSSF Scorecard v4 (~19 checks), OpenSSF OSPS Baseline, OWASP CI/CD Top 10 (2022), SLSA v1.0 (Build track), NIST SSDF SP 800-218, Microsoft S2C2F, CIS Software Supply Chain Security Benchmark, AWS Well-Architected (Security Pillar / DevOps lens), and Azure DevOps Security Best Practices. Coverage is documented per requirement using YES / PARTIAL / OUT / GAP labels. The doc also lists frameworks intentionally out of scope (OWASP ASVS, NIST 800-53, PCI DSS 4.0, ISO 27001 / SOC 2, SAFECode, MITRE ATT&CK for CI/CD) and explains why
- Refreshed `docs/scorecard-mapping.md` and `docs/osps-mapping.md` from generic notes into concrete per-check / per-theme tables that reference exact catalog control IDs
- Each `*-level-3` and `*-release-hardening-2/3` profile description now ends with a one-line "Framework alignment:" pointer back to `docs/framework-alignment.md`. The control lists, assurance metadata, weights, and lifecycle of every profile / control are byte-equivalent before and after this change — only the description metadata changed
- Documented two explicit decisions in the alignment page: (a) **no new profiles** added (subsets of the catalog are documentation, not gates) and (b) **no new controls** added in v5.0.0 (gaps require org-scoped audit log access or runtime build-platform telemetry that is out of scope for this release line). Both rationales are recorded with concrete reasoning
- Future framework-driven work is ranked in the alignment page (audit-log evidence, sigstore/cosign signature verification, OpenSSF Best Practices badge ingestion, deeper self-hosted runner posture, container hardening extensions) and mirrored in `docs/profiles/deferred-followups.md`

---

### Breaking changes

- The default report contract is now `reports/1.0`. Downstream parsers pinned to the v4 wire shape must select `--report-json-contract 0.3` explicitly. The `0.3` and `0.2` shapes remain byte-equivalent to v4.0.4
- `--report-json-contract 0.1` is removed from the CLI selector. Passing `0.1` returns a usage error referencing the v5 migration guide
- The legacy bundled profile alias `github-release-hardening` is removed. Passing `--profile github-release-hardening` returns exit code `2` with a migration message pointing at the canonical `github-release-hardening-1`. The control set itself is unchanged
- Per-result `evidence` is now a structured object in `reports/1.0`. The flat `evidence_sources` and `evidence_collection_method` keys are not present in `1.0` payloads, but remain in `0.3`/`0.2` payloads exactly as before
- The bundled `evaluation-report-v3.schema.json` is re-encoded as UTF-8 without BOM. Validators that previously assumed UTF-8 should now succeed; validators that explicitly required UTF-16 will not

---

### Notes

- This is a major release and introduces the new default JSON wire contract `reports/1.0`
- Contract `1.0` describes wire stability for downstream tooling; the package classifier remains `Development Status :: 4 - Beta`. Those two stability promises are intentionally decoupled
- `reports/0.3` and `reports/0.2` remain selectable for the entire `5.x` line; `0.3` is the recommended pin for parsers that cannot adopt `1.0` yet
- The Evidence Model v2 projection runs on emission and does not require evaluator-plugin changes; richer `extra` keys (`collected_at`, `attested_by`, `digest`, `evidence_schema_id`, `source_platform`) are honored when present
- SARIF output is additive and only written when `--sarif-output PATH` is set; relative paths resolve under `--output-dir`
- Python minimum remains `>=3.12`. No SLSA L3 claim is made in this release; supply-chain expectations and what is in/out of scope are documented in `docs/release-readiness.md`
- Review `docs/v5.0.0-migration-guide.md` before upgrading from the 4.x line

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.4

This patch release aligns the current public repository state with the release line after the post-v4.0.3 documentation, site, CI, and public provenance hygiene updates. It does not change runtime behavior, bundled profiles, the control catalog, evaluator scoring, CLI flags, report schemas, or packaged policy data.

---

### Highlights

- Promoted the current default-branch documentation and CI hygiene state into a dedicated v4.0.4 release
- Improved public repository metadata hygiene before publication
- Kept the GitHub Pages site on the working Tailwind v3 build path
- Preserved the organized Azure Pipelines layout under `pipelines/azure/`

---

### Improvements

- Better alignment between the README, changelog, package metadata, and current public release state
- Cleaner public repository metadata hygiene without changing functional source code or policy data
- More consistent packaging maturity metadata by moving the package classifier from Alpha to Beta
- Continued validation of GitHub CI/CD, Security CI/CD, GitHub Pages, package build, and self-check workflows

---

### Notes

- This is a patch release in the 4.0.x line
- No runtime, schema, CLI, control, evaluator, or bundled profile behavior changes are introduced
- The v4.0.3 release remains available as the predecessor release
- This release exists to make the public repository, package metadata, documentation, and release line consistent before public publication

---

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.3

This patch release improves public repository hygiene for Azure Pipelines by moving the project pipeline into the supported `pipelines/azure/` layout, reducing unnecessary platform metadata exposure, and aligning detection, documentation, and CLI messaging with that organized structure.

---

### Highlights

- Moved the project Azure Pipelines definition from the repository root into `pipelines/azure/`
- Kept the public Azure YAML free of sensitive environment-specific metadata
- Updated repository discovery so `evaluate-many --skip-non-repos` recognizes supported nested Azure pipeline layouts
- Improved profile recommendation and terminal wording for Azure pipeline detection
- Normalized synthetic Azure fixture names so examples do not look like real production service connections

---

### Improvements

- Cleaner public repository structure for multi-platform CI evidence
- Better alignment between Azure documentation, parser support, profile recommendation, and batch repository detection
- Lower metadata noise in public fixtures and CI examples
- Added regression coverage for nested Azure pipeline repository detection
- Revalidated GitHub and Azure self-checks, targeted Azure tests, linting, typing, and secret/provenance hygiene scans

---

### Notes

- This is a patch release in the 4.0.x line
- Users running the provided Azure DevOps pipeline should update the pipeline YAML path to `pipelines/azure/azure-pipelines.yml`
- No report schema, bundled profile, control catalog, evaluator scoring, or packaged policy data changes are introduced
- Previous release tags remain unchanged

---

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.2

This patch release consolidates documentation, release hygiene, and CI hygiene improvements that landed after v4.0.1. It does not change runtime behavior, bundled profiles, the control catalog, evaluator logic, CLI flags, report schemas, or packaged policy data.

---

### Highlights

- Updated public launch documentation to reflect the current release state
- Added sanitized real CI screenshots for GitHub Actions and Azure Pipelines self-check flows
- Improved workflow self-check commands to use the supported `evaluate` subcommand
- Refined Azure Pipelines execution hygiene with pip caching and shallow checkout behavior
- Preserved the existing v4.0.1 release while promoting the current public repository state into v4.0.2

---

### Improvements

- Better public release traceability between README, screenshots, CI examples, and repository state
- Clearer documentation of what is included in the public repository and what remains outside the public repository
- Improved CI example accuracy through real sanitized pass/fail self-check evidence
- Cleaner repository hygiene through safer ignore patterns for maintainer-private working notes
- Improved cross-platform CLI test stability by avoiding Linux-specific path assumptions in test expectations

---

### Notes

- This is a patch release in the 4.0.x line
- No runtime, schema, CLI, control, evaluator, or bundled profile behavior changes are introduced relative to v4.0.1
- Previous release tags remain unchanged
- This release focuses on publication readiness, documentation accuracy, CI hygiene, and release traceability

---

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.1

This public-launch patch release promotes the validated launch candidate into the official 4.0.1 release without changing runtime behavior, bundled profiles, control catalog, evaluator logic, CLI flags, report schemas, or packaged policy data.

### Highlights

- First public-launch release package for the repository governance layer
- Added formal public release readiness, traceability, and launch checklist artifacts
- Included evidence packs covering pre-freeze and release candidate validation
- Added roadmap and post-publication governance assets
- Strengthened publication readiness with regression guardrails and false-positive issue intake support

### Improvements

- Better publication governance through formal release-readiness and launch checklist documentation
- Improved traceability with a dedicated publication traceability matrix
- Stronger release evidence with pre-freeze and RC1 candidate validation packs
- Better public maintenance posture through roadmap and post-publication governance documentation
- Improved operational readiness with a false-positive issue template for public feedback handling
- Continued workflow hygiene by keeping action references pinned to immutable SHAs
- Improved repository consistency through documentation refreshes and formatting normalization without semantic runtime changes

### Notes

- This is a public-launch patch release in the 4.0.x line
- No runtime, schema, CLI, control, evaluator, or bundled profile behavior changes are introduced relative to the validated 4.0.0 candidate
- Validation evidence is captured in the repository evidence packs and includes tests, linting, formatting, typing, packaging, smoke validation, self-check execution, and external validation reruns

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.0

This major release advances the kit with a new report contract, cleaner profile discovery, stronger collector hardening, and a more explicit migration path, while removing deprecated controls and tightening operational behavior across evaluation and evidence workflows.

### Highlights

- Introduced the new default evaluation JSON contract `reports/v0.3`
- Removed deprecated controls and aligned external profile migration behavior
- Improved profile discovery with richer derived metadata and new filtering options
- Strengthened Azure and AWS collector hardening and dry-run safety
- Expanded release-hardening and evidence-backed workflow documentation
- Improved cross-platform CLI reliability, including safer Windows output handling

### Improvements

- Better reporting clarity through gate-oriented metadata in the new `reports/v0.3` contract
- Stronger profile usability with additive metadata such as family, posture, and live-signal posture
- Improved profile discovery via family, advisory-only, and extreme-only filtering
- Better collector safety with clearer permission guidance, safer dry-run previews, and stronger handling of synthetic versus live evidence
- Improved batch evaluation usability with clearer skipped-directory summaries that preserve JSON contract stability
- Better recommendation behavior by restricting signal detection to the evaluated target and preferring safer starter guidance when governance evidence is missing
- Improved diff reporting and fail-on behavior with clearer ANSI and help semantics
- Better documentation alignment across migration guidance, profile docs, lifecycle guidance, evidence packs, adoption notes, and release-hardening usage
- Stronger packaging and publishing hygiene through immutable SHA pinning in the publish workflow
- Improved Windows reliability through UTF-8 stdio reconfiguration, safer ASCII status messages, and more robust smoke validation output handling

### Notes

- This is a major release and introduces the new default report contract `reports/v0.3`
- Users who need the previous JSON wire shape should continue using `--report-json-contract 0.2`
- Deprecated controls `SEC-AUDIT-016` and `CI-SBOM-017` are now removed from the catalog and evaluator registry
- External YAML profiles that still reference removed controls now fail fast with migration guidance
- This release focuses on contract clarity, collector hardening, migration readiness, and more predictable operational behavior across platforms

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.3.0

This release improves profile documentation clarity, strengthens bundled profile stability, and hardens packaging and validation workflows for more reliable release operations across platforms.

### Highlights

- Added regression coverage to lock bundled profile invariants and keep hybrid advisory metadata stable
- Expanded profile maturity documentation across profile guides and the release playbook
- Improved the public `profiles --format json` surface with richer additive metadata
- Hardened packaging validation so release checks resolve artifacts for the current project version
- Improved Windows compatibility for human-readable profile listing output

### Improvements

- Better bundled profile stability through invariant-focused regression testing
- Improved profile guidance with clearer operational usage classes and more honest `recommend-profile` messaging
- Better automation support through additive profile metadata such as maturity labels, assurance mix, legacy alias markers, and canonical profile identifiers
- Improved compact profile listing text for hybrid advisory profiles and legacy alias messaging
- Stronger release hygiene with explicit cleanup guidance for distribution and consumer smoke validation directories
- Better release documentation while intentionally keeping bundled profile controls unchanged
- Expanded follow-up documentation for work intentionally deferred from this release

### Notes

- This release focuses on profile maturity clarity, release hygiene, and packaging reliability
- Bundled profile controls remain unchanged in this version
- Packaging validation now resolves artifacts against the active `pyproject.toml` version instead of trusting stale files in `dist/`
- Includes Windows compatibility and documentation encoding fixes for a smoother cross-platform experience

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.2.0

This release improves evidence-backed evaluation, strengthens documentation and migration guidance, refines platform control behavior, and prepares the path for the planned v4.0.0 deprecations.

### Highlights

- Added a dedicated v4.0.0 migration guide covering deprecated controls, replacement paths, and custom profile migration
- Expanded API-backed evidence collection metadata for GitHub and AWS live collection flows
- Improved evaluator behavior across GitHub, Azure, and AWS with stronger structural validation and clearer evidence semantics
- Tightened control logic to reduce false positives and better distinguish deterministic proof from weaker signals
- Clarified the deprecation path for older audit and SBOM-related controls ahead of v4.0.0

### Improvements

- Better migration readiness through a dedicated upgrade guide and clearer deprecation messaging
- Improved documentation consistency across README, adoption guidance, evidence pack guidance, lifecycle notes, and hardened example references
- Stronger API-backed evidence handling with richer `collection` metadata, including collection method, timestamps, source URL, and attested model context
- Better PLAT and GH evaluator behavior by distinguishing live API-collected evidence from self-attested or scaffolded files
- Improved schema validation and evidence handling for branch protection, rulesets, environment protection, secret scanning, and AWS CodeCommit review posture
- Stronger GitHub workflow evaluation with more structural parsing and broader OIDC, provenance, least-privilege, SAST, and secret-scanning detection
- Improved Azure and AWS collectors with clearer credential expectations and manual-only hooks for artifact and provenance collection paths
- Better catalog assurance and parser behavior through more deterministic workflow and pipeline analysis
- Clearer control lifecycle handling as deprecated evaluators now return `NOT_EVALUATED` with migration guidance instead of misleading pass/fail results

### Notes

- This release prepares users for the planned v4.0.0 removal of `SEC-AUDIT-016` and `CI-SBOM-017`
- Deprecated controls now surface migration-oriented behavior and should be replaced with the recommended platform-specific alternatives
- Focused on evaluator accuracy, evidence trust boundaries, documentation clarity, and upgrade readiness
- Continues strengthening the distinction between live API-backed proof, manual evidence, and not-yet-evaluable placeholder inputs

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.1.0

This release improves evidence validation maturity, expands advisory profile coverage, and strengthens Azure and AWS posture evaluation with more reliable proof handling and clearer confidence boundaries.

### Highlights

- Added new evidence JSON schemas for AWS and Azure SBOM and provenance artifacts
- Introduced bundled multi-platform advisory profiles for GitHub + AWS and GitHub + Azure scenarios
- Expanded regression coverage for catalog assurance values and `reports/0.2` result projection
- Improved evaluator maturity by tightening the distinction between weak signals and stronger proof

### Improvements

- Better evidence quality by rejecting obvious placeholder or template digests in artifact-bound validation
- Improved Azure governance evaluation with stricter service connection and YAML evidence handling
- Stronger waiver and branch-protection behavior with clearer manual-review-required outcomes when proof is missing or incomplete
- Better Azure profile progression across starter, advisory, hard-gate, and release-hardening tracks
- Improved AWS profile structure with clearer hard-gate and release-hardening expectations
- Stronger AWS control evaluation through stricter CodePipeline export validation and better live evidence handling
- Better freshness handling through support for `collection.collected_at` on evidence objects
- Improved reliability for artifact-bound SBOM and provenance evaluators by reducing false confidence from template-style inputs

### Notes

- This release focuses on evaluator maturity, stronger proof expectations, and more reliable multi-platform posture assessment
- The trust model continues to distinguish observable signals from evidence-backed proof
- Azure and AWS evaluations are further refined to reduce inflated confidence and better surface cases that still require manual review
- Includes additional advisory profile options for combined GitHub + cloud pipeline scenarios

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.0.0

This major release evolves the kit from a clone-only baseline checker into a broader posture evaluation toolkit with report drift analysis, external profile loading, API-backed evidence collection, and a new report JSON contract.

### Highlights

- Expanded the kit beyond clone-only evaluation with API-backed evidence collection workflows
- Introduced report drift analysis to compare evaluation outputs across runs
- Added support for external YAML profile loading and richer profile extensibility
- Upgraded the report JSON contract with new evidence collection metadata
- Improved platform evidence support across GitHub, Azure DevOps, and AWS
- Strengthened human-readable output and diagnostics for operational use

### Improvements

- Better evidence handling through API-backed collection for GitHub, Azure, and AWS
- Improved report transparency with collection method metadata and live collection context
- Stronger extensibility through external profile loading and plugin-based evaluator registration
- Better regression analysis with report comparison and fail-on-regression support
- Improved CLI usability with richer human output, clearer diagnostics, and better profile help guidance
- Stronger validation through packaged report and profile schemas
- Better scaffolded evidence quality through placeholder detection and validation improvements
- Improved terminal behavior and Windows compatibility for human-readable output paths
- Clearer repository detection and stricter evaluation behavior for source inputs
- Promoted multiple controls from experimental to stable while formally deprecating older ones

### Notes

- This is a major release and introduces a new default report JSON contract: `reports/0.2`
- Users with strict downstream integrations depending on the previous JSON shape may need to keep using the older contract explicitly
- The release adds migration-oriented capabilities, including diff-based report comparison and external profile support
- API-backed evidence collection now complements the existing manual evidence model
- Review the migration guidance before upgrading from the 2.x line

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v2.0.1

This patch release stabilizes the 2.0 release path by fixing publication blockers, improving Azure profile recommendation accuracy, and strengthening release validation for package artifacts.

### Highlights

- Fixed the PyPI publish workflow to keep SBOM artifacts separate from distribution packages
- Improved `recommend-profile` detection for Azure repositories using nested pipeline layouts
- Added regression coverage to prevent package artifact mixing and Azure detection regressions
- Updated release-readiness documentation to reflect the corrected publication flow

### Improvements

- Better release reliability by ensuring SBOM output no longer interferes with wheel and sdist publishing
- Improved Azure platform detection for repositories using supported nested pipeline structures
- Stronger regression confidence through dedicated tests for nested Azure pipeline discovery
- Better packaging hygiene through validation that prevents SBOM artifacts from being bundled into distributions again
- Improved operational clarity with updated release-readiness guidance and corrected artifact paths

### Notes

- This is a maintenance-focused patch release in the 2.0.x line
- Focused on publication stability, packaging hygiene, and Azure recommendation accuracy
- No major breaking changes are expected
- Strengthens the release path established in v2.0.0 for safer publication and more predictable platform detection

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v2.0.0

This major release marks the next stage of the project's evolution: from a GitHub-focused local-first policy evaluation kit into a broader multi-platform governance and release-hardening framework for GitHub, Azure DevOps, and AWS.

Built on the foundations established across the 0.x and 1.x lines, v2.0.0 expands platform coverage, strengthens evidence-backed evaluation, improves CLI workflows, and delivers more actionable reporting while preserving the project's local-first trust model.

### Highlights

- Expanded the kit beyond GitHub with maturity and release-hardening ladders for Azure DevOps / Azure Pipelines and AWS CodeBuild / CodePipeline
- Added platform-specific parsers and schema-backed evidence handling for broader governance and pipeline posture evaluation
- Introduced new CLI workflows for profile discovery, batch evaluation, evidence scaffolding, and profile recommendation
- Improved reporting with action insights, prioritization guidance, stronger waiver semantics, and clearer explainability
- Continued the project's progression from initial local policy checks into a more mature operational assessment framework

### Improvements

- Better platform coverage through new GitHub, Azure, and AWS evaluation ladders
- Stronger evaluator maturity with stricter tracks while preserving the `github-level-1` baseline
- Improved CLI usability with `profiles`, `--show-profiles`, `evaluate-many`, `scaffold-evidence`, and `recommend-profile`
- Better automation support through JSON-friendly profile discovery and batch evaluation outputs
- Stronger report quality with root-cause grouping, recommended actions, prioritization sections, and clearer trust-boundary messaging
- Improved evaluator accuracy through tighter disclosure and CodeQL-equivalent heuristics
- Better waiver clarity by distinguishing in-repository versioned waivers from CLI-provided waiver inputs
- Refined documentation, operational guidance, and packaging hygiene for broader adoption and distribution reliability

### Notes

- This is a major release focused on platform expansion, evaluation maturity, and operational usability
- The trust model remains local-first: the kit evaluates what is observable from a repository clone, with optional evidence files for posture that cannot be proven from source alone
- Azure and AWS support in this release are intentionally clone-based and evidence-assisted, not live-tenant verification
- This version builds on the foundations introduced across earlier releases, including packaged policy data, lifecycle-aware controls, schema-backed evidence handling, release hardening, consumer validation flows, and stable 1.x CLI/report contracts
- Human summary output is now more action-oriented, while JSON-oriented automation remains supported

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.3

This patch release improves explainability, evidence validation, consumer-side validation workflows, and packaging hygiene, while preserving the stable 1.0.x contract.

### Highlights

- Improved scorecard explainability across JSON, Markdown, and optional stdout outputs
- Added runtime validation for branch protection evidence against the bundled schema
- Introduced a reproducible consumer smoke workflow for wheel and CLI validation
- Expanded test coverage for adoption paths, evidence handling, and scorecard behavior
- Improved packaging hygiene to avoid unintended bundled artifacts

### Improvements

- Better transparency around whether `--scorecard-json` was loaded and whether it influenced control evaluation
- Stronger evidence trust through schema-based validation of branch protection inputs
- Improved consumer validation with reproducible virtual environment, wheel, and CLI smoke checks
- Better regression confidence through added tests for recommended adoption paths, minimal gap handling, and local branch evidence
- Cleaner packaging behavior by removing recursive data glob side effects and preventing cache artifacts from being bundled
- Refined documentation for official install channels, Windows and PowerShell usage, and packaging operations

### Notes

- This is a maintenance-focused patch release in the 1.0.x line
- No breaking changes are expected for the CLI contract or public report schema
- Focused on explainability, packaging quality, evidence trust, and operational validation confidence
- Continues strengthening the stability and maintainability of the stable 1.0 line

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.2

This patch release improves adoption guidance, regression coverage, CLI summary behavior, and documentation consistency, while preserving the stable 1.0.x contract.

### Highlights

- Added a clearer recommended adoption playbook for practical project rollout
- Improved regression coverage for JSON projection and Markdown summary stability
- Enhanced CLI summary output with better totals and canonical status ordering
- Refined installation guidance, including Windows-friendly execution notes
- Updated cross-links across adoption, maintainer checklists, and examples for a more consistent user path

### Improvements

- Better onboarding support through a more actionable recommended adoption path
- Stronger regression confidence with expanded golden fixtures and report validation tests
- Improved CLI usability with clearer summary output in both human-readable and JSON formats
- Better consistency in report interpretation through stable controls table behavior
- Enhanced documentation alignment across examples, maintainer guidance, and adoption materials
- Improved usability for Windows environments when console scripts are not available on PATH

### Notes

- This is an additive patch release in the 1.0.x line
- No breaking changes are expected for the CLI contract or public report schema
- Focused on adoption clarity, test confidence, and day-to-day usability improvements
- Continues strengthening the stable foundation established in the 1.0 line

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.1

This patch release improves documentation, workflow hygiene, adoption assets, and GitHub Pages presentation, while keeping the project aligned with the 1.0.x stable line.

### Highlights

- Improved maintainer documentation and patch-readiness guidance
- Expanded adoption templates for waivers, views, and workflow integration
- Refined GitHub Actions hygiene with stronger action pinning and workflow consistency
- Improved GitHub Pages presentation for better readability and layout behavior
- Updated repository documentation and validation guidance for smoother project adoption

### Improvements

- Better maintainer support with clearer operational and patch validation guidance
- Improved adoption readiness through additional starter templates and workflow scaffolding
- Stronger CI/CD hygiene with more consistent third-party action pinning practices
- Better alignment between package workflow and security workflow expectations
- Improved GitHub Pages hero layout to avoid visual overlap on larger screens
- Enhanced site readability through softer visual effects and cleaner spacing
- Refined documentation across README, adoption guidance, release readiness, and troubleshooting notes

### Notes

- This is a maintenance-focused patch release in the 1.0.x line
- No major breaking changes are expected
- Focused on documentation quality, workflow hygiene, and presentation improvements
- Continues strengthening repository trust, adoption clarity, and day-to-day maintainability

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.0

This release marks the first stable major version of the kit, improving workflow organization, packaging alignment, and release maturity while establishing a clearer and more reliable foundation for ongoing evolution.

### Highlights

- First stable major release of the OSS Security Policy as Code Starter Kit
- Improved GitHub Actions structure with clearer CI, security, and deploy workflow separation
- Better packaging alignment for current Python distribution expectations
- Enhanced CLI version visibility and installed package identification
- Refined documentation for release, packaging, contribution, and roadmap guidance

### Improvements

- More organized workflow layout for CI/CD, security checks, and deployment
- Better repository trust posture through stronger action pinning practices
- Improved packaging metadata consistency for release readiness
- Clearer CLI behavior for version reporting and installed package validation
- Enhanced documentation quality across README, contribution flow, and release guidance
- Stronger foundation for stable public usage and future versioned evolution

### Notes

- This is the first stable major release in the 1.x line
- Focused on stability, release maturity, and maintainability
- No major breaking changes are expected for normal CLI usage
- Some schema references may continue to reflect the evaluation output contract version rather than the Python package version

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.4.0

This release improves policy data maturity, strengthens evidence validation, and expands release integrity signals with SBOM, build provenance, and broader CI coverage.

### Highlights

- Added lifecycle metadata to controls for clearer policy maturity tracking
- Introduced new experimental controls for dependency scanning and SBOM generation
- Strengthened branch protection evidence validation with a more explicit trust model
- Improved package workflow with SBOM generation and signed build provenance
- Expanded CI coverage across Ubuntu, macOS, and Windows
- Added coverage reporting to improve test visibility in CI

### Improvements

- Better control maturity visibility across JSON and Markdown reports
- Improved schema enforcement for policy data consistency
- Stronger evidence handling for branch protection validation
- Enhanced release integrity with CycloneDX SBOM generation
- Improved supply chain trust signals through build provenance attestation
- Better cross-platform confidence with multi-OS quality validation
- Increased test observability through CI coverage reporting

### Notes

- This release focuses on policy lifecycle clarity, stronger evidence validation, and release trust
- The new controls are currently experimental and should be treated as advisory until they mature
- JSON reports generated by v0.3.x are not compatible with the v0.4.0 schema because `lifecycle` is now required in `control_result`
- Re-generate reports with v0.4.0 to align with the updated schema

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.3.0

This release strengthens packaging, CLI usability, CI reliability, and release governance, making the kit easier to distribute, validate, and operate with clearer automation behavior.

### Highlights

- Improved package and release workflow for more reliable distribution
- Expanded CLI behavior with clearer output and exit-code handling
- Stronger report validation and test coverage for release confidence
- Better release-readiness guidance and repository governance documentation
- More consistent CI decisions for automation and publishing workflows

### Improvements

- Added package CI workflow with build, validation, and install checks
- Improved maintainers' ability to validate distribution artifacts before publishing
- Enhanced CLI usability with new output and summary options
- Clearer pass/fail automation through documented exit-code behavior
- Stronger report validation against the project schema
- Improved test coverage for JSON, Markdown, and failure-path scenarios
- Better documentation for release readiness, required checks, and maintainer workflows

### Notes

- This release focuses on packaging maturity, CLI clarity, and release engineering quality
- No major breaking changes are expected in the core evaluation model
- Strengthens the project for safer publishing and more predictable CI/CD usage
- Continues improving maintainability, trust, and automation confidence across the repository

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.2.0

This release improves package structure, installation readiness, and test organization, making the kit cleaner to consume, easier to maintain, and more aligned with a distributable Python package model.

### Highlights

- Reorganized the project into a more installable package-oriented layout
- Moved policy profiles and controls into package data for cleaner distribution
- Restructured the test suite by layers with better repository-based fixtures
- Removed duplicated root-level artifacts to improve maintainability
- Updated CI, contribution guidance, and architecture/adoption documentation to match the new model

### Improvements

- Better packaging consistency for local installation and distribution workflows
- Improved maintainability through a cleaner repository structure
- More reliable test organization with clearer separation of application, infrastructure, CLI, and adapter layers
- Stronger fixture strategy for workflow and parsing validation scenarios
- Better alignment between documentation, repository layout, and actual project usage

### Notes

- This release focuses on structural maturity, packaging hygiene, and maintainability
- No major conceptual change to the CLI behavior or control scope
- Users consuming root-level `controls/` and `profiles/` should now use the packaged artifacts under `src/oss_policy_kit/data/`
- Continues the same local-first assessment philosophy established in v0.1.0

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.1.0

This first publishable release delivers a local-first starter kit for evaluating OSS governance signals, GitHub Actions hygiene, and release readiness, with structured reports and explicit boundaries about what automation can and cannot verify.

### Highlights

- Local CLI to evaluate repositories directly from disk
- Versioned policy profiles with Markdown and JSON reporting
- Initial control catalog covering governance files, workflow hygiene, permissions, and release readiness signals
- Example vulnerable and hardened repositories for validation and learning
- Waiver format with schema validation, tests, and security-focused CI workflows
- Honest evidence model that clearly distinguishes automated findings from manual-review-required items

### Improvements

- Better structure for OSS governance and policy-as-code evaluation
- Clearer reporting outputs for local review and decision-making
- Stronger baseline for GitHub Actions security hygiene assessments
- Improved consistency across controls, examples, waivers, and CLI workflows
- More transparent handling of checks that require platform-side verification or human validation

### Notes

- This is the first publishable baseline of the kit
- Focused on local assessment, governance visibility, and release readiness support
- Does not replace GitHub platform configuration review, threat modeling, or formal OpenSSF certification processes
- Several controls intentionally remain manual-review-required when evidence cannot be proven locally

**License:** Apache-2.0.
