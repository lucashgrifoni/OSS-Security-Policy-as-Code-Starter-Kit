# Release readiness

This is the maintainer checklist for patch releases, public launch, and routine repository operations.

Keep detailed launch evidence, private planning notes, and internal traceability packs outside the public repository. This page is the public operational checklist.

## EU CRA awareness — 2026-09-11 reporting deadline

The EU **Cyber Resilience Act** sets a regulatory clock that affects any maintainer placing software products on the EU market:

- **2026-09-11**: vulnerability/incident reporting obligations begin (enforceable).
- **2027-12-11**: full obligations apply.
- **SBOM**: must be machine-readable (CycloneDX or SPDX), include at least top-level dependencies, and be retained for **10 years** after a product is placed on market.
- **Vulnerability handling**: documented and kept current.

This kit helps with the **technical readiness** side: it generates a CycloneDX SBOM at build time (`artifacts/sbom.cyclonedx.json`), evaluates SBOM-quality controls (`BUILD-SBOM-QUAL-003`, `*-ARTSBOM-058`), enforces governance docs that ground vulnerability handling (`GOV-SEC-001`, `GOV-DISC-013`), and starting in v5.1.0 evaluates audit log streaming (`AUDIT-STREAM-060`) for centralized incident reporting. The **legal** side (notified bodies, market-placement timing, retention storage) is out of scope; this kit does **not** certify CRA compliance. See `docs/framework-alignment.md` (EU CRA section) for the per-control mapping.

## v5.0.0 release gate (additive to the routine checklist below)

The v5.0.0 release introduces `reports/1.0` (default), Evidence Model v2, SARIF 2.1.0 output, and removes the legacy profile alias `github-release-hardening`. Before tagging:

- [ ] `pyproject.toml` `version` bumped to `5.0.0` and matches `src/oss_policy_kit/__init__.py`.
- [ ] `CHANGELOG.md` v5.0.0 entry written (highlights, improvements, notes, breaking changes).
- [ ] `docs/v5.0.0-migration-guide.md` reflects final shipped behavior.
- [ ] `docs/reports-contract-v1.0.md` matches the bundled `evaluation-report-v1.schema.json`.
- [ ] Default report contract is `reports/1.0` and `--report-json-contract 0.1` returns the migration error.
- [ ] Legacy alias `github-release-hardening` returns the migration error (exit code 2).
- [ ] SARIF output validates as SARIF 2.1.0 for hardened, vulnerable, and healthy runs.
- [ ] `docs/signal-controls-audit.md` captures the v5.0.0 signal control disposition.
- [ ] `docs/azure-aws-collector-privacy.md` describes credentials and privacy boundaries.
- [ ] Bundled `evaluation-report-v3.schema.json` is UTF-8 (no BOM); v1 schema is strict (`additionalProperties: false`).
- [ ] `python scripts/check_public_hygiene.py` (see below) returns clean against tracked files.
- [ ] Mirror clone validation per `docs/release-readiness.md` mirror block returns clean.
- [ ] Wheel and sdist install in a clean venv (`scripts/consumer_smoke.py`).
- [ ] `evaluate` smokes on `examples/hardened-repo` and `examples/vulnerable-repo` produce expected exit codes.

### Supply chain expectations for v5.0.0

The v5.0.0 release line ships with **partial provenance**, not SLSA L3. What is in scope:

- CycloneDX SBOM generated as a CI artifact alongside wheel/sdist.
- GitHub Actions workflow pinned to immutable SHAs; reviewed before each tag.
- GitHub artifact attestations for the wheel and sdist when the publish workflow is run with `attestations: write` (track this as a v5.x.y enhancement; not a v5.0.0 hard requirement).
- Release notes describe how to verify wheel/sdist checksums published on the GitHub Release page.

What is **not** in scope for v5.0.0 and must not be claimed:

- SLSA L3 build provenance (no isolated builder yet).
- Cosign signing as a hard requirement (optional path documented; not required for v5.0.0 to ship).
- OpenSSF Scorecard score as a merge gate (track as advisory in v5.x; gate later when stable).

### Public hygiene scan (must be run before tagging)

The release must fail if any private maintainer, workstation, credential, tenant, or internal planning marker appears in tracked files, generated release assets, or mirror-clone reachable objects.

This includes:

- personal email addresses or consumer email domains
- workstation home-directory paths
- private planning, prompt, validation, or traceability artifact names
- Git author-mapping files used only for local history hygiene
- real cloud account or organization identifiers (other than the synthetic `000000000000`)
- real service connection identifiers
- credential-looking secrets
- self-hosted runner machine names
- private fixture names

Run the helper:

```bash
python scripts/check_public_hygiene.py
```

This script grep-scans tracked files for the forbidden tokens and exits non-zero if any are found. Pair it with a mirror-clone scan (see below) before tagging.

## Repository contents

- [ ] `LICENSE` is present and correct
- [ ] `NOTICE` contains attribution if required
- [ ] `README.md` explains what the project is and is not
- [ ] `SECURITY.md` matches the actual vulnerability reporting path
- [ ] `CHANGELOG.md` reflects the intended release
- [ ] `pyproject.toml` version matches `src/oss_policy_kit/__init__.py` (for example `4.0.0` on the current release line)

## Quality gates

- [ ] `python -m pytest -q`
- [ ] `python -m ruff check src tests`
- [ ] `python -m mypy src/oss_policy_kit`
- [ ] Bandit local sweep — on Windows use the JSON formatter with forced UTF-8 IO encoding so the default text formatter does not fail on `cp1252`:
      `$env:PYTHONIOENCODING='utf-8'; python -m bandit -q -r src -f json -o security-results/bandit.json` (PowerShell)
      or `PYTHONIOENCODING=utf-8 python -m bandit -q -r src -f json -o security-results/bandit.json` (bash/zsh)

## Packaging gates

- [ ] clean `dist/`, `build/`, and `.consumer-smoke-venv/` before validating artifacts
- [ ] `python -m build`
- [ ] `python scripts/twine_check_dist.py` (preferred; resolves the current package version and avoids PowerShell `dist/*` glob issues)
- [ ] `python scripts/consumer_smoke.py --repo-root .`
- [ ] `pip install cyclonedx-bom && python -m cyclonedx_py environment --of JSON -o artifacts/sbom.cyclonedx.json` produces a valid SBOM JSON file
- [ ] SBOM (`artifacts/sbom.cyclonedx.json`) published as a dedicated GitHub Actions artifact or release asset alongside the package distributions
- [ ] run the `publish-pypi.yml` workflow with `workflow_dispatch` and `target=testpypi` before the official PyPI publish (**third-party Actions in this workflow are pinned by full commit SHA** — rotate intentionally)

See `docs/packaging-and-release.md` for exact commands.

## Product smoke

- [ ] `python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable`
- [ ] `python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened`
- [ ] `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck`
- [ ] `python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/gate --fail-on fail` exits with code `1`
- [ ] optional parser smoke: `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/summary --summary-only --format json`
- [ ] `python -m oss_policy_kit profiles` and `python -m oss_policy_kit profiles --format json`
- [ ] optional: `python -m oss_policy_kit recommend-profile --target ./examples/hardened-repo`
- [ ] optional: `python -m oss_policy_kit scaffold-evidence --target . --platform github` in a throwaway directory, then delete artifacts

## Claims hygiene

- [ ] no certification or compliance claims in docs
- [ ] automation limits are visible in `README.md` and `docs/architecture.md`

## What "green" means

- `github-level-1` with 14 `pass` means the local repository posture matches this kit's starter baseline well
- `github-release-hardening-1` with `pass` plus `manual-review-required` or `self-attested` is normal when branch protection remains a platform-side concern

That is intentional honesty, not a defect.

## Patch release routine

- [ ] working tree clean of accidental artifacts
- [ ] no secrets or tokens in tracked files
- [ ] if `gitpage/` changed, run `npm ci` and `npm run build`
- [ ] if templates changed, spot-check the recommended adoption path
- [ ] update release notes in `CHANGELOG.md`

## GitHub settings before public launch

Complete these manually on GitHub:

- [ ] `Settings -> General`: confirm the default branch and repository description
- [ ] `Settings -> Code security`: enable private vulnerability reporting
- [ ] `Settings -> Branches` or `Rules -> Rulesets`: protect the default branch
- [ ] `Settings -> Branches / Rulesets -> Required status checks`: require the exact job names you rely on
- [ ] `Settings -> Actions`: confirm Actions are enabled and not blocked by policy
- [ ] confirm default branch runs are green after merge

Typical merge-blocking jobs for this repository:

- `GitHub CI/CD`: quality and package jobs
- `Security CI/CD`: dependency review, CodeQL, and security jobs you choose to block on

`Deploy GitHub Pages` is usually a delivery workflow, not a merge blocker for the Python package.

## Workflow pinning and routine operations

Third-party GitHub Actions should stay pinned to full commit SHAs.

When rotating SHAs:

1. read upstream release notes
2. update the workflow YAML
3. validate locally with a self-check
4. confirm Actions still pass after push

If a workflow or job name changes, update branch protection or rulesets to match the new name shown in GitHub Actions.

## gitpage operations

The site under `gitpage/` is optional.

Operational rules:

- run `npm ci` after lockfile changes
- delete `gitpage/node_modules` if you suspect corruption or Windows file-lock issues
- treat the GitHub Pages workflow as the build source of truth when local Windows behavior is noisy

## Final public launch question

You are ready to make the repository public when all of these are true:

- the quality, packaging, and smoke gates are green
- the README and docs describe the project honestly
- local-only or internal planning files are gone
- GitHub security and repository settings are aligned with the public launch you want
