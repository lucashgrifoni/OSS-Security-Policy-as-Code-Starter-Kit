# Adoption guide (~ 15 minutes)

This guide is for maintainers who want a pragmatic baseline without over-claiming "compliance".

## Install channels (quick reference)

- **PyPI (primary):** `python -m pip install oss-policy-kit`
- **PyPI pinned version:** `python -m pip install oss-policy-kit==<version>`
- **GitHub Release artifacts (alternative):** install downloaded wheel/sdist in controlled environments
- **Source/editable (contributors):** `python -m pip install -e ".[dev]"`

Recommended CLI entrypoint across platforms: `python -m oss_policy_kit`.

**Supported Windows shells:** Git Bash, PowerShell 7+, or WSL. Windows PowerShell 5.1 also works but lacks `&&` / `||` pipeline operators and uses UTF-16 LE for redirections by default; when copying examples written in bash, prefer Git Bash or PowerShell 7+. Always prefer `python -m oss_policy_kit` over the `oss-policy-kit` console script on Windows so you do not depend on the per-user `Scripts\` directory being on `PATH`.

## Choose a baseline (predict outcomes before you run)

The kit does **not** certify repositories. These baselines describe **what to copy** and **what result shape to expect** on `github-level-1` (**14** active controls; deprecated YAML-only audit/SBOM controls stay in the catalog but are **not** in starter/advisory/hard-gate profiles).

| Baseline | Artifacts | Typical `github-level-1` |
| --- | --- | --- |
| **Minimal** | Governance templates only, or CI without dependency review / CodeQL / waivers | Often **not** 14x `pass` (frequent gaps: `GOV-WAIV-014` as **`manual-review-required`** when no in-repo waiver policy, `CI-PIN-008`, `SEC-CODEQL-010`) |
| **Recommended (official)** | `templates/workflows/ci.yml` + `templates/workflows/security.yml` + `templates/waivers/waivers.yaml` + `templates/docs/*` as needed | **Target: 14x `pass`** for a Python `src/` layout with `pyproject.toml` and `[dev]` extras matching the template |
| **Hardening** | Recommended + `.oss-policy-kit/evidence/branch-protection.json` + evaluate with `github-release-hardening-1` | **`pass` + `self-attested`** on `PLAT-BRPROT-015` is normal until a human confirms GitHub settings |

**Honest distinction:** *minimal* is useful for learning and gap lists; **`all-pass` on `github-level-1` is only a documented target for the recommended template bundle**, not for a bare-bones copy.

**Profile maturity labels:** `github-level-1` is the **starter** ladder, `github-level-2` is **advisory** (stronger signals), and `github-level-3` is a **hard-gate** oriented to deterministic checks plus GitHub evidence files. The id `github-release-hardening` (without `-1`) is a **legacy alias** that resolves to the same control set as `github-release-hardening-1`; **always prefer `github-release-hardening-1`** in docs, UX, and automation. The legacy id is retained only for backwards compatibility when a filesystem path to the legacy YAML is referenced directly.

**Cross-platform maturity (honest):** inside this kit the **GitHub family is the most mature path**. `github-level-3` / `github-release-hardening-3` combine deterministic workflow parsing with evidence-backed branch-protection and environment controls. The **Azure** (`azure-level-3`, `azure-release-hardening-3`) and **AWS** (`aws-level-3`, `aws-release-hardening-3`) hard-gate families are the strictest bundled gates for their platforms but still rely more on evidence discipline than on deterministic parsing; treat them as close — not equal — to the GitHub hard-gate family until Azure/AWS collectors reach parity. The hybrid profiles (`github-azure-level-2`, `github-aws-level-2`) are **advisory-only** and must not be used as release gates.

## Minute 0-2: choose a profile

- Start with `github-level-1`.
- Add `github-release-hardening-1` when you are ready to track platform controls that require GitHub settings review (expect `self-attested` when using local evidence only).

For stricter tiers:

- `github-level-2`: adds advisory workflow hardening checks (`GH-WF-018`–`021`, merge queue signal `GH-MERGEQ-053`, secret-scan signal `SEC-SECRETS-050`, etc.).
- `github-level-3`: **hard-gate** — adds GitHub platform evidence (`GH-PLAT-024`–`026`), merge queue, reusable workflow SHA pins (`CI-WFCALLSHA-055`), and evidence freshness (`GOV-EVIDFRESH-054`). Weak-only deploy/provenance YAML signals are intentionally excluded.
- `github-release-hardening-2` and `github-release-hardening-3`: add platform-evidence controls for rulesets, deployment environments, and secret scanning posture (`GH-PLAT-024` to `GH-PLAT-026`) plus freshness where listed.

Use `python -m oss_policy_kit profiles` for the compact bundled profile table on **stdout** with `profile`, `title`, `platform`, `level`, executive `audience`, and a brief `description`. Use `python -m oss_policy_kit --show-profiles` when you want the same table with full audience and description text. For automation, use `python -m oss_policy_kit profiles --format json`. For a heuristic starting point from a clone layout, use `python -m oss_policy_kit recommend-profile --target <repo>`.

> **Reading `recommend-profile` honestly:** the heuristic treats JSON files under `.oss-policy-kit/evidence/` as platform signals, so a repository with only a **synthetic** evidence pack (and no real workflow, pipeline or buildspec) can still be suggested a `*-release-hardening-2` profile. The suggestion rationale uses "and/or" to reflect this, but the heuristic cannot tell scaffolded evidence apart from `collect-evidence` output. Before promoting any `*-release-hardening-*` suggestion to a hard gate, confirm a real CI workflow/pipeline/buildspec exists. See [`docs/profiles/overview.md` — How `recommend-profile` reads `.oss-policy-kit/evidence/`](profiles/overview.md#how-recommend-profile-reads-oss-policy-kitevidence).

**Multi-platform (v3.1.0):** bundled **`github-aws-level-2`** and **`github-azure-level-2`** are **advisory** profiles for teams that use GitHub as SCM but run CI on **AWS** or **Azure**; they layer the GitHub workflow bundle on top of the respective platform’s clone-visible controls (still not a substitute for live platform verification).

Human-readable CLI output (tables, summaries, warnings) uses the detected terminal width on a TTY and a fixed fallback width when **stdout** or **stderr** is not a TTY (for example pipes, capture, or `CliRunner`), so behavior stays predictable in CI and scripts.

When you maintain several sibling repositories under one folder, `evaluate-many --target-root <parent> --profiles <comma-separated>` writes a consolidated matrix plus per-target reports. Use `--fail-on fail` or `--fail-on degraded` for a batch CI gate, `--skip-non-repos` to skip folders that lack repository markers, and `--quiet` to suppress incremental stderr progress lines.

### CI pipelines (GitHub Actions)

Templates under [`templates/workflows/`](../templates/workflows/) install `oss-policy-kit`, run `evaluate`, upload reports as artifacts, and honor exit codes (`0` = gate passed for the chosen `--fail-on`; `1` = gate violated). Prefer copying one of those files rather than reinventing flags.

When you wire `evaluate --format json`, stdout contains **only** the compact JSON summary; confirmations about where Markdown/JSON reports were written appear on **stderr**, which keeps JSON parsing reliable in orchestration tools.

To start `release-hardening-*` evidence files without hand-authoring JSON from scratch, run `scaffold-evidence --target <repo> --platform github|azure|aws`, then edit the generated `.oss-policy-kit/evidence/*.json` until they reflect real platform posture. Re-running without `--force` **skips** existing files so manual edits are preserved; use `--force` only when you intend to replace templates.

**v3+ preference (GitHub):** with `GITHUB_TOKEN` and `pip install 'oss-policy-kit[github]'`, use `collect-evidence --target <repo> --platform github` to generate the same evidence files directly from the API (see `docs/evidence-pack.md`).

### Drift between runs

Keep `evaluation-report.json` from two points in time (for example before/after CI changes) and compare:

```powershell
python -m oss_policy_kit diff-reports --before out/old/evaluation-report.json --after out/new/evaluation-report.json --format markdown
```

Use `--fail-on-regression` in CI gates when you want to fail on `pass`/`self-attested` → `fail` regressions.

Azure DevOps ladder (v3.0.1+, evaluator tuning **v3.1.0**):

- **`azure-level-1` (starter)**: governance plus **AZ-PIPE-027..029** and **signal** controls **AZ-SEC-031** / **AZ-SCA-032** / **AZ-SBOM-033** (catalog **`assurance: signal`** — PASS is directional, not proof of tool execution).
- **`azure-release-hardening-1`**: starter scope plus **AZ-PLAT-034** and **AZ-PLAT-035** (branch policies + pipeline governance evidence).
- **`azure-level-2` (advisory)**: starter signals plus **AZ-PIPE-030** (`extends` secure template) and **AZ-IDENT-036** (deployment identity / federation posture from YAML and, when present, governance JSON).
- **`azure-release-hardening-2`**: advisory (`azure-level-2`) plus **AZ-PLAT-034/035**.
- **`azure-level-3` (hard-gate)**: **GOV-EVIDFRESH-054**, **AZ-PLAT-034/035**, **AZ-SCONN-056**, **AZ-WIFEV-057**, **AZ-ARTSBOM-058**, **AZ-ARTPRV-059**, and **AZ-IDENT-036** on top of deterministic pipeline controls. **031..033** are intentionally **excluded** so the gate does not depend on scanner/SBOM YAML “mentions”.
- **`azure-release-hardening-3`**: hard-gate core (same family as **`azure-level-3`**) **plus** the **031..033** signal bundle for release visibility — clearly above **`azure-release-hardening-2`**.

Clone-only heuristics still apply to pipeline YAML. **Branch policies, approvals, environments, and service connections** become **evidence-backed** when you add JSON under `.oss-policy-kit/evidence/` or run **`collect-evidence --platform azure`** (HTTP APIs: policies, pipelines, environments, **check/configurations** for approvals, **serviceendpoint/endpoints** for federation vs secret-based connections). **`posture_support`** on collected files records which APIs succeeded so evaluators can stay honest when a read failed.

Supported Azure repository shapes in this release:

- `azure-pipelines.yml` or `azure-pipelines.yaml` at repository root.
- `pipelines/azure/*.yml|*.yaml`.
- `.azure-pipelines/*.yml|*.yaml`.

Supported Azure evidence files:

- `.oss-policy-kit/evidence/azure-branch-policies.json`
- `.oss-policy-kit/evidence/azure-pipeline-governance.json`
- `.oss-policy-kit/evidence/azure-sbom-artifact.json` (artifact-digest SBOM attestation)
- `.oss-policy-kit/evidence/azure-provenance-artifact.json` (artifact-digest provenance / attestation)

AWS CodeBuild and CodePipeline ladder:

- **`aws-level-1` (starter)**: governance plus committed `buildspec` checks. Scanner/SBOM/provenance items are **signal** controls (low-confidence PASS is directional, not proof).
- **`aws-level-2` (advisory)**: starter scope plus a **structured** CodePipeline export under `pipelines/aws/` (stages or artifact store), provenance **signals** in buildspec, and strict managed-secret sourcing in buildspec.
- **`aws-level-3` (hard-gate)**: deterministic checks plus **evidence-backed** controls (`AWS-CP-044`, `AWS-CB-045`, `AWS-CBIDENT-057`, `AWS-PIPEIAM-056`, `AWS-SBOMART-058`, `AWS-PROVART-059`) and `GOV-EVIDFRESH-054`. Buildspec-only signals such as `AWS-SEC-039` / `AWS-SBOM-041` are intentionally **not** in this profile so the gate is not “green” from heuristics alone.
- **`aws-release-hardening-1`**: starter profile plus `AWS-CP-044` / `AWS-CB-045` evidence (or manual review).
- **`aws-release-hardening-2`**: advisory (`aws-level-2`) plus the same pipeline/build evidence files.
- **`aws-release-hardening-3`**: **hard-gate core** (same family as `aws-level-3`) **plus** the level-2 signal bundle for release visibility, evidence freshness, IAM/identity, and artifact-bound SBOM/provenance JSON.

**Manual vs API-backed evidence**: JSON produced by `collect-evidence` includes `collection` metadata and `attested_by: aws-api-collection`; evaluators may upgrade outcomes to **PASS** with `evidence_collection_method: live`. Hand-filled scaffold JSON remains **self-attested** until refreshed with API collection.

AWS support remains clone-first: the kit reads committed buildspec or curated CodePipeline exports plus optional evidence files. Live AWS reads happen only when you run **`collect-evidence`** (optional extras).

Supported AWS repository shapes in this release:

- `buildspec.yml` or `buildspec.yaml` at repository root.
- `.aws/buildspec*.yml` or `.aws/buildspec*.yaml`.
- `pipelines/aws/codepipeline*.json`, `pipelines/aws/codepipeline*.yaml`, or `pipelines/aws/codepipeline*.yml` (curated exports only; no recursive repo-wide scan).

Supported AWS evidence files:

- `.oss-policy-kit/evidence/aws-codebuild-project.json`
- `.oss-policy-kit/evidence/aws-codepipeline.json`
- `.oss-policy-kit/evidence/aws-sbom-artifact.json` (artifact-digest SBOM attestation)
- `.oss-policy-kit/evidence/aws-provenance-artifact.json` (artifact-digest provenance attestation)

## Monorepo / multi-app

Use **`evaluate-many --target-root <parent>`** when you maintain several sibling repositories under the same parent folder and want a consolidated matrix. The command is **non-recursive**: only the **immediate child directories** of `--target-root` are treated as candidate targets (same semantics documented in `docs/profiles/overview.md`). Nested sub-folders inside a candidate are not discovered automatically.

### `--skip-non-repos`: what it considers a repo root

`--skip-non-repos` filters each immediate child through a conservative heuristic (`is_likely_repository`) that looks for at least one primary signal on the child's own root: `.git`, a build manifest (`package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, etc.), a CI file (`.github/workflows/`, `azure-pipelines.yml`, `pipelines/azure/*.yml`, `buildspec.yml`), or a `Dockerfile`. `README.md` alone is **not** enough. **`.oss-policy-kit/evidence/` is not considered a repo signal either**: a folder that only carries a synthetic or scaffolded evidence pack (and no `.git`, no manifest, no CI file, no `Dockerfile`) will be skipped by `--skip-non-repos`. If you want to evaluate that folder, run `evaluate` directly on it, or run `evaluate-many` without `--skip-non-repos`.

That means a visibly cloud-native monorepo laid out as `services/`, `gateway/`, `infra/`, `serverless-sim/` **at the sub-project's root**, with **no** root-level manifest, is treated as a non-repo and silently skipped. This is by design: the heuristic deliberately refuses to guess. The skipped directory list is recorded in `evaluation-batch.json` under `skipped_directories`, and the CLI now prints a one-line stderr summary pointing operators at that field when anything was skipped.

If a skipped child is actually a repo you care about:

- drop a root-level anchor file (`pyproject.toml`, `package.json`, `Dockerfile`, ...) matching the real stack, **or**
- run `evaluate` directly on the sub-tree that does look like a repo root, **or**
- remove `--skip-non-repos` and let the child be evaluated as-is (accepting that you may evaluate non-repo folders too).

### `--include` / `--exclude` (fnmatch on child folder names)

When the parent folder contains mixed items, use `--include` and `--exclude` with `fnmatch`-style patterns applied to the **child folder name only** (not to full paths). Examples:

```bash
# Only evaluate child folders matching lab-*
python -m oss_policy_kit evaluate-many \
  --target-root ./apps \
  --profiles github-level-1 \
  --include "lab-*"

# Skip auxiliary / output folders that are not real repos
python -m oss_policy_kit evaluate-many \
  --target-root ./apps \
  --profiles github-level-1 \
  --skip-non-repos \
  --exclude "out-*"
```

Combine with `--skip-non-repos` when you want both a repo-shape filter and a name-pattern filter.

### When to fall back to `evaluate` per sub-tree

`evaluate-many` is optimized for the "many sibling repos" case. When a sub-project is itself a monorepo (e.g. a `services/` folder with its own internal layout), treat it as a separate target and call `evaluate` directly on the sub-tree that is the real repository root:

```bash
python -m oss_policy_kit evaluate \
  --target ./services/api \
  --profile github-level-1 \
  --output-dir ./out/services-api
```

This keeps the `--skip-non-repos` heuristic honest and avoids false positives from inferring a repo root that does not exist.

## Minute 2-5: run the CLI on your repository

```bash
python -m pip install -e .
python -m oss_policy_kit evaluate --target /path/to/your/repo --profile github-level-1 --output-dir ./out
```

Equivalent (omits `evaluate`, same flags):

```bash
python -m oss_policy_kit --target /path/to/your/repo --profile github-level-1 --output-dir ./out
```

On Windows, treat `python -m oss_policy_kit` as the **supported** entrypoint. If `oss-policy-kit` is not found, your Python Scripts directory may not be on `PATH` (common with per-user installs); use `-m` or add Scripts to PATH.

### What the profile is (and is not)

`github-level-1` checks for OSS-style governance files and GitHub Actions hygiene signals in the clone. A generic application repository without `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, workflows, and changelog will typically fail multiple controls **by design**. That pattern reflects missing repo-level evidence, not a complete verdict on application security maturity.

Open:

- `out/evaluation-report.md` for human review
- `out/evaluation-report.json` for tooling

### CI and exit codes

In pipelines, use **`--fail-on fail`** (or **`degraded`**, which also treats `manual-review-required` as a failure) so the process exits with code **`1`** when the summary is not acceptable, and **`0`** when it is.

Example:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out --fail-on fail
```

For machine-readable stdout (in addition to the JSON report file), use:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out --format json
```

If you need a compact parser-friendly summary:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out --summary-only --format json
```

The summary object includes ordered status counts, `controls_total`, and warning count.

## Minute 5-10: recommended copy-paste bundle (target `pass: 14` on `github-level-1`)

1. **Workflows** - copy into `.github/workflows/` (adjust names if you already have conflicts):
   - `templates/workflows/ci.yml` - quality gates, **package build** (twine / wheel), and optional CycloneDX SBOM output in CI (evaluated under active controls such as **`SEC-CODEQL-010`**, **`SEC-DEPREV-011`**, and workflow hygiene IDs — not under deprecated YAML-only catalog entries).
   - `templates/workflows/security.yml` - **dependency review** and **CodeQL** jobs aligned with **`SEC-DEPREV-011`** / **`SEC-CODEQL-010`**; optional pip-audit-style steps may appear in YAML but are **not** part of the `github-level-1` gate set (see **`docs/policy-data-lifecycle.md`** for deprecated audit/SBOM controls kept catalog-only).
2. **Waivers** - copy `templates/waivers/waivers.yaml` to `waivers/waivers.yaml` (empty list is valid; satisfies **`GOV-WAIV-014`** as `pass`).
3. **Governance docs** - copy from `templates/docs/` (`SECURITY.md`, `CONTRIBUTING.md`, etc.) and customize.
4. **Pins** - templates already use full action SHAs; keep that discipline when upgrading actions (see maintainer docs for resolving new SHAs).

Adapt `python-version`, install paths, and branch filters to your repository. The template assumes `pip install -e ".[dev]"`, `ruff`, `mypy src`, and `pytest`.

For a deterministic runbook with copy/paste commands, use:

- [docs/recommended-adoption-playbook.md](recommended-adoption-playbook.md)

## Minute 5-10 (alternative): fix the "obvious" failures incrementally

If you are not copying the full recommended bundle yet, prioritize:

1. Add `SECURITY.md` with a real private reporting channel.
2. Add `CONTRIBUTING.md` and `LICENSE`.
3. Add `CODEOWNERS` if reviews are part of your workflow.
4. Fix GitHub Actions hygiene:
   - explicit top-level `permissions:`
   - avoid `pull_request_target` unless you truly need it
   - pin third-party actions to full commit SHAs
5. Add CodeQL + dependency review workflows (see `templates/workflows/security.yml`).
6. Add **SBOM generation** in a package or release workflow (CycloneDX/Syft/SPDX - see `templates/workflows/ci.yml` job `package`).
7. Add **`waivers/waivers.yaml`** so exceptions are versioned in-repo.

## Minute 10-15: handle exceptions honestly

If something cannot be fixed immediately:

- Use a **waiver** (`waivers/waivers.example.yaml`) with justification, owner, expiry, and scope.
- For platform-only controls, plan a **manual review** cadence (for example quarterly).

### `--waivers` (operational input) vs `GOV-WAIV-014` (governance control)

These two are **not** the same thing and intentionally stay independent:

- `evaluate --waivers <file>` is an **operational** mechanism. It loads an external YAML file for the current run so waivers can be applied (for example, a central waivers registry consumed by many repos). The file path is not required to live inside the repository being evaluated.
- `GOV-WAIV-014` is a **governance control**. It checks that the repository **itself** versions a waivers policy (typically `waivers/waivers.yaml` committed in-repo) so exceptions are reviewable via normal PR/CODEOWNERS flow.

Loading an external waivers file with `--waivers` does **not** satisfy `GOV-WAIV-014`: the CLI prints an explicit "Waiver note" when both paths are in play. To turn `GOV-WAIV-014` green, commit `templates/waivers/waivers.yaml` (or an equivalent policy file) into the repository under review; use `--waivers` only to evaluate the run against a specific waiver set without modifying the repo's committed policy.

## Optional: add Scorecard JSON as supplemental evidence

Generate or export Scorecard output for your repository and pass:

```bash
--scorecard-json ./scorecard.json
```

This can supplement a small number of checks, but it does not replace in-repo workflows for deterministic CI evidence.

## Status reminders (avoid misreading the report)

- **`manual-review-required`**: often YAML ambiguity or unparseable workflow - not always "your repo failed"; read the reason.
- **`self-attested`**: local file or claim present; **not** remote verification (common for **`PLAT-BRPROT-015`** with evidence JSON only).
- **`waived`**: only after a waiver entry applies; different from `self-attested`.
