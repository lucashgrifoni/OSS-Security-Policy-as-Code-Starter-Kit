# CLI Reference

Full reference for the `oss-policy-kit` CLI. Always run the relevant `--help` for the authoritative wording — this page exists so reviewers can scan the surface in one place.

## Public Contract

The supported CLI forms are:

- preferred: `python -m oss_policy_kit evaluate ...`
- compatible: `python -m oss_policy_kit --target ./repo --profile ...`
- also supported: `python -m oss_policy_kit ./repo --profile ...`

The explicit `evaluate` subcommand is the clearest form and should be preferred in docs, scripts, and examples.

## Project Initialization

For new adopters, `init` is the fastest path from "fresh clone" to a working baseline. It detects the CI platform and primary language stack, picks a recommended profile, and writes a persisted `oss-policy-kit.yaml` config plus any optional artifacts you ask for.

```bash
# Minimum: detect platform, pick a profile, write oss-policy-kit.yaml
python -m oss_policy_kit init --target .

# Full bootstrap in one shot (config + waivers stub + evidence skeleton + workflow)
python -m oss_policy_kit init --target . \
  --with-waivers --with-evidence --with-workflow

# Preview without touching the filesystem
python -m oss_policy_kit init --target . --dry-run

# Force a profile and platform when you already know what you want
python -m oss_policy_kit init --target . --profile github-level-2 --platform github

# Stable JSON output for automation / CI
python -m oss_policy_kit init --target . --format json
```

The command is idempotent: re-running without `--force` preserves any file you have edited and reports it as `skipped`. Pass `--force` only when you want to replace generated files with the latest defaults.

> **Honesty contract.** `oss-policy-kit.yaml` is reserved for future kit versions to consume when `--profile` is omitted from `evaluate`. Today the file documents intent and powers reproducibility, but `evaluate` still reads its inputs from explicit flags. The file uses a stable `schema_version` (`oss-policy-kit/config/v1`) so the upcoming consumer can migrate safely.

The JSON output uses `schema_version: oss-policy-kit/init-result/v1` and is additive across releases.

## Config-aware evaluate

Starting in v5.4.0, `evaluate` reads `oss-policy-kit.yaml` (written by `init`) when `--profile` is omitted:

```bash
python -m oss_policy_kit init --target .          # writes oss-policy-kit.yaml
python -m oss_policy_kit evaluate --target .      # uses the profile from the file
```

When the fallback is used, evaluate logs `Using profile from oss-policy-kit.yaml: <profile-id>` on stderr. Explicit `--profile <id>` always wins over the file. Missing both flag **and** config produces exit code 2 with a clear message.

The config schema (`oss-policy-kit/config/v1`) records: `profile`, `profile_source`, `fail_on`, `output_dir`, `report_json_contract`, and detected metadata. `fail_on` and `output_dir` are still consumed via flags only in this release; future versions will expand the fallback surface.

## SAST evidence

`scan-sast` runs Semgrep against the target and writes evidence consumed by the `SAST-SEMGREP-064` control:

```bash
pip install semgrep                                              # one-time
python -m oss_policy_kit scan-sast --target .                    # writes evidence
python -m oss_policy_kit evaluate --target . --profile my-sast   # consumes evidence
```

Semgrep is **not** a hard dependency. When the binary is missing, `scan-sast` still writes an evidence file with `status: not_available` and exits 0; `evaluate` then reports `SAST-SEMGREP-064` as `manual-review-required` with remediation pointing to `pip install semgrep`. This keeps the kit honest about gaps without crashing pipelines that have not adopted SAST yet.

As of v5.4.0 `SAST-SEMGREP-064` is `lifecycle: stable` and is bundled in the **`appsec-sast-sca-1`** profile. The shortest opt-in path is:

```bash
pip install semgrep
python -m oss_policy_kit scan-sast --target .
python -m oss_policy_kit evaluate --target . --profile appsec-sast-sca-1 --fail-on fail
```

A starting template for fully custom profiles still ships at `templates/profiles/external-with-sast.yaml.example`.

## IaC evidence (Terraform / OpenTofu)

`scan-iac` runs the bundled Terraform / OpenTofu rule pack against the target and writes evidence consumed by every `IAC-TF-*` control (12 rules introduced in v5.5.0). Pair it with the bundled `iac-terraform-baseline-1` advisory profile:

```bash
pip install 'oss-policy-kit[iac]'                                # one-time, brings python-hcl2
python -m oss_policy_kit scan-iac --target .                     # writes .oss-policy-kit/evidence/iac-terraform.json
python -m oss_policy_kit evaluate --target . --profile iac-terraform-baseline-1 --fail-on degraded
```

`python-hcl2` is **not** a hard dependency. When the parser is missing `scan-iac` exits 0 and writes an evidence stub with `status: not_available`; `evaluate` then reports every `IAC-TF-*` control as `manual-review-required` with remediation pointing to the iac extra. The 12 rules cover: public storage (S3/GCS), open management ports, IAM `AdministratorAccess` / wildcard `Action+Resource`, missing encryption-at-rest, audit/access logging gaps, default-VPC reliance, accidental public IPs, missing `owner`/`cost_center` tags, unpinned providers, local backend state, missing `prevent_destroy` on production data stores, and wildcard IAM principals. The rule pack is **deliberately pragmatic** — the kit's value here is the stable evidence shape and profile composition, not a Trivy/Checkov replacement. See [iac-terraform.md](iac-terraform.md) for the full adoption playbook.

## Day-to-day usage

1. **First run**: install the package, then `python -m oss_policy_kit profiles` (or `--show-profiles`) to pick a ladder, and `python -m oss_policy_kit recommend-profile --target .` for a quick hint.
2. **Local maintainer loop**: `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/latest` before tagging or opening a release PR; open `evaluation-report.md` for the narrative view.
3. **Multi-app / monorepo**: `python -m oss_policy_kit evaluate-many --target-root ./apps --profiles github-level-1 --output-dir ./out/batch` — read `evaluation-batch.md` first (consolidated totals, repeated gaps, relative paths to per-repo reports).
4. **Waivers**: keep versioned waivers in-repo for `GOV-WAIV-014`; use `--waivers path.yaml` only for temporary or CI-local exceptions and treat them as explicitly out-of-band from versioned policy.
5. **Release-hardening + evidence**: run `scaffold-evidence` once, fill `.oss-policy-kit/evidence/*.json`, then evaluate with `github-release-hardening-*` (or Azure/AWS equivalents). Re-run scaffold **without** `--force` to preserve hand-edited JSON; use `--force` only when you intend to replace templates.
6. **Interpreting scope**: read [results-guide.md](results-guide.md) when results look similar across apps — the kit measures clone-visible posture, not application logic flaws.

## Profile Discovery

Use either of these:

- `python -m oss_policy_kit profiles`
- `python -m oss_policy_kit --show-profiles`

Both commands list the bundled ladders with platform, level, control count, and whether the profile stays clone-only or extends into release-hardening/evidence expectations. **Listing goes to stdout** (errors stay on stderr). Machine-readable catalog:

```bash
python -m oss_policy_kit profiles --format json
```

Heuristic profile suggestion from repository layout:

```bash
python -m oss_policy_kit recommend-profile --target ./examples/hardened-repo
python -m oss_policy_kit recommend-profile --target . --format json
```

`recommend-profile` is **heuristic guidance**, not a compliance verdict. It can be strongly influenced by local `.oss-policy-kit/evidence/*.json`, platform signals in CI files, and repository manifests/lockfiles. Treat the recommendation as a starting point, then confirm with an explicit `evaluate` run and review the resulting statuses.

> **Caveat: evidence templates trigger release-hardening recommendations.**
> `recommend-profile` may suggest `release-hardening-*` profiles when it detects evidence JSON files under `.oss-policy-kit/evidence/` — even if those files still contain placeholder values from `scaffold-evidence`. Running `evaluate` against an unfilled template will surface `manual-review-required` for evidence-backed controls (this is the tool being honest about missing evidence; not a bug). Recommended flow: run `scaffold-evidence`, fill the JSONs with real values, then re-run `recommend-profile`. See also [results-guide.md](results-guide.md#evidence-templates-vs-real-evidence).

## Batch / Monorepo

Evaluate each **immediate child directory** of a root folder against one or more profiles (paths with spaces are supported via normal shell quoting):

```bash
python -m oss_policy_kit evaluate-many --target-root ./path/to/apps --profiles github-level-1 --output-dir ./out/batch
```

This writes per-target reports under `./out/batch/<child-name>/<profile-id>/` plus consolidated `evaluation-batch.json` and `evaluation-batch.md`.

`evaluate-many` inspects immediate child directories of `--target-root`. It does not recurse into monorepos. For nested layouts, run `evaluate-many` once per level or invoke `evaluate` per target.

### `--skip-non-repos` requires a primary signal at child root

`--skip-non-repos` rejects a child directory unless it contains at least one **primary signal at its own root**: `.git/`, a build manifest (`package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, etc.), a CI file (`.github/workflows/`, `azure-pipelines.yml`, `pipelines/azure/*.yml`, `buildspec.yml`), or a `Dockerfile`. `README.md` alone is **not** sufficient.

This is a deliberate contract — but it can surprise modern monorepo layouts where the manifest or CI lives in a subfolder. For example, a child shaped like:

```text
my-app/
├── README.md
├── docs/
├── infra/
│   └── terraform/...
├── services/
│   ├── api/
│   │   └── package.json
│   └── worker/
│       └── pyproject.toml
└── gateway/
    └── Dockerfile
```

…will be skipped because no primary signal sits at `my-app/` root. The skip is recorded in `evaluation-batch.json.skipped_directories[].reason`. To evaluate this layout, run one of:

```bash
# Evaluate each service as its own target
python -m oss_policy_kit evaluate-many --target-root ./my-app/services --profiles github-level-1 --output-dir ./out/services

# Or evaluate a specific service directly
python -m oss_policy_kit evaluate --target ./my-app/services/api --profile github-level-1 --output-dir ./out/api
```

## Evidence Scaffolding

Generate schema-shaped starter files under `.oss-policy-kit/evidence/`:

```bash
python -m oss_policy_kit scaffold-evidence --target . --platform github
```

By default, **existing files are not overwritten** (stdout prints `created` / `skipped` / `overwritten`). Use `--force` only when you want to replace templates you have already edited.

Replace placeholders, then re-run `evaluate` with a `release-hardening-*` profile. Evidence remains **self-attested** (maintainer-supplied), not platform-verified.

## Common Examples

Subcommand with `--target`:

```bash
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

Subcommand with positional target:

```bash
python -m oss_policy_kit evaluate ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

Top-level compatibility form:

```bash
python -m oss_policy_kit --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened-root
```

## Optional Inputs

Unix-like shells:

```bash
python -m oss_policy_kit evaluate --target ./path/to/repo \
  --profile github-level-1 \
  --output-dir ./out \
  --waivers ./waivers/waivers.example.yaml \
  --scorecard-json ./path/to/scorecard.json
```

Windows PowerShell:

```powershell
python -m oss_policy_kit evaluate --target .\path\to\repo --profile github-level-1 --output-dir .\out --waivers .\waivers\waivers.example.yaml
```

## Pipeline-Friendly Output

For compact stdout suitable for CI parsing:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out --summary-only --format json
```

The JSON summary includes:

- ordered `summary_by_status`
- `controls_total`
- `operational_warnings_count`

The **human** `--summary-only` mode prints a short, action-oriented recap (counts, top gaps, suggested next step) while keeping this JSON contract stable.

## Waivers: versioned in repo vs `--waivers`

- **`--waivers`**: external YAML loaded for **this run only**; may set specific controls to `waived`. The report states the absolute path under `external_waiver_path`.
- **`GOV-WAIV-014`**: checks for a **versioned** waiver policy file **inside the clone** (for example `waivers/waivers.yaml`). Using `--waivers` does **not** satisfy that control by design; the Markdown report explains both mechanisms side by side.

## Exit Codes

After a successful evaluation:

| Code | Meaning |
| --- | --- |
| `0` | Completed and `--fail-on` threshold was not violated |
| `1` | Completed and `--fail-on` threshold was violated |
| `2` | Invalid usage, missing paths, or other user-correctable errors |
| `3` | Unexpected internal error |

## Windows Note

`pyproject.toml` exposes the `oss-policy-kit` console script, but on Windows the Scripts directory is not always on `PATH`.

- canonical invocation: `python -m oss_policy_kit`
- if you prefer the console script, use an activated virtual environment or ensure the Scripts directory is on `PATH`

## Quick reference (real flags per subcommand)

| Subcommand | Required | Common flags | Notes |
| --- | --- | --- | --- |
| (root) | — | `--version/-V`, `--help/-h`, `--debug`, `--show-profiles/-sp` (**deprecated, use the `profiles` subcommand**) | Compatibility entry point; also accepts the same flags as `evaluate` for backward compat. `--debug` (place before any subcommand, e.g. `oss-policy-kit --debug evaluate ...`) emits per-control diagnostics to stderr; stdout output is unchanged. |
| `profiles` | — | `--format/-f` (`compact` default, `table`, `detailed`, `json`), `--family` (`github`/`azure`/`aws`), `--only-extreme`, `--advisory-only` | Listing only. JSON returns the `oss-policy-kit/profile-list/v2` schema. |
| `evaluate` | `--profile/-p` (or positional target) | `--target/-t`, `--output-dir/-o`, `--format/-f`, `--summary-only/-so`, `--fail-on/-fo` (`none`/`fail`/`degraded`), `--waivers/-w`, `--scorecard-json/-sj`, `--report-json-contract` (`1.0`/`0.3`/`0.2`), `--sarif-output`, `--include-absolute-path` (opt-in; default is privacy-by-default basename), `--verbose/-v`, `--quiet/-q`, `--kit-root/-k` | Default contract is `1.0`; `0.3` and `0.2` remain selectable. SARIF only emitted when `--sarif-output` is set. `target_path` in the JSON / Markdown report is the target's basename by default — pass `--include-absolute-path` to keep the full absolute path. |
| `evaluate-many` | `--target-root`, `--profiles/-p` (comma-separated) | `--output-dir/-o`, `--include`, `--exclude` (fnmatch on child names), `--fail-on/-fo`, `--skip-non-repos`, `--quiet/-q`, `--kit-root/-k` | Iterates immediate children of `--target-root`. `--profiles` is plural. |
| `recommend-profile` | `--target/-t` | `--format/-f` (`human` default, `json`) | Heuristic — never a compliance verdict. The `*-release-hardening-2` suggestions require BOTH a CI signal (workflow / pipeline / buildspec) AND release-shaped evidence to be present; a single workflow alone falls back to `*-level-1`. |
| `init` | — (defaults `--target .`) | `--profile/-p`, `--platform`, `--fail-on`, `--output-dir/-o`, `--with-waivers`, `--with-evidence`, `--with-workflow`, `--force/-f`, `--dry-run`, `--format` (`human`/`json`) | Writes `oss-policy-kit.yaml` and optional artifacts. Idempotent without `--force`. |
| `scan-sast` | — (defaults `--target .`) | `--rulesets` (csv, default `auto`), `--timeout`, `--format` (`human`/`json`) | Runs Semgrep when available and writes `.oss-policy-kit/evidence/sast-semgrep.json`. Status `not_available` is recorded honestly when Semgrep is missing. |
| `scan-iac` | — (defaults `--target .`) | `--include` (csv glob, default `**/*.tf`), `--exclude` (csv glob), `--timeout`, `--format` (`human`/`json`) | Runs the bundled Terraform / OpenTofu rule pack and writes `.oss-policy-kit/evidence/iac-terraform.json` (schema `oss-policy-kit/evidence/iac-terraform/v1`). Status `not_available` is recorded honestly when `python-hcl2` is missing (`pip install 'oss-policy-kit[iac]'`). |
| `scan-bicep` | — (defaults `--target .`) | `--include` (csv glob, default `**/*.bicep`), `--exclude` (csv glob), `--timeout`, `--format` (`human`/`json`) | Runs the bundled Bicep rule pack and writes `.oss-policy-kit/evidence/iac-bicep.json`. |
| `scan-cfn` | — (defaults `--target .`) | `--include` (csv glob, default `**/*.yml`/`**/*.yaml`/`**/*.json`), `--exclude` (csv glob), `--timeout`, `--format` (`human`/`json`) | Runs the bundled CloudFormation rule pack and writes `.oss-policy-kit/evidence/iac-cfn.json`. |
| `scan-pulumi` | — (defaults `--target .`) | `--include` (csv glob), `--exclude` (csv glob), `--timeout`, `--format` (`human`/`json`) | Runs the bundled Pulumi rule pack and writes `.oss-policy-kit/evidence/iac-pulumi.json`. |
| `scan-k8s` | — (defaults `--target .`) | `--include` (csv glob), `--exclude` (csv glob), `--helm-pre-pass`/`--no-helm-pre-pass`, `--timeout`, `--format` (`human`/`json`) | Runs the bundled Kubernetes rule pack (manifests + optional Helm pre-pass) and writes `.oss-policy-kit/evidence/k8s-baseline.json`. |
| `scaffold-evidence` | `--target/-t`, `--platform` (`github`/`azure`/`aws`) | `--force` | Creates `.oss-policy-kit/evidence/` and template JSON files. `--target` must already exist. |
| `collect-evidence` | `--target/-t`, `--platform` (`github`/`azure`/`aws`) | `--repo`, `--output-dir/-o`, `--dry-run` | `--dry-run` reports presence/absence of credential env vars without printing values, and does not require `--target` to exist on disk. |
| `diff-reports` | `--before`, `--after` | `--format/-f` (`table` default, `json`, `markdown`), `--fail-on-regression` / `--no-fail-on-regression` | Default is to exit `1` on regression; opt out with `--no-fail-on-regression`. |
| `emit-vex` | — (defaults `--osv-sarif .oss-policy-kit/evidence/sast/osv-scanner.sarif.json`) | `--osv-sarif`, `--output/-o` | Emits a CycloneDX VEX 1.6 document from OSV-Scanner SARIF. All findings get `analysis.state: in_triage` in v0.1 — the manufacturer fills in the analysis post-hoc. See [`vex-emission.md`](vex-emission.md) and ADR-002. New in v5.9.0. |
| `emit-insights` | — (defaults `--target .`) | `--target/-t`, `--output/-o`, `--validate` | Emits an OpenSSF Security Insights 1.0 YAML document for the repository. See [`insights-emission.md`](insights-emission.md). |
| `export-evidence` | — (defaults `--target .`) | `--target/-t`, `--report`, `--format`, `--output/-o`, `--validate` | Exports the latest evaluation report into an external format. The `chainloop` format is experimental. See [`evidence-export.md`](evidence-export.md) and ADR-012. |

Exit codes are uniform across subcommands: `0` success, `1` `--fail-on` / regression threshold violated, `2` invalid usage or missing input, `3` unexpected internal error.
