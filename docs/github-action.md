# GitHub Action: oss-policy-kit

The kit ships as a composite GitHub Action so adopters can evaluate the bundled OSS security baseline on every pull request without touching their build images. The action installs the published `oss-policy-kit` PyPI distribution into a hermetic Python environment and runs `evaluate` against the workspace.

## Quick start

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v10.0.13 # x-release-please-version
  with:
    profile: github-level-1
    fail-on: fail
```

A release tag is readable, but it is still mutable. For maximum supply-chain assurance — and to satisfy
`CI-PIN-008`, which this action's own `github-level-1` profile enforces — pin to the commit SHA of the
release tag and let Dependabot bump it:

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@4dc762d87933601cd30faa3c006d9fd53acef60c # v10.0.2
  with:
    profile: github-level-1
    fail-on: fail
```

That is the form used in [`templates/workflows/oss-policy-kit-marketplace-action.yml`](../templates/workflows/oss-policy-kit-marketplace-action.yml).

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `target` | no | `.` | Repository root to evaluate. |
| `profile` | no | (empty) | Profile ID or external YAML path. When empty, the action looks for `oss-policy-kit.yaml` at the target. |
| `fail-on` | no | `fail` | CI gate mode: `none`, `fail`, or `degraded`. |
| `output-dir` | no | `oss-policy-reports` | Directory where reports are written. |
| `waivers` | no | (empty) | Path to a YAML waivers file (kept under version control). |
| `scorecard-json` | no | (empty) | OpenSSF Scorecard JSON used as supplemental evidence. |
| `sarif-output` | no | (empty) | SARIF 2.1.0 file path. Relative paths resolve under `output-dir`. |
| `kit-version` | no | (matches action tag) | Pin a specific PyPI version, or `latest` to track the newest published release. |
| `python-version` | no | `3.12` | Python used to run the kit. 3.12+ is required. |

## Outputs

| Output | Description |
| --- | --- |
| `report-json` | Absolute path to `evaluation-report.json` |
| `report-markdown` | Absolute path to `evaluation-report.md` |
| `sarif` | Absolute path to the SARIF file (set only when `sarif-output` was provided) |
| `exit-code` | Exit code returned by `oss-policy-kit evaluate` (`0`, `1`, `2`, `3`) |

## Job summary and annotations

After each run the action writes a **GitHub Actions job summary** (a Markdown table of control
counts plus the failing controls) to the workflow run page, and emits **inline annotations** —
`::error` for each `fail` and `::warning` for each manual-review (`UNKNOWN`) control — so findings
surface directly on the pull request's Checks tab. This is best-effort and never changes the exit
code the action forwards: `fail-on` still decides whether the check passes or fails.

## Permissions

The action only needs `contents: read`. Grant `security-events: write` only if you forward SARIF to GitHub Code Scanning.

```yaml
permissions:
  contents: read
  # security-events: write  # only when forwarding SARIF
```

## Forwarding SARIF to Code Scanning

```yaml
- name: Run oss-policy-kit
  id: oss-policy
  uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v10.0.13 # x-release-please-version
  with:
    profile: github-level-2
    sarif-output: results.sarif

- name: Upload SARIF
  if: ${{ always() && steps.oss-policy.outputs.sarif != '' }}
  uses: github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3 # v4.37.6
  with:
    sarif_file: ${{ steps.oss-policy.outputs.sarif }}
    category: oss-policy-kit
```

## Honesty contract

The action runs the same `evaluate` command you would run locally. It does not collect platform evidence via the GitHub API: that requires `GITHUB_TOKEN` and `collect-evidence`, which is intentionally out of scope of the basic Marketplace action. To include platform evidence, run `oss-policy-kit collect-evidence` in a previous step and point the action at the resulting `oss-policy-reports/` artifacts via `--with-evidence` (manual flow) or commit the evidence files under `.oss-policy-kit/evidence/` before the evaluate step (recommended for hardened release workflows).

A full reusable example lives at [`templates/workflows/oss-policy-kit-marketplace-action.yml`](../templates/workflows/oss-policy-kit-marketplace-action.yml).
