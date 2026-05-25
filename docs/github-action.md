# GitHub Action: oss-policy-kit

The kit ships as a composite GitHub Action so adopters can evaluate the bundled OSS security baseline on every pull request without touching their build images. The action installs the published `oss-policy-kit` PyPI distribution into a hermetic Python environment and runs `evaluate` against the workspace.

## Quick start

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v6.4.0
  with:
    profile: github-level-1
    fail-on: fail
```

Pin to a specific release for reproducibility:

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v6.4.0
  with:
    profile: github-level-1
    fail-on: fail
```

For maximum supply-chain assurance, pin to the commit SHA of the release tag and let Dependabot bump it.

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
| `kit-version` | no | (matches action tag) | Pin a specific PyPI version, or `latest` to track the newest 6.x. |
| `python-version` | no | `3.12` | Python used to run the kit. 3.12+ is required. |

## Outputs

| Output | Description |
| --- | --- |
| `report-json` | Absolute path to `evaluation-report.json` |
| `report-markdown` | Absolute path to `evaluation-report.md` |
| `sarif` | Absolute path to the SARIF file (set only when `sarif-output` was provided) |
| `exit-code` | Exit code returned by `oss-policy-kit evaluate` (`0`, `1`, `2`, `3`) |

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
  uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v6.4.0
  with:
    profile: github-level-2
    sarif-output: results.sarif

- name: Upload SARIF
  if: ${{ always() && steps.oss-policy.outputs.sarif != '' }}
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.oss-policy.outputs.sarif }}
    category: oss-policy-kit
```

## Honesty contract

The action runs the same `evaluate` command you would run locally. It does not collect platform evidence via the GitHub API: that requires `GITHUB_TOKEN` and `collect-evidence`, which is intentionally out of scope of the basic Marketplace action. To include platform evidence, run `oss-policy-kit collect-evidence` in a previous step and point the action at the resulting `oss-policy-reports/` artifacts via `--with-evidence` (manual flow) or commit the evidence files under `.oss-policy-kit/evidence/` before the evaluate step (recommended for hardened release workflows).

A full reusable example lives at [`templates/workflows/oss-policy-kit-marketplace-action.yml`](../templates/workflows/oss-policy-kit-marketplace-action.yml).
