# Tutorial: from zero to PR gate in 15 minutes

This tutorial assumes you maintain or contribute to a GitHub repository with Python 3.12+ available locally. You will install the kit, run a first evaluation, fix one control, document one exception, and wire the same gate into a pull request.

Total time: about 15 minutes. The local part does not need a GitHub token.

## Step 1 - Install (2 min)

```bash
python -m pip install oss-policy-kit
python -m oss_policy_kit --version
```

If your shell cannot find the `oss-policy-kit` script, keep using `python -m oss_policy_kit`. That form works consistently on Windows, Linux, and macOS.

## Step 2 - Bootstrap your repo (1 min)

Run this from your repository root:

```bash
python -m oss_policy_kit init --target . --platform github --with-evidence --with-workflow
```

This writes:

- `oss-policy-kit.yaml` with a default starter profile.
- `.oss-policy-kit/evidence/` with evidence stubs.
- `.github/workflows/oss-policy-check.yml` for pull-request gating.

`--platform github` is doing real work here. Platform detection reads CI files in the
clone, not the git remote, so a repository that does not have `.github/workflows/` yet --
which is the repository this tutorial is written for -- is detected as `unknown`, and
`init` then writes only `oss-policy-kit.yaml` and prints a note saying it skipped the
other two. Naming the platform is what makes the evidence stubs and the workflow appear.

Before committing, inspect the generated files:

```bash
git status
git diff -- oss-policy-kit.yaml .github/workflows/oss-policy-check.yml
```

## Step 3 - First evaluation (1 min)

```bash
python -m oss_policy_kit evaluate --target . --output-dir ./out
```

`evaluate` reads the profile (and, when you omit them, the `fail_on` / `output_dir` / `report_json_contract`) from the `oss-policy-kit.yaml` that Step 2 wrote — you will see `Using profile from oss-policy-kit.yaml: github-level-1` on stderr. Passing `--output-dir ./out` explicitly keeps the report paths below stable regardless of the directory recorded in the config.

Expected shape -- a per-control table on stdout, then one summary line:

```text
Profile: github-level-1  |  Target: <your-repo>
| ID           | Status | Confidence | Reason                        |
| GOV-SEC-001  | fail   | high       | SECURITY.md not found ...     |
...
Summary: fail=<n>  manual-review-required=<n>  pass=<n> | Controls: 14 | Reports: out
```

The two `Wrote out/evaluation-report.{json,md}` lines go to stderr, next to the
`Using profile from ...` line. Add `--summary-only` if you want counts, the weighted
score, and the top gaps instead of the table.

Open `./out/evaluation-report.md`. Each non-pass control includes status, reason, remediation, and assurance grade.

Keep this text evidence instead of an image:

| Evidence | What to confirm |
|---|---|
| CLI stdout | The selected profile, the per-control table, and the status summary are printed. The weighted score is in `evaluation-report.md`, and on stdout only under `--summary-only`. |
| `evaluation-report.md` | Each non-pass control includes reason, remediation, confidence, and evidence when available. |
| `evaluation-report.json` | `summary_by_status`, `controls_total`, and per-control records are present for automation. |

## Step 4 - Fix one, waiver one (5 min)

A missing `SECURITY.md` is a good first fix:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/before
```

Create a minimal `SECURITY.md` in your editor:

```markdown
# Security Policy

## Reporting a Vulnerability

Report security issues through GitHub private vulnerability reporting.
We will acknowledge valid reports within 5 business days.
```

Run again:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/after
```

For a gap that is real but not fixable today, add a waiver:

```yaml
# waivers/waivers.yaml
version: 1
waivers:
  - control_id: SEC-CODEQL-010
    justification: "CodeQL rollout planned for the next release hardening sprint."
    owner: "security@example.com"
    status: approved
    expires_at: "2027-03-31"
```

The root of the file is a mapping with `version` and `waivers`, and the free-text field
is `justification`. A bare list of waivers, or `reason` in place of `justification`, is
refused by the loader. Waive a control the profile you run actually evaluates --
`SEC-CODEQL-010` is in `github-level-1`; a waiver for a control outside the profile is
loaded and never applies. Full shape: [`waivers/waivers.example.yaml`](../waivers/waivers.example.yaml).

Then run with waivers:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --waivers ./waivers/waivers.yaml
```

The report still shows the control, now as `waived`, with its owner, justification, and expiry.

Expected report change after the fix:

| Before | After |
|---|---|
| `GOV-SEC-001` is non-pass when `SECURITY.md` is missing. | `GOV-SEC-001` passes once the repository root contains a monitored security policy. |
| No waiver metadata exists for the planned gap. | `SEC-CODEQL-010` reads `waived`, and its detail block lists owner, justification, and expiry. |

## Step 5 - Commit and push (2 min)

```bash
git add SECURITY.md oss-policy-kit.yaml .github/workflows/oss-policy-check.yml waivers/waivers.yaml .oss-policy-kit/
git commit -m "chore: add OSS security policy gate"
git push origin feature/oss-policy-gate
```

Open a pull request. The generated workflow evaluates the same profile that you ran locally.

## Step 6 - See the gate in action (3 min)

In the PR Checks tab:

- Passing gate: the required check is green and the report artifact is available.
- Failing gate: the check is red, and `evaluation-report.md` explains which controls failed.

To intentionally see the failure path, delete `SECURITY.md`, push again, then restore it. The point is to verify that the gate blocks the same kind of issue you saw locally.

Gate behavior to verify:

| PR state | Expected evidence |
|---|---|
| Passing gate | Required check is green, and the report artifact contains no `fail` status for the configured threshold. |
| Failing gate | Required check is red, the command exits with code `1`, and `evaluation-report.md` explains which controls failed. |

## Step 7 - Next steps (1 min)

| Goal | How |
|---|---|
| Stricter GitHub gate | Switch to `github-level-2` in `oss-policy-kit.yaml` |
| Code Scanning integration | Add `--sarif-output` and upload the SARIF artifact |
| EU CRA posture | Evaluate `cra-eu-ready-1` or `cra-eu-reporting-1` as advisory |
| Release hardening | Run `scaffold-evidence --platform github` and a release-hardening profile |
| Many repositories | Use `evaluate-many` |

Full CLI reference: [cli-reference.md](cli-reference.md). Profile overview: [profiles/overview.md](profiles/overview.md).

## Troubleshooting

### Python 3.12 is not available

Install Python 3.12+ and rerun the install command. Older Python versions are not supported by the package metadata.

### Module not found on Windows

Use the module form:

```bash
python -m oss_policy_kit evaluate --target .
```

### Every control is manual-review-required

You probably selected a profile that needs platform evidence not present in the clone. Run:

```bash
python -m oss_policy_kit recommend-profile --target .
```

Then start with the recommended baseline and add evidence-backed profiles later.

### The gate fails but the gap is intentional

Use a waiver with owner, reason, and expiry. Do not remove the control from the profile just to get a green check.
