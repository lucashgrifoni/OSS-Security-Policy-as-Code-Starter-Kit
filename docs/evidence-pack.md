# Evidence Pack

This document is a practical walkthrough for reproducing evidence, opening the generated artifacts, and taking screenshots for the README.

## Recommended path (v3+): `collect-evidence` (GitHub)

To populate **`.oss-policy-kit/evidence/`** with real GitHub API data (instead of manual templates),
install the **`[github]`** extra, set **`GITHUB_TOKEN`**, then run:

```powershell
python -m oss_policy_kit collect-evidence --target . --platform github --repo org/repo
```

The **`org/repo`** slug can be omitted when the repository **`origin`** points to **github.com**.

## Azure DevOps (`collect-evidence --platform azure`)

Install **`oss-policy-kit[azure]`** (or **`httpx`**). Set **`AZURE_DEVOPS_ORG`** and
**`AZURE_DEVOPS_TOKEN`** (PAT with Code, Build, and Project read access). Pass
**`--repo ProjectName/repoName`** (automatic slug detection from git is not available yet).

```powershell
python -m oss_policy_kit collect-evidence --target . --platform azure --repo MyProject/my-repo
```

## AWS (`collect-evidence --platform aws`)

Install **`oss-policy-kit[aws]`** (or **`boto3`**). Use default AWS credentials and region
(**`AWS_REGION`** / **`AWS_DEFAULT_REGION`**). Set **`AWS_CODEBUILD_PROJECT`** and/or
**`AWS_CODEPIPELINE_NAME`** to drive collection. **`--repo`** is not required for AWS.

```powershell
$env:AWS_CODEBUILD_PROJECT = "my-build"
$env:AWS_CODEPIPELINE_NAME = "my-pipe"
python -m oss_policy_kit collect-evidence --target . --platform aws
```

## Token scopes (summary)

| Platform | Variables | Minimum scopes / IAM | Behavior when permissions are missing |
|------------|-----------|------------------------|-------------------------------------|
| **GitHub** | `GITHUB_TOKEN` required for `collect-evidence --platform github` | Repository metadata read plus branch protection/rulesets read (often requires administration-read scope or classic PAT `repo`). **ORG-MFA-001** is not collected here: it requires organization-level API access (for example `admin:org` read) or manual evidence. | **403** -> permission error; **404** on optional endpoints -> empty or conservative payload with log warnings. |
| **Azure DevOps** | `AZURE_DEVOPS_ORG`, `AZURE_DEVOPS_TOKEN` | PAT: **Code (read)** (`vso.code`), **Build (read)** (`vso.build`), **Service Endpoints (read)** (`vso.serviceendpoint`); **Release (read)** optional. | **401/403** -> `CollectionPermissionError`; unavailable APIs -> conservative notes and `posture_support` fields in JSON. |
| **AWS** | Default AWS account credentials; optional `AWS_CODEBUILD_PROJECT`, `AWS_CODEPIPELINE_NAME`, `AWS_REGION` | `codebuild:BatchGetProjects`, `codepipeline:GetPipeline`; additional IAM only if evidence collection needs calls like `iam:GetRole` / `iam:SimulatePrincipalPolicy`. | boto3 errors are mapped to `CollectionPermissionError` or `CollectionNetworkError`. |

## Artifact SBOM and provenance (Azure / AWS)

Controls **AZ-ARTSBOM-058**, **AZ-ARTPRV-059**, **AWS-SBOMART-058**, and **AWS-PROVART-059**
use JSON with SHA-256 digests bound to release artifacts. The APIs currently used by this kit
(**Azure DevOps** REST limited to policies/pipelines; **AWS** CodeBuild/CodePipeline)
do **not** expose a single canonical document aligned with
`evidence-azure-sbom-artifact`, `evidence-azure-provenance-artifact`,
`evidence-aws-sbom-artifact`, and `evidence-aws-provenance-artifact`.

`collect_sbom_artifact` / `collect_provenance_artifact` methods exist in collectors as optional
extension hooks and currently **log** that this evidence should be provided **manually** or generated
by your own pipeline (S3, Inspector, universal package feeds, etc.). See `collect()` docstrings in
`github_collector.py`, `azure_collector.py`, and `aws_collector.py` for current behavior.

## Dry-run security contract

`python -m oss_policy_kit collect-evidence --platform {github|azure|aws} --dry-run` is safe to run in public CI logs and transcripts. It contracts itself to printing **only**:

- the resolved target and output directory,
- the repository slug (detected from `origin` for GitHub; echoed for Azure; empty for AWS unless passed),
- the **names** of credential-related environment variables,
- whether each of those variables is `set` or `not set`,
- the JSON files that **would** be created (with the endpoint source hint),
- a final hint to re-run without `--dry-run` once credentials are ready.

It **never** prints the value of any environment variable, token, PAT, or secret. It never performs an authenticated API call. You can paste the full output of a dry-run into a public issue, a pull-request comment, or a public CI log without leaking credentials.

If you run the command without `--dry-run`, the real collectors do authenticate against GitHub/Azure DevOps/AWS and write evidence JSON under `.oss-policy-kit/evidence/`; at that point normal secret-handling rules apply (do not echo tokens, do not commit generated evidence with live identifiers into public forks, etc.).

## Manual mode: `scaffold-evidence`

Use this when you only need schema-aligned JSON templates for manual editing before evaluation.

**`org-mfa-posture.json` is cross-platform.** `scaffold-evidence --platform {github|aws|azure}` always emits `org-mfa-posture.json` in addition to the platform-specific files. This is intentional: the underlying control (**ORG-MFA-001**) tracks an organization-level posture that is not tied to a single SCM/CI platform, so the scaffold bundle includes it regardless of which `--platform` you passed. It is safe to leave the file as `self-attested` until you populate it with real organization data (or collect it out-of-band, since `collect-evidence` cannot read it without organization-level API access — see the "Token scopes" table above).

## How To Use This File

Run each command from the repository root.

After each command:

1. open the generated file
2. position the screen on the relevant section
3. take the screenshot

If the artifact already exists under `out/evidence/`, you can skip rerunning the command and go straight to the file.

## Step 1. Test Suite Evidence

Command (matches CI-style non-integration scope used in this repository):

```powershell
python -m pytest tests -k "not integration" -q
```

Expected result:

- a green summary line ending in `passed` (exact test counts move with the suite; treat the command output on **your** revision as the source of truth)
- exit code `0`

Artifact to open:

- `out/evidence/pytest.txt`

What to screenshot:

- the final pytest summary line with `passed`
- the `EXIT_CODE=0` line if visible

## Step 2. CLI Help Evidence

Command:

```powershell
python -m oss_policy_kit --help
```

Expected result:

- CLI usage is printed
- `evaluate` command is listed
- exit code table is visible

Artifact to open:

- `out/evidence/cli-help.txt`

What to screenshot:

- the `Usage:` line
- the `evaluate` command
- the exit code section

## Step 3. Hardened Example Evidence

Command:

```powershell
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/evidence/hardened
```

Expected result:

- the report is generated successfully
- summary is `pass: 14` for `github-level-1` (fixture aligned with the active profile control count)

Artifacts to open:

- `out/evidence/example-hardened.txt`
- `out/evidence/hardened/evaluation-report.md`

What to screenshot:

- in `evaluation-report.md`, the header and `Summary` table
- make sure `pass: 14` is visible

## Step 4. Vulnerable Example Evidence

Command:

```powershell
python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/evidence/vulnerable
```

Expected result:

- the report is generated successfully
- on a current kit revision, the vulnerable fixture typically clusters around multiple `fail` outcomes with a small number of `pass` and often one `manual-review-required` (exact counts are fixture-defined; re-run and read the printed JSON summary or Markdown `Summary` table as truth)

Artifacts to open:

- `out/evidence/example-vulnerable.txt`
- `out/evidence/vulnerable/evaluation-report.md`

What to screenshot:

- the `Summary` section
- optionally one part of the controls table showing failures

## Step 5. Repository Self-Check Evidence

Command:

```powershell
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/evidence/selfcheck-root
```

Expected result:

- the current repository is evaluated successfully
- **revision-dependent:** the self-check summary changes as the kit and repository evolve; compare runs using saved `evaluation-report.json` or `diff-reports` rather than assuming a fixed pass/fail mix

Artifacts to open:

- `out/evidence/selfcheck-root.txt`
- `out/evidence/selfcheck-root/evaluation-report.md`

What to screenshot:

- the report header
- the `Summary` table
- optionally the first failed controls in the controls table

## Step 6. CI Gate Evidence

Command:

```powershell
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/evidence/selfcheck-gated --fail-on fail
```

Expected result:

- reports are still written
- process returns exit code `1`
- this demonstrates gate behavior, not a crash

Artifacts to open:

- `out/evidence/selfcheck-gated.txt`
- `out/evidence/selfcheck-gated/evaluation-report.md`

What to screenshot:

- the lines showing the report files were written
- the final `EXIT_CODE=1`

## Step 7. JSON Summary Evidence

Command:

```powershell
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/evidence/selfcheck-summary --summary-only --format json
```

Expected result:

- compact JSON is printed
- `summary_by_status` is present
- `controls_total` is present

Artifact to open:

- `out/evidence/selfcheck-summary-json.txt`

What to screenshot:

- the full JSON line
- the `EXIT_CODE=0` line

## Step 8. Package Build Evidence

Command:

```powershell
python -m build
```

Expected result:

- source distribution is built
- wheel is built
- exit code `0`

Artifacts to open:

- `out/evidence/build.txt`
- `dist/`

What to screenshot:

- the final `Successfully built ... tar.gz and ... whl`
- optionally the `dist/` folder showing both artifacts

## Step 9. Installed Wheel Smoke Test

Commands:

```powershell
python -m venv out/evidence/venv-wheel-smoke
out/evidence/venv-wheel-smoke/Scripts/python.exe -m pip install dist/oss_policy_kit-1.0.2-py3-none-any.whl
out/evidence/venv-wheel-smoke/Scripts/python.exe -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/evidence/wheel-hardened
```

Expected result:

- the wheel installs in an isolated environment
- the installed CLI runs successfully
- hardened example again produces `pass: 14` on `github-level-1`

Artifacts to open:

- `out/evidence/wheel-smoke.txt`
- `out/evidence/wheel-hardened/evaluation-report.md`

What to screenshot:

- the installation success in `wheel-smoke.txt`
- the generated `wheel-hardened/evaluation-report.md` summary

## Best Screenshot Set For README

If you want a smaller set, use these five screenshots:

1. `out/evidence/pytest.txt`
2. `out/evidence/cli-help.txt`
3. `out/evidence/hardened/evaluation-report.md`
4. `out/evidence/selfcheck-root/evaluation-report.md`
5. `out/evidence/selfcheck-gated.txt`

## Ready-Made README Claim

Use wording like this:

> The project is operational and reproducible: tests pass, the CLI evaluates sample repositories, reports are generated in Markdown and JSON, build artifacts are produced, and CI-style policy gating behaves as documented.

Avoid claiming that the current repository revision is fully compliant unless the active self-check report shows that result.
