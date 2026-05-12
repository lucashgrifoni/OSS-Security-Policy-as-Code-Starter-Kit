# Quickstart in 15 minutes

This guide takes a fresh clone of any public repository to a first
`evaluation-report.md` in under 15 minutes. It assumes only Python 3.12+
and `pip`. No GitHub token, no AWS credentials, no Azure login is
required.

If anything below takes longer than 15 minutes, please open an issue.
The kit fails honestly when something is missing, and that surface
should be visible in the documentation.

## 1. Install (2 minutes)

```bash
python -m venv .venv
# Windows:    .venv\Scripts\activate
# Linux/Mac:  source .venv/bin/activate
pip install oss-policy-kit
oss-policy-kit --version
```

Expected output: a version line like `5.8.0`. If `oss-policy-kit` is
not on `PATH`, use `python -m oss_policy_kit` instead (works identically
on every command below).

## 2. Run the hardened example (2 minutes)

The kit ships two example repositories. Start with the hardened one to
confirm everything works on your machine:

```bash
git clone https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit.git
cd OSS-Security-Policy-as-Code-Starter-Kit
oss-policy-kit evaluate \
  --target ./examples/hardened-repo \
  --profile github-level-1 \
  --output-dir ./out/hardened \
  --summary-only
```

Expected: `Outcome: pass=14`, score `28/28 (100.0%)`. The report files
land at `./out/hardened/evaluation-report.json` and
`./out/hardened/evaluation-report.md`.

## 3. Run the vulnerable example (2 minutes)

Same command, different target. This one is intentionally weak across
the bundled baseline:

```bash
oss-policy-kit evaluate \
  --target ./examples/vulnerable-repo \
  --profile github-level-1 \
  --output-dir ./out/vulnerable \
  --summary-only \
  --fail-on fail
```

Expected: 11 controls fail, exit code `1`. That `1` is the same signal
CI would surface: every adopter sees exactly what their pipeline will
see.

## 4. Run against your own repo (5 minutes)

Pick a public repository (yours or a third party):

```bash
git clone https://github.com/<owner>/<repo>.git ./my-repo
oss-policy-kit evaluate \
  --target ./my-repo \
  --profile github-level-1 \
  --output-dir ./out/my-repo \
  --summary-only
```

Open `./out/my-repo/evaluation-report.md` in any Markdown viewer.

Three pieces of output matter at this point:

- **`Outcome:`** line — quick pass / fail / manual-review counts.
- **`Top gaps:`** block — the highest-weight controls that did not
  pass, with a one-line remediation hint each.
- **`Suggested next step:`** line — the single action with the largest
  payoff against this profile.

## 5. Choose a profile that fits (2 minutes)

`github-level-1` is the safest first profile. Ask the kit what fits
your repo:

```bash
oss-policy-kit recommend-profile --target ./my-repo
```

This is a **heuristic, not a compliance decision** (the output says so
itself). Use the suggestion as a starting point. The 36 bundled
profiles are documented in [`docs/profiles/overview.md`](profiles/overview.md).

## 6. Add a waiver if a gap is intentional (1 minute)

Some failing controls are intentional. Document them in a waiver file
so the gap stays explicit:

```bash
cp templates/waivers/waivers.yaml ./my-repo/waivers/waivers.yaml
# edit with owner, justification, expires_on
oss-policy-kit evaluate \
  --target ./my-repo \
  --profile github-level-1 \
  --waivers ./my-repo/waivers/waivers.yaml \
  --output-dir ./out/my-repo
```

Waiver tracking itself is a control (`GOV-WAIV-014`): the report will
list each applied waiver, its owner, and its expiry date.

## 7. Wire it into CI (1 minute)

Use the bundled GitHub Action:

```yaml
- uses: lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit@v5
  with:
    profile: github-level-1
    fail-on: fail
```

Done. The repo now gates pull requests on the same baseline you ran
locally.

## Next steps

- **More signals**: pair `evaluate` with `scan-iac`, `scan-k8s`,
  `scan-cfn`, `scan-pulumi`, `scan-bicep`, or `scan-sast` to enrich the
  evidence the evaluator sees.
- **Release gate**: switch to a `*-release-hardening-*` profile and run
  `scaffold-evidence` to declare the release posture explicitly.
- **Reference**: see [`docs/cli-reference.md`](cli-reference.md) for
  every flag.

## When something fails

- `oss-policy-kit --version` works but `oss-policy-kit` is not on
  `PATH`: use `python -m oss_policy_kit` everywhere instead.
- `pip install oss-policy-kit` complains about Python version: the kit
  requires Python 3.12+. Earlier versions are not supported.
- `evaluate` finishes but every control says `manual-review-required`:
  the target is missing the in-repo signals the profile expects. Try
  `recommend-profile` to surface a profile that fits the repo's shape.

The kit's design rule: surface the gap honestly, never silently pass.
If the output ever feels wrong, the report itself should explain why.
