# Pre-commit integration

The kit publishes a `.pre-commit-hooks.yaml` so adopters using [pre-commit.com](https://pre-commit.com) can wire a clone-visible evaluation into their developer flow without installing the kit globally.

This is **complementary** to running the kit in CI — the CI gate stays authoritative because pre-commit runs only on the developer's machine. The pre-commit hook catches violations earlier in the loop.

---

## Hooks shipped

### `oss-policy-kit-evaluate`

Runs `python -m oss_policy_kit evaluate --target . --fail-on fail --summary-only` on `pre-push`. Use for **deterministic / hard-gate ladder profiles** (`*-level-3`, `*-release-hardening-3`, `appsec-sast-sca-1` with `scan-sast` evidence). Fails the push when the gate sees a `fail` result.

### `oss-policy-kit-evaluate-degraded`

Runs `python -m oss_policy_kit evaluate --target . --fail-on degraded --summary-only` on `pre-push`. Use for **advisory profiles** (every `cra-eu-*`, `osps-baseline-1`, `slsa-build-l2-1`, `ssdf-baseline-1`, `cis-supply-chain-1`, `owasp-cicd-top10-1`, `s2c2f-l1-1`, the IaC / Kubernetes / container baselines, and `webhook-security-1`).

Why two hooks? `--fail-on fail` paired with an advisory profile defeats the design — advisory profiles surface `manual-review-required` on platform/SBOM/provenance controls when evidence files are not filled, and treating that as a hard block creates false outage signals. The two-hook split makes the contract explicit.

### `oss-policy-kit-validate-profiles`

Runs `python scripts/validate-bundled-profiles.py` on `pre-commit`. For **kit maintainers** and adopters who extend the bundled catalog with custom profiles: every `control_ids` member must resolve in the catalog; unknown IDs / removed IDs / orphan controls fail the hook.

---

## Adopter configuration

In your repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit
    rev: v6.4.0  # always pin to a tag; floating refs are not supported
    hooks:
      - id: oss-policy-kit-evaluate
```

For an advisory profile (e.g. CRA preparation):

```yaml
repos:
  - repo: https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit
    rev: v6.4.0
    hooks:
      - id: oss-policy-kit-evaluate-degraded
```

Then run:

```bash
pre-commit install --hook-type pre-push
pre-commit install --hook-type pre-commit  # only if using oss-policy-kit-validate-profiles
```

---

## What the hook expects

- The repository must have an `oss-policy-kit.yaml` at the root (run `python -m oss_policy_kit init --target .` once if it does not exist).
- Python 3.12+ on the developer's machine.
- The kit is installed as a dependency of the hook via pre-commit's own venv — no global install required.
- If the repository uses a profile that needs evidence files (`*-release-hardening-2/3`, `cra-eu-strict-1`, etc.), the corresponding files must exist under `.oss-policy-kit/evidence/` or the hook will surface them as gaps.

---

## What the hook does not replace

The pre-commit hook is a **local convenience**, not a release gate. It cannot:

- Verify platform evidence the kit collects via `collect-evidence` (org-scope token required).
- Replace the CI gate (the developer can skip pre-commit with `--no-verify`).
- Substitute for a release-hardening review when the artifact is being signed and published.

For those, keep the canonical CI workflow described in [`docs/github-action.md`](github-action.md) and the release playbook in [`docs/release-playbook-hardgate.md`](release-playbook-hardgate.md).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Hook fails with "No such option: --target" | Old kit version pinned | Bump `rev:` to a version `>= v5.4.0` (when the unified target-pos flag landed) |
| Hook hangs on first run | pre-commit is installing the kit into its venv | First run downloads + installs; subsequent runs are fast |
| Hook fails on advisory profile with `manual-review-required` | Using `oss-policy-kit-evaluate` (hard gate) with an advisory profile | Switch to `oss-policy-kit-evaluate-degraded` |
| Hook passes locally but CI fails | Evidence files filled locally but not committed | Check `.gitignore`; the kit's evidence files under `.oss-policy-kit/evidence/` should be committed when they represent shared posture |
