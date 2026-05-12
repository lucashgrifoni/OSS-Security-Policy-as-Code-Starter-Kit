# Recommended adoption playbook (official path)

This is the shortest reproducible path to adopt the kit with high signal and low interpretation overhead.

## Scope

This playbook targets:

- `github-level-1` with expected `pass: 14` (deprecated audit/SBOM YAML controls are catalog-only)
- additive adoption only (no compliance claim)
- Python repositories with `pyproject.toml` and a `src/` layout

## 1) Copy the baseline bundle

From this repository, copy into your target repository:

- `templates/workflows/ci.yml` -> `.github/workflows/ci.yml`
- `templates/workflows/security.yml` -> `.github/workflows/security.yml`
- `templates/waivers/waivers.yaml` -> `waivers/waivers.yaml`
- `templates/docs/SECURITY.md` -> `SECURITY.md`
- `templates/docs/CONTRIBUTING.md` -> `CONTRIBUTING.md`

Also ensure:

- a valid `LICENSE` file exists
- `.github/CODEOWNERS` exists
- `CHANGELOG.md` (or `docs/release-notes.md`) exists

## 2) Run baseline quality commands

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m mypy src/oss_policy_kit
python -m pytest
```

## 3) Evaluate and gate

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/adoption --format json
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/adoption-gate --fail-on fail
```

For a quick human-readable recap without opening the Markdown report:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/adoption --summary-only
```

If you operate several repos under one parent directory, batch evaluation is available via `evaluate-many` (see `README.md`).

Expected shape for this baseline:

- JSON summary includes `pass: 14` (one entry per active `github-level-1` control)
- `--fail-on fail` exits with code `0`

## 4) Optional hardening profile

If you also track branch protection evidence in-repo:

```bash
python -m oss_policy_kit evaluate --target . --profile github-release-hardening-1 --output-dir ./out/hardening --format json
```

`self-attested` for platform settings can still be expected locally.

## 5) Anti-overclaim checklist

Do not claim:

- certification
- automatic compliance
- remote platform verification from clone-only evidence

Treat outputs as local governance and workflow signals.
