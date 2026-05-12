## Summary

- What changed?
- Why was the change needed?

## Validation

- [ ] `python -m pytest`
- [ ] `python -m ruff check .`
- [ ] `python -m ruff format --check .`
- [ ] `python -m mypy src/oss_policy_kit`
- [ ] Relevant CLI smoke test executed (examples and/or `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck`, or the top-level equivalent without `evaluate`)
- [ ] If packaging, metadata, or `.github/workflows/github-ci-cd.yml` / `.github/workflows/security-ci-cd.yml` changed: `python -m build` and `python scripts/twine_check_dist.py` (after cleaning `dist/`, `build/`, `src/*.egg-info`; avoids fragile `dist/*` on Windows PowerShell)

## Release / security impact

- [ ] No public contract changed
- [ ] Breaking change documented, if applicable
- [ ] Security-sensitive behavior reviewed
- [ ] Docs updated, if applicable
- [ ] PR description does not imply OSPS certification, automatic compliance, or "pass = safe" guarantees
