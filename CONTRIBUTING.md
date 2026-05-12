# Contributing

Thanks for improving the OSS Security Policy as Code Starter Kit.

This repository is intentionally scoped. Contributions should strengthen the kit as a local OSS repository assessment tool, template pack, and release-readiness starter project.

## Principles

- Prefer small, reviewable changes with a clear reason.
- Keep claims honest. This project provides evidence, remediation cues, and local signals, not certification.
- Preserve explicit limits. Do not make the tool appear more authoritative than the available evidence supports.
- Add or update tests when behavior, reports, workflows, or policy semantics change.

## Development setup

Install the project in editable mode with developer tooling:

```bash
python -m pip install -e ".[dev]"
```

On Windows, prefer `python -m oss_policy_kit` instead of relying on the `oss-policy-kit` console script being on `PATH`.

## Local quality gates

Run these before opening or updating a pull request:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy src/oss_policy_kit
python -m pytest
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck
```

The CLI also accepts the same flags without the `evaluate` subcommand. Example:

```bash
python -m oss_policy_kit --target . --profile github-level-1 --output-dir ./out/selfcheck
```

### Known intermittent test issue (Windows + Python 3.12)

`tests/cli/test_cli_subprocess.py::test_subprocess_profiles_advisory_only_subset` (and other subprocess-based tests in the same file) can transiently fail on Windows with:

```
SystemError: ...lark/visitors.py:264: unknown opcode 211
```

This comes from the transitive chain `jsonschema -> rfc3987_syntax -> lark` when `lark` loads stale `__pycache__` `.pyc` files compiled for a different Python build. The CLI itself is unaffected (`python -m oss_policy_kit profiles --format json --advisory-only` works directly). If you hit this:

1. Re-run `python -m pytest -q` once — the failure is intermittent and usually clears on the next run.
2. If it persists, clear cached bytecode and try again:

   ```bash
   # from the repo root
   find . -type d -name __pycache__ -prune -exec rm -rf {} +
   python -m pytest -q
   ```

3. If it still persists, recreate the virtualenv from scratch with Python 3.12 and `python -m pip install -e ".[dev]"`.

Do not skip or `xfail` the test — the CLI behavior it covers is real.

## Project conventions

- Python source lives under `src/oss_policy_kit/`.
- Bundled policy data lives under `src/oss_policy_kit/data/`.
- Tests live under `tests/`, including repository-shaped fixtures under `tests/fixtures/repositories/`.
- Documentation under `docs/` should stay public-facing, accurate, and stable enough for end users.
- Example repositories under `examples/` should continue to demonstrate clearly distinct outcomes.

## What to update when behavior changes

If you change evaluator logic, report structure, or CLI output:

- update or add tests under `tests/`
- update relevant golden fixtures if the change is intentional
- update `README.md` and any affected docs under `docs/`
- update `CHANGELOG.md` with factual, non-marketing release notes

If you change packaged data or schemas:

- keep `src/oss_policy_kit/data/` and public schema references aligned
- avoid introducing cache or bytecode files into package data

If you change workflows or templates:

- keep least-privilege permissions explicit
- keep third-party actions pinned when the repository policy requires it
- validate the self-check and relevant examples after the change

## False positives and ambiguous results

If a reported finding looks technically wrong or too noisy, open the dedicated false-positive issue template and include:

- the profile id and, when available, the control id
- the smallest reliable reproduction
- the expected result versus the actual result
- enough repository-shape context for another maintainer to reproduce the behavior

Treat reproducible false positives as product defects. Add or update regression coverage before closing them.

## Maintainer release routine

Before tagging or announcing a release:

```bash
python -m build
python scripts/twine_check_dist.py
python scripts/consumer_smoke.py --repo-root .
```

Then verify:

- `pyproject.toml` and `src/oss_policy_kit/__init__.py` agree on the version
- `CHANGELOG.md` is up to date
- `README.md` and relevant docs still match actual behavior
- the repository security reporting path described in `SECURITY.md` is still correct

See [docs/packaging-and-release.md](docs/packaging-and-release.md) and [docs/release-readiness.md](docs/release-readiness.md) for the maintainer and release-readiness contract.

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for the maintainer set, decision-making process, release authority, and the path to becoming a maintainer.

## Security issues

Do not open public issues for undisclosed vulnerabilities.

Use the reporting path described in [SECURITY.md](SECURITY.md).
