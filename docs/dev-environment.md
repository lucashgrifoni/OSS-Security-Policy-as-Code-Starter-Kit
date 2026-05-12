# Developer environment

Practical notes for working on the kit locally. Not a substitute for `CONTRIBUTING.md`.

## Python version

`pyproject.toml` declares `requires-python = ">=3.12"`. Earlier 3.x versions are not supported and will fail at install time.

## Editable install for development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Equivalent on bash / zsh:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## PATH note for installed scripts (Windows)

The `oss-policy-kit` console script is registered in `pyproject.toml`. On Windows, the user-site `Scripts/` directory may not be on `PATH` by default. Either:

1. Use the canonical form `python -m oss_policy_kit ...`, which always works.
2. Or activate a virtualenv (`.venv\Scripts\Activate.ps1`) so its `Scripts/` directory is on `PATH`.

## Local test loop

```powershell
python -m pytest -q
python -m pytest tests/cli/ -v
python -m pytest tests/cli/test_init.py tests/cli/test_evaluate_with_config.py tests/application/test_config_loader.py -v
```

## Lint and type check

```powershell
python -m ruff check src/ tests/
python -m mypy src/oss_policy_kit
```

## Bandit (local SAST sweep)

Bandit is part of the `[dev]` extra. On Windows, the default text formatter
can fail with `UnicodeEncodeError` on the system code page (`cp1252`). Use
the JSON formatter and force UTF-8 IO encoding for a robust local run:

```powershell
New-Item -ItemType Directory -Force security-results | Out-Null
$env:PYTHONIOENCODING = "utf-8"
python -m bandit -q -r src -f json -o security-results/bandit.json
```

Equivalent on bash / zsh:

```bash
mkdir -p security-results
PYTHONIOENCODING=utf-8 python -m bandit -q -r src -f json -o security-results/bandit.json
```

The Azure Pipelines template already uses the JSON formatter
(`pipelines/azure/azure-pipelines.yml`); on GitHub Actions the equivalent
SARIF-producing scanners (Semgrep, Trivy, Snyk Code, CodeQL) run in
`Security CI/CD` instead.

## CLI smoke checks

```powershell
python -m oss_policy_kit --version
python -m oss_policy_kit --help
python -m oss_policy_kit profiles --format json | Out-Null
python -m oss_policy_kit evaluate --target examples/hardened-repo --profile github-level-1 --output-dir .tmp-validation/smoke
```

## Local cache cleanup

The directories below are recreated automatically by their respective tools. Removing them locally is safe and saves disk space:

```powershell
Remove-Item -Recurse -Force .mypy_cache -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .ruff_cache -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .tmp-validation -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force out -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force artifacts -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
```

Be careful with the following — clean only when you understand the impact:

- `dist/` — may contain the latest wheel/sdist for a release. Do not remove if you are about to publish.
- `.venv-v5-baseline/` — maintainer venv from earlier release lines. Remove only if you no longer need it.
- `gitpage/node_modules/` — recreated by `npm ci` inside `gitpage/`. Removing forces a reinstall.

## Cross-platform line endings

`.gitattributes` forces `eol=lf` on `*.md`, `*.py`, `*.json`, `*.yml`, `*.yaml`, `*.toml`, and `.gitignore`. Files without those extensions (`LICENSE`, `NOTICE`, `CODEOWNERS`, `*.txt`) are left to the platform default. If `git status` shows EOL-only diffs on those files, revert them with:

```powershell
git diff <file>           # confirm only EOL changed
git checkout -- <file>    # restore the indexed version
```

Recommended `git config` for Windows contributors:

```powershell
git config --global core.autocrlf input
```

