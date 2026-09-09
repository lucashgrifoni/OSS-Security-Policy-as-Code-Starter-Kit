# Packaging and release

This document describes how to install, build, validate, and distribute the `oss-policy-kit` package.

## Supported distribution channels

| Channel | Audience | Notes |
| --- | --- | --- |
| PyPI package (`oss-policy-kit`) | end users and CI consumers | primary install channel: `python -m pip install oss-policy-kit` |
| Wheel or sdist attached to a GitHub Release | end users and CI consumers | alternative install path when you pin release assets directly |
| Git clone + editable install | contributors and maintainers | `python -m pip install -e ".[dev]"` |

## What gets published

- `sdist` (`.tar.gz`)
- `wheel` (`.whl`)
- CycloneDX SBOM JSON as a release/documentation artifact (`artifacts/sbom.cyclonedx.json`)

Policy data is packaged only from `src/oss_policy_kit/data/` using explicit YAML and JSON globs. Packaging intentionally excludes cache and bytecode files.

## Prerequisites

- Python 3.12+
- current enough `pip` for PEP 517 builds

Developer install:

```bash
python -m pip install -e ".[dev]"
```

Minimal one-off build tooling:

```bash
python -m pip install --upgrade pip build twine
```

## Dependency and supply-chain posture

Runtime dependencies live under `[project].dependencies` in `pyproject.toml`.

Principles:

- keep runtime dependencies minimal
- prefer actively maintained packages with clear licenses
- use conservative version ranges
- keep dev-only tooling under `[project.optional-dependencies].dev`

Security-related checks already used by this repository:

- dependency review on pull requests
- `pip-audit` in the security workflow
- SBOM generation in the package workflow

Useful local release-time check:

```bash
pip install pip-audit
pip-audit
```

## Local build and validation

Clean stale artifacts first:

```bash
rm -rf dist build .consumer-smoke-venv src/*.egg-info
```

Windows PowerShell:

```powershell
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue dist, build, .consumer-smoke-venv
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue src\oss_policy_kit.egg-info
```

Build and validate:

```bash
python -m build
python scripts/twine_check_dist.py
```

The helper resolves the sdist and wheel that match the current `pyproject.toml` version and runs `twine check` with **explicit paths**, so it behaves correctly on **Windows PowerShell** (where `dist/*` is not expanded the same way as on POSIX shells).

POSIX shell (explicit globs, no helper):

```bash
python -m build
python -m twine check dist/oss_policy_kit-*.tar.gz dist/oss_policy_kit-*.whl
```

Windows PowerShell (explicit files after `build`; adjust the version segment if needed):

```powershell
python -m build
python -m twine check @(
    (Get-ChildItem -Path dist -Filter "oss_policy_kit-*.tar.gz" -File).FullName
    (Get-ChildItem -Path dist -Filter "oss_policy_kit-*.whl" -File).FullName
)
```

## Install the wheel in a clean environment

```bash
python -m venv .venv-release
# Windows: .venv-release\Scripts\activate
# Unix: source .venv-release/bin/activate
python -m pip install dist/*.whl
python -m oss_policy_kit --help
python -m oss_policy_kit evaluate --help
```

Windows PowerShell:

```powershell
python -m venv .venv-release
.\.venv-release\Scripts\Activate.ps1
python -m pip install (Get-ChildItem dist\oss_policy_kit-*.whl | Sort-Object Name | Select-Object -Last 1)
python -m oss_policy_kit --help
```

## Official consumer smoke

The repository ships `scripts/consumer_smoke.py` for a reproducible end-user style smoke run.

What it does:

1. creates a temporary isolated venv
2. installs the wheel that matches the current `pyproject.toml` version from `dist/`
3. runs `--version`, `--help`, `evaluate --help`, self-check, hardened/vulnerable examples, `--fail-on`, waivers, and `--kit-root`
4. writes `out/consumer-smoke-summary.json` and `out/consumer-smoke-summary.md`

It fails fast when the current-version wheel is missing or ambiguous.

Run it after `python -m build`:

```bash
python scripts/consumer_smoke.py --repo-root .
```

Windows PowerShell:

```powershell
python .\scripts\consumer_smoke.py --repo-root .
```

Use `--keep-venv` only when debugging.

## CI validation

`Package` in `.github/workflows/github-ci-cd.yml` runs on every push and pull request and:

1. cleans build artifacts
2. runs `python -m build`
3. runs `python scripts/twine_check_dist.py` (twine with explicit artifact paths)
4. generates a CycloneDX SBOM
5. installs the built wheel into a clean environment with `--no-deps`, so the wheel's
   own dependency metadata is what gets exercised, and runs the CLI help commands

It validates artifacts and publishes nothing. Publication is a separate workflow that
runs only on a tag push (see the release flow below).

## Versioning and changelog discipline

Versions are not edited by hand. [release-please](https://github.com/googleapis/release-please)
reads the Conventional Commit subjects merged to `master` since the previous tag, decides
the bump (`fix` = patch, `feat` = minor, `feat!` or a `BREAKING CHANGE` footer = major) and
keeps ONE open pull request titled `chore(master): release X.Y.Z` that carries:

- the version in `pyproject.toml`, `src/oss_policy_kit/__init__.py` and the docs listed
  under `extra-files` in `.github/release-please-config.json`
- the `CHANGELOG.md` section, grouped by the `changelog-sections` in that file
  (`feat` under Highlights, `fix` under Fixes, `perf` and `refactor` under Improvements,
  `docs` / `build` / `ci` under Notes)

What that means for a commit: the subject is the changelog line, so write it for the
reader of the changelog. An unbalanced parenthesis in a commit body makes release-please
drop the commit from the changelog silently while the run stays green.

## Release flow

The whole flow, in the order it actually happens. Steps 3, 5 and 6 are the maintainer's;
everything else is a workflow.

1. Merge the release pull request. Its merge commit is `chore(master): release X.Y.Z`.
2. release-please runs on that merge and creates a **draft** GitHub Release named
   `vX.Y.Z`. `draft: true` in its config means the git tag is NOT created: a draft
   release names a tag that does not yet exist.
3. Create the tag on the merge commit and push it. Tags are signed:

   ```bash
   git tag -s vX.Y.Z -m "oss-policy-kit X.Y.Z" <merge-commit-sha>
   git push origin vX.Y.Z
   ```

4. The tag push starts three workflows. `publish-pypi.yml` builds from the tag and
   publishes through Trusted Publishing with attestations. `publish-container.yml`
   builds the multi-architecture image from the same checkout and pushes it to GHCR,
   signed with cosign. `release.yml` renders the release notes from the commits between
   the previous tag and this one, updates the draft, and closes the transient
   release-please PR described below.
5. Publish the draft release once the notes read correctly. `release.yml` never
   publishes: a person reads the summary line first.
6. Validate the published artifacts from a clean environment, not from the working
   tree: `pip install oss-policy-kit==X.Y.Z` in a fresh virtualenv, pull the GHCR image
   by digest, and run the consumer smoke above against both.

### Rolling back a published release

A published version cannot be replaced. PyPI refuses a re-upload of a filename it already
holds, and the GHCR digest of a pushed image never changes. Rollback here means pointing
consumers at the previous version, not editing this one.

What an adopter does, and what it was measured to give:

```bash
pip install "oss-policy-kit==<previous version>"
docker pull ghcr.io/lucashgrifoni/oss-policy-kit@sha256:<previous digest>
```

Verified against 10.0.19 while 10.0.20 was current: the older wheel installs and reports
its own version, evaluates the same target to the same verdicts and the same weighted
score, and `diff-reports` reads across the boundary in both directions -- an older build
reading a newer report and the reverse -- with no regressions and no schema mismatch. Patch
releases share the `reports/2.0` contract, so a rollback within a major does not strand a
report an adopter already stored. A rollback across a major does; the migration guide for
that major is the document that says how.

The maintainer's side of a bad release:

1. Do not delete the tag or the release. Both are referenced by the provenance already
   published for the artifacts, and removing them turns every verification into a failure
   that looks like tampering.
2. Yank the version on PyPI. A yanked version stays installable for anyone who pins it
   exactly and disappears from resolution for everyone else. This step has not been
   exercised on this project -- it is the documented PyPI behaviour, not a measured result.
3. Ship the fix as the next patch. `latest` on GHCR moves to it on the next tag push; until
   then `latest` still points at the bad digest, which is the argument for pinning by digest
   in the line above.

### The transient major-bump pull request

Minutes after step 1, a second release PR titled with the NEXT MAJOR (`release 11.0.0`
right after `10.0.18`) appears. It is not a signal that a major is due. release-please
runs on the merge commit before the tag exists, its last-release lookup finds nothing,
and it computes a bump from the whole history, breaking changes from earlier majors
included. Since v10.0.19 `release.yml` closes that PR on the tag push and records the
reason on it. If it is still open after step 4, close it; do not merge it.

## Private Maintainer Notes

Maintainer-private planning notes, prompts, exploratory audits, and local validation scratchpads must stay outside the
public repository tree. Keep them in a private workspace or private repository and copy only durable, public-facing
outcomes into `docs/`, `CHANGELOG.md`, tests, or release notes.

Before a public release, verify:

```bash
git ls-files private-notes
```

The command should return no tracked files.

## PyPI

PyPI is an active distribution channel for this project.

Consumer install examples:

```bash
python -m pip install oss-policy-kit
python -m pip install oss-policy-kit==<version>
python -m oss_policy_kit --version
```

Keep the distinction explicit:

- **Distribution channels for users:** PyPI (primary), GitHub Release wheel/sdist (alternative).
- **Internal release process:** build, validate (`twine check` and consumer smoke), test on TestPyPI first, then publish/upload through maintainer-controlled release steps.

If a release is available on GitHub before PyPI propagation completes, GitHub Release artifacts remain a valid temporary install path for consumers who need that exact build immediately.

## `publish-pypi.yml` workflow

`.github/workflows/publish-pypi.yml`:

- Pins third-party GitHub Actions to immutable commit SHAs (with `# vX.Y` comments for humans).
- **`workflow_dispatch`** with **`target=testpypi`** publishes to TestPyPI first (**recommended** gate before wider promotion).
- Production PyPI publication runs from **`publish-pypi`** only on **`push`** of version tags **`v*`** (OIDC to `pypi`).
