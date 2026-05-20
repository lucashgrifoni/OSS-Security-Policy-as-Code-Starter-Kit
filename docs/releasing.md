# Releasing

Releases are automated from **Conventional Commits**. The flow:

1. **Land work on `master`** using Conventional Commit subjects
   (`feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `build:`, `ci:`, `chore:`,
   add `!` or a `BREAKING CHANGE:` footer for breaking changes).

2. **release-please opens a release PR** (`.github/workflows/release-please.yml`).
   It bumps the version in `pyproject.toml` and `src/oss_policy_kit/__init__.py`
   (the `# x-release-please-version` marker) and regenerates the `CHANGELOG.md`
   entry. Commit type → CHANGELOG section mapping (`.github/release-please-config.json`):
   - `feat` → **Highlights**
   - `fix` / `perf` / `refactor` → **Improvements**
   - `docs` / `build` / `ci` → **Notes**
   - `chore` / `test` → hidden

3. **Merge the release PR.** release-please tags the commit (`vX.Y.Z`) and creates
   a **draft** GitHub Release. The tag fires the rest of the pipeline:
   - `publish-pypi.yml` — build, attest, publish to PyPI (Trusted Publishing).
   - `publish-container.yml` — build, cosign keyless sign, publish to GHCR.
   - `release.yml` — rewrite the draft Release body into the standard template.

4. **Standard Release template** (`.github/workflows/release.yml`):

   ```
   ## OSS Security Policy as Code Starter Kit vX.Y.Z

   This release is ...

   ---
   ## Highlights      (feat)
   ---
   ## Improvements    (fix / perf / refactor)
   ---
   ## Notes           (docs / build / ci / other)
   ---
   **License:** Apache-2.0.
   ```

   The release is created as a **draft**. Refine the one-line *"This release is …"*
   summary (and curate bullets if needed), then **publish** the draft. A release that
   is already published is never overwritten by the workflow.

## Requirements

- A GitHub App (Contents RW, Pull requests RW, Issues RW) installed on the repo, with
  `RELEASE_PLEASE_APP_ID` and `RELEASE_PLEASE_APP_PRIVATE_KEY` repository secrets. The
  App token (not `GITHUB_TOKEN`) is what lets the release tag cascade into the publish
  workflows.

## Manual / re-generation

- Re-generate a draft Release body for an existing tag:
  `gh workflow run "Release notes" -f tag=vX.Y.Z` (only edits drafts; never clobbers a
  published release).
- Auto-publish instead of draft: in `release.yml`, the `create or update` step uses
  `--draft`; remove that flag to publish directly (not recommended — the
  *"This release is …"* line is best curated by a human).

## Supply-chain verification

Verification commands (PyPI dist + GHCR image) live in
[`docs/supply-chain-verification.md`](supply-chain-verification.md). The project ships
**GitHub Artifact Attestations + PyPI Trusted Publishing + cosign keyless** — it does
**not** claim SLSA Build L3.
