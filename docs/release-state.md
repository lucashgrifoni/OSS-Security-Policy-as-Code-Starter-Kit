# Release state

## Public line

`v5.9.1` is the current public release. It is a patch over `v5.9.0`, correcting invalid pinned action SHAs in the container publication workflow. PyPI remains the primary install channel, and GitHub Release artifacts are the alternate channel when attached to a release.

## v6.0.0 development line

The local branch has landed the v6 development baseline (Cycle 1 + Cycle 2):

- 52 bundled profiles.
- 212 bundled controls.
- 17 CLI subcommands, including `emit-insights` and `export-evidence`.
- Three breaking changes tracked in the changelog: M-003, B-001, and B-002.
- `reports/1.0` remains the default during `6.0.0.dev0`; `reports/2.0` is opt-in.
- PyPI distribution attestations and source-built container publication are present locally, but release verification still requires an actual tag run.

## Release boundaries

Do not describe v6.0.0 as released until all of these happen:

1. Maintainer review is complete.
2. Branch is pushed to the public remote.
3. `v6.0.0` release tag is created intentionally.
4. PyPI/TestPyPI workflow evidence is reviewed.
5. GHCR image publish, cosign signature, and GitHub Artifact Attestation verification pass.
6. Changelog, migration guide, and release notes match the final tag.

## Current non-claims

- No SLSA Build L3 claim is made on this branch.
- No compliance or certification guarantee is made for CRA, EU AI Act, OSPS, SLSA, or SSDF.
- Clone-visible findings are not a substitute for live platform settings review.
