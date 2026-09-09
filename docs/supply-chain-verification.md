# Supply chain verification

This project currently uses GitHub Artifact Attestations, PyPI Trusted Publishing attestations, and cosign keyless signing. It does not claim SLSA Build L3 on this branch because there is no `slsa-github-generator` provenance workflow and no successful `slsa-verifier` pre-release run recorded here.

## Release assets

From v6.0.1 onward, each tagged GitHub Release attaches:

- the wheel and sdist (`oss_policy_kit-<version>-py3-none-any.whl`, `oss_policy_kit-<version>.tar.gz`),
- a CycloneDX SBOM (`sbom.cyclonedx.json`),
- the build provenance bundle (`oss-policy-kit.intoto.jsonl`).

These are produced by the `publish-pypi` workflow on the release tag. The
provenance bundle is the GitHub Artifact Attestation for the distributions; you
can also verify the wheel/sdist directly with `gh attestation verify` as shown
below without downloading the bundle.

## Verifying PyPI artifacts

Download the wheel or sdist from the GitHub Release assets for the version you want to verify, then run:

```bash
gh attestation verify oss_policy_kit-<version>-py3-none-any.whl \
  --repo lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit

gh attestation verify oss_policy_kit-<version>.tar.gz \
  --repo lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit
```

For artifacts downloaded from PyPI, verify the direct distribution file URL against
PyPI's Integrity API provenance object:

```bash
python -m pip install pypi-attestations

export WHEEL_DIRECT_URL="https://files.pythonhosted.org/packages/.../oss_policy_kit-<version>-py3-none-any.whl"

pypi-attestations verify pypi \
  --repository https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit \
  "$WHEEL_DIRECT_URL"
```

The direct URL is available from the PyPI release file page or the simple JSON
API. The PyPI publication path uses Trusted Publishing and explicitly enables
`pypa/gh-action-pypi-publish` attestations. Those attestations identify the
GitHub Actions workflow identity that published the distribution; they do not
prove that the source code is vulnerability-free.

## Verifying container images

Verify the cosign keyless signature:

```bash
cosign verify ghcr.io/lucashgrifoni/oss-policy-kit:<version> \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Verify the GitHub Artifact Attestation attached to the OCI image:

```bash
gh attestation verify oci://ghcr.io/lucashgrifoni/oss-policy-kit:<version> \
  --repo lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit
```

The container workflow builds from the checked-out release tag instead of installing from PyPI. That removes the release race where the GHCR build starts before the PyPI package is visible.

## Rebuilding the wheel yourself

Signature and provenance say the artifact came from this repository's workflow. Rebuilding
says the artifact came from the source you can read. They answer different questions, and
the second one needs no trust in GitHub at all.

```bash
# `-c core.autocrlf=false` at clone time. On Windows the default rewrites LICENSE and
# NOTICE to CRLF, and both are hashed into the wheel's RECORD.
git -c core.autocrlf=false clone https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit.git
cd OSS-Security-Policy-as-Code-Starter-Kit
git checkout v<version>

# Read the epoch on the host: the build image has no git.
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)

docker run --rm -v "$PWD:/src" -w /build -e SOURCE_DATE_EPOCH python:3.12-slim bash -c '
  cp -r /src/. /build && rm -rf dist build src/*.egg-info
  find . -type f -exec chmod 644 {} + && find . -type d -exec chmod 755 {} +
  pip install -q build && python -m build --wheel && sha256sum dist/*.whl'
```

Compare that hash against the wheel on PyPI or the GitHub Release.

What to expect:

| Release | Wheel | Source distribution |
|---|---|---|
| Anything published after v10.0.20 | Identical hash | Identical file contents; the gzip header and the mtimes of the generated `egg-info` members still carry build time |
| v10.0.20 and earlier | Identical contents, all 231 entries; different hash | Identical file contents, different hash |

The split is deliberate rather than a caveat about tooling. Through v10.0.20 the build did
not set `SOURCE_DATE_EPOCH`, so every timestamp inside the wheel was the runner's clock at
checkout -- v10.0.20 carries 16:08:18 on the source entries and 16:08:30 on the generated
ones. Nobody outside that run can replay it. From the next release the epoch is the
committer date of the commit being built, which anyone holding the tag also holds.

If a hash differs on a release that should match, compare entry by entry before concluding
anything. Two of the differences are usually yours rather than the release's: line endings,
which the clone flag above settles, and file modes, which is what the `chmod` line settles.

## Trust model

| Artifact | Current evidence | What it proves | What it does not prove |
|---|---|---|---|
| Wheel / sdist from GitHub Release | GitHub Artifact Attestation for `dist/*` | The files were produced by the repository workflow identity | SLSA Build L3, vulnerability absence, or maintainer intent |
| Wheel / sdist on PyPI | PyPI Trusted Publishing attestation | The upload used the configured trusted publisher identity | That the package is safe to install |
| GHCR image | cosign keyless signature + GitHub Artifact Attestation | The image digest is bound to the GitHub workflow identity | That every dependency is vulnerability-free |

## Future SLSA path

To claim SLSA Build L3 later, add a dedicated SLSA provenance workflow, attach `.intoto.jsonl` provenance to the release, pin the generator by full SHA or stable tag resolved to SHA, and run `slsa-verifier` against a pre-release tag before changing README or launch wording.

## References

- [PyPI digital attestations](https://docs.pypi.org/attestations/)
- [PyPI producing attestations](https://docs.pypi.org/attestations/producing-attestations/)
- [PyPI consuming attestations](https://docs.pypi.org/attestations/consuming-attestations/)
- [GitHub Artifact Attestations](https://docs.github.com/actions/concepts/security/artifact-attestations)
- [GitHub CLI attestation verify](https://cli.github.com/manual/gh_attestation_verify)
