# Supply chain verification

This project currently uses GitHub Artifact Attestations, PyPI Trusted Publishing attestations, and cosign keyless signing. It does not claim SLSA Build L3 on this branch because there is no `slsa-github-generator` provenance workflow and no successful `slsa-verifier` pre-release run recorded here.

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
