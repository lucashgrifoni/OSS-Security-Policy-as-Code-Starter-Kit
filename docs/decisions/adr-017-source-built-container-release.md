# ADR-017 - Build container images from release source instead of PyPI

## Status

Accepted for the v6.0.0 development branch.

## Context

The PyPI and GHCR workflows both run on `v*` tag pushes. The original container build installed `oss-policy-kit==${KIT_VERSION}` from PyPI. That created a race: GHCR could start before PyPI propagation completed, causing a failed image build even though the tag and package were otherwise valid.

## Decision

The official Dockerfile now installs from the checked-out release source tree:

```dockerfile
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --upgrade pip \
    && pip install ".[all]"
```

The container workflow keeps the tag trigger, cosign keyless signing, Buildx SBOM generation, and GitHub Artifact Attestation flow. `KIT_VERSION` remains as an image label/build-arg input, not as the package source.

## Alternatives considered

1. **Use `workflow_run` after PyPI publish.** Rejected for this branch because tag behavior through `workflow_run.head_branch` needs release-candidate testing and would make the release graph harder to reason about.
2. **Build the wheel in PyPI workflow and pass `dist/` to the container workflow.** Deferred. It is more reproducible, but requires a larger workflow restructure.
3. **Manual rerun after PyPI propagation.** Rejected. It leaves the release dependent on operator timing.

## Consequences

- The container image is bound to the source at the release tag.
- The GHCR build no longer depends on PyPI propagation timing.
- PyPI and GHCR artifacts can still be verified independently.
- The image is not byte-reproducible yet; base image digest pinning and `SOURCE_DATE_EPOCH` remain follow-ups.

## Validation

Local structural tests assert that the Dockerfile contains `pip install ".[all]"` and does not install `oss-policy-kit[all]==...` from PyPI. A real tag run is still required before claiming production release evidence.
