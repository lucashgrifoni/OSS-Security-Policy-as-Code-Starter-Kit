# Container image

v5.9.0+ ships:

1. A `Dockerfile` at the repository root (multi-stage, non-root, container-baseline-1-compliant).
2. The `.github/workflows/publish-container.yml` workflow that publishes signed multi-arch images to `ghcr.io/<owner>/oss-policy-kit` on `v*` tag pushes.

Adopters can build locally today; CI automation activates when a tag is pushed.

## Build

```bash
docker build -t oss-policy-kit:5.9.0 .
```

The image installs from the checked-out source tree. The build arg is retained for image labels and release tag plumbing:

```bash
docker build --build-arg KIT_VERSION=5.9.0 -t oss-policy-kit:5.9.0 .
```

## Run

The image runs as a non-root user (uid 10001, container-baseline-1 expectation) with `python -m oss_policy_kit` as the entrypoint. Mount your repository at `/work`:

```bash
docker run --rm \
  -v "$(pwd):/work" \
  -w /work \
  oss-policy-kit:5.9.0 \
  evaluate --target . --profile github-level-1 --summary-only
```

For evidence collection that needs a token, pass it as an env var (never bake it into the image):

```bash
docker run --rm \
  -v "$(pwd):/work" \
  -w /work \
  -e GITHUB_TOKEN \
  oss-policy-kit:5.9.0 \
  collect-evidence --target . --platform github --repo owner/name
```

For `emit-vex` against an existing OSV-Scanner SARIF in your repo:

```bash
docker run --rm \
  -v "$(pwd):/work" \
  -w /work \
  oss-policy-kit:5.9.0 \
  emit-vex --waivers waivers/waivers.yaml --output vex.cyclonedx.json
```

## Design choices

- **Multi-stage build.** Builder stage installs the wheel into a venv; runtime stage copies only the venv. Keeps the final image small.
- **Pinned Python 3.12.** The kit declares `requires-python >=3.12` in `pyproject.toml`; the image matches.
- **Non-root user `appuser` (uid 10001).** Required by `container-baseline-1`'s `CONT-IMAGE-001..003` controls.
- **No build tools in the runtime image.** Source install happens in the builder stage, then only the venv is copied.
- **`[all]` extras installed by default.** A single image supports every subcommand including `collect-evidence` (GitHub / Azure / AWS) and the IaC scanners.
- **OCI labels** for `image.title`, `image.description`, `image.source`, `image.licenses`, `image.vendor` — feeds Sigstore Cosign provenance, image SBOM tooling, and registry discovery.
- **No PyPI race.** The release workflow builds the container from the checked-out tag instead of waiting for the package to appear on PyPI. See [ADR-017](decisions/adr-017-source-built-container-release.md).

## CI publication (v5.9.0+)

The `publish-container` workflow handles the release flow on `v*` tag pushes:

- **Multi-arch**: builds `linux/amd64` and `linux/arm64` via QEMU + Buildx.
- **Signed**: `cosign sign --yes` (keyless via Sigstore Public Good + GitHub OIDC). Verify with `cosign verify`.
- **Provenance**: `actions/attest-build-provenance` pushes a GitHub Artifact Attestation to the registry. Verify with `gh attestation verify oci://...`.
- **SBOM attached**: `sbom: true` on the Buildx build action; resulting SBOM is part of the OCI index.
- **Reproducible-ish**: pinned base image (`python:3.12-slim-bookworm`), pinned action SHAs, source-tree install from the release tag, and build-arg-controlled image version.
- **Tags**: `<version>` and `latest` on tagged releases; `edge` on manual `workflow_dispatch` runs.

To verify a published image:

```bash
cosign verify ghcr.io/<owner>/oss-policy-kit:5.9.0 \
  --certificate-identity-regexp 'https://github.com/<owner>/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

gh attestation verify oci://ghcr.io/<owner>/oss-policy-kit:5.9.0 \
  --repo <owner>/OSS-Security-Policy-as-Code-Starter-Kit
```

## When to use this image

- You want a Python-3.12-free CI runner.
- You self-host the kit inside a sandboxed VM / Kubernetes Job.
- You want a single, reproducible artifact to attach to a release archive.

## When NOT to use this image

- You are already running Python 3.12 on the CI runner — `pip install oss-policy-kit` is simpler.
- You need adapter-specific subcommands but want to omit the others to shrink the image. Build a slimmer image by replacing `oss-policy-kit[all]` with `oss-policy-kit[github]` (or whichever subset you need).

## Roadmap

- ~~**Publish workflow**~~ — **shipped in v5.9.0** (`.github/workflows/publish-container.yml`).
- ~~**Image signing**~~ — **shipped in v5.9.0** (cosign keyless via Sigstore Public Good).
- ~~**SBOM attachment**~~ — **shipped in v5.9.0** (Buildx `sbom: true`).
- **Reproducible builds via base image digest pinning** — still planned. The Dockerfile pins `python:3.12-slim-bookworm` by tag; pinning by digest (`@sha256:...`) is a follow-up to balance reproducibility vs upstream patch absorption.
- **`--source-date-epoch` integration** — planned for byte-reproducible images.
