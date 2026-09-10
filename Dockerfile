# Official container image for oss-policy-kit (builds the current source tree;
# containerized since v5.9.0). The published image is tagged per release on GHCR.
#
# Design choices:
#
# - Multi-stage build: a builder image installs the wheel into a venv,
#   the runtime image only copies the venv. Final image stays under 200 MB.
# - Pinned Python minor: 3.12 (the kit's declared minimum is >=3.12; we do
#   not chase 3.13 yet because some dependencies still have rough edges).
# - Non-root user: `appuser` (uid 10001). Required by container-baseline-1.
# - Read-only-friendly: nothing writes to the image filesystem at runtime;
#   adopters mount their repo and an output volume.
# - No build tools in the runtime image: source install happens in the
#   builder stage so the runtime stays minimal.
#
# Example usage (adopter side):
#
#   docker build -t oss-policy-kit:latest .
#   docker run --rm -v "$(pwd):/work" -w /work oss-policy-kit:latest \
#     evaluate --target . --profile github-level-1 --summary-only
#
# The publish workflow builds from the checked-out tag instead of installing
# from PyPI, avoiding a tag-push race between package and container release.

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
# Base image pinned by digest (supply-chain hardening). The human-readable tag is
# kept for clarity.
#
# NOTHING REFRESHES THIS AUTOMATICALLY, despite the docker ecosystem being
# configured in .github/dependabot.yml. Dependabot's docker updater fires when a
# newer TAG appears; `3.12-slim-bookworm` is a rolling tag whose name never
# changes, so the digest behind it moves upstream and Dependabot has nothing to
# propose. It has opened zero docker pull requests on this repository while
# opening them routinely for pip, npm and github-actions -- the coverage looked
# real and was not. This comment previously claimed Dependabot refreshed the
# digest; it never has.
#
# Until something watches it, refresh by hand and check what it buys:
#   docker buildx imagetools inspect python:3.12-slim-bookworm --format '{{.Manifest.Digest}}'
#   trivy image --severity CRITICAL,HIGH --ignore-unfixed python@<digest>
FROM python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134 AS builder

# Build-time environment hygiene. PIP_NO_CACHE_DIR keeps the wheel cache
# out of the final image; PYTHONDONTWRITEBYTECODE avoids stray __pycache__
# directories embedded in the venv.
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install build tools needed for the optional dependencies. The default
# install uses the package's `all` extra so adopters get a single image
# capable of running every subcommand including collect-evidence and the
# IaC scanners.
#
# Note: KICS "Apt Get Install Pin Version Not Defined" is intentionally NOT
# pinned here. These packages exist only in this discarded builder stage and
# are never shipped in the runtime image; Debian rotates point-release versions
# within weeks, so a hard `pkg=version` pin becomes uninstallable and breaks
# the build for no security gain. The finding is accepted via `exclude_queries`
# in .github/workflows/security-ci-cd.yml (query 965a08d7-...).
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        git \
    && rm -rf /var/lib/apt/lists/*

# Create the venv we will copy into the runtime image.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install the package from the checked-out source tree. This keeps the
# release image bound to the Git tag being built and removes any dependency
# on PyPI propagation timing.
ARG KIT_VERSION=5.9.0
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY .github/requirements/pip.txt .github/requirements/runtime-all.txt /tmp/requirements/
COPY src ./src
# --no-cache-dir is redundant with ENV PIP_NO_CACHE_DIR=1 above, but stated
# explicitly so KICS "Pip install Keeping Cached Packages" reads it directly.
#
# Every byte that crosses the network is checked against a hash recorded in the
# repository:
#
#   1. pip itself, from .github/requirements/pip.txt. The venv's pip is upgraded
#      because the base image's copy is old: 25.0.1 carried five advisories, and
#      26.1.2 -- the previous pin -- had since gained one of its own (CVE-2026-13346,
#      fixed in 26.2.0). A `pip==` pin inside a RUN string is invisible to the
#      filesystem scans; the built-image scan in github-ci-cd.yml is what sees it.
#   2. the runtime dependency closure of `.[all]`, from runtime-all.txt. Regenerate
#      with the `uv pip compile` line recorded at the top of that file.
#   3. the kit itself: built into a wheel, then installed from that wheel. The
#      checkout is the one artifact with no hash to carry, because it is the thing
#      being built.
#
# The build and the install are two steps rather than a single `pip install .`
# because Scorecard reads an install whose argument is a bare path as an unpinned
# download, and one whose argument ends in `.whl` as pinned -- `isUnpinnedPipInstall`
# in ossf/scorecard sets `hasWheel` on the suffix alone. `--no-deps` does not change
# that verdict for a non-editable install; only the wheel does. Nothing about what
# reaches the image changes, and /tmp/wheel stays in the discarded builder stage.
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements/pip.txt \
    && pip install --no-cache-dir --require-hashes -r /tmp/requirements/runtime-all.txt \
    && pip wheel --no-cache-dir --no-deps --wheel-dir /tmp/wheel . \
    && pip install --no-cache-dir --no-deps /tmp/wheel/*.whl

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134 AS runtime

# Container-baseline-1 expectations:
# - non-root user
# - no shell-as-PID-1
# - no extra capabilities
# - no writable system paths
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Debian security updates published after the pinned base image was built. The digest is
# still the pin -- this only applies what `Debian-Security` has for it, and measured on
# 2026-09-09 that is exactly one package: `libpcre2-8-0` 10.42-1 -> 10.42-1+deb12u1, the
# five `libpcre2` advisories open on this repository. They are the ones the pip advisories
# are not: `pip` is uninstalled below and never reaches the published image, while
# `libpcre2` is a system library that ships in it.
#
# `upgrade` rather than `--only-upgrade libpcre2-8-0`, and the simulation is why: a full
# upgrade of this base moves that one package and nothing else, so naming the package buys
# no smaller change and needs an edit the next time Debian publishes. `upgrade` never
# installs or removes a package, so the image contents stay the set the Dockerfile chose.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Create the non-root user. Fixed uid/gid keeps adopter mounts predictable.
RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --home /home/appuser --shell /usr/sbin/nologin appuser \
    && mkdir -p /home/appuser \
    && chown -R appuser:appuser /home/appuser

# Copy the venv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# No package installer ships in the runtime image. Two pips were in every published
# image: the base image's 25.0.1 at /usr/local (six advisories as of 2026-09-09, the six
# `pip` alerts open on this repository -- not the five `libpcre2` ones, which the apt
# upgrade above answers) and the venv's own. The venv's pip is not clean either: pip
# vendors msgpack and setuptools under pip/_vendor and, since 26.x, ships a CycloneDX BOM
# that lets Trivy see them -- so an image with ANY pip carries whatever those vendored
# copies are missing. The kit never invokes pip at runtime; every mention of it in src/ is
# remediation text shown to the operator. The system python is addressed by absolute
# path because PATH already prefers the venv.
#
# Both this and the apt upgrade are held in place by
# tests/infrastructure/test_the_runtime_stage_keeps_the_base_image_cves_out.py. Neither is
# covered by the alert list: these CVEs are reported against the base image, so deleting
# either command reintroduces them into the published image without moving one alert.
RUN /usr/local/bin/python3 -m pip uninstall --yes pip \
    && /opt/venv/bin/python -m pip uninstall --yes pip \
    && rm -rf /root/.cache/pip

# Drop privileges before declaring the entrypoint. WORKDIR /work is the
# canonical mount point for the adopter's repository.
#
# The chown is what makes the documented commands work as a non-root user. `WORKDIR`
# creates the directory as root, and every command in docs/container-image.md writes its
# report under it, so without this the image cannot write to its own working directory:
# `docker run --rm <image> evaluate --target /work --output-dir out` ends in
# "Cannot write to --output-dir 'out': Permission denied" and exit 2. It went unnoticed
# because a Docker Desktop bind mount is world-writable, so the failure only appears where
# the docs say to use this image -- Linux, CI, a Kubernetes Job.
WORKDIR /work
RUN chown appuser:appuser /work
USER appuser

# OCI labels for image discoverability and SBOM / provenance tooling.
LABEL org.opencontainers.image.title="oss-policy-kit" \
      org.opencontainers.image.description="Evaluate clone-visible OSS repository governance plus GitHub Actions / Azure Pipelines / AWS CodeBuild signals against composable policy profiles." \
      org.opencontainers.image.url="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit" \
      org.opencontainers.image.source="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Lucas Henrique Grifoni"

# Image self-test. The runtime container is one-shot (CLI), so this primarily
# documents a working entrypoint and satisfies HEALTHCHECK posture checks
# (Trivy DS-0026 / KICS). A long interval keeps it effectively free.
HEALTHCHECK --interval=1h --timeout=10s --retries=1 \
    CMD ["python", "-m", "oss_policy_kit", "--version"]

ENTRYPOINT ["python", "-m", "oss_policy_kit"]
CMD ["--help"]
