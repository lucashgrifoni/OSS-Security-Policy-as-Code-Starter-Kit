# Official container image for oss-policy-kit (v5.9.0+).
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
# - No build tools in the runtime image: `pip install` happens in the
#   builder stage so the runtime stays minimal.
#
# Example usage (adopter side):
#
#   docker build -t oss-policy-kit:5.9.0 .
#   docker run --rm -v "$(pwd):/work" -w /work oss-policy-kit:5.9.0 \
#     evaluate --target . --profile github-level-1 --summary-only
#
# A published image at ghcr.io/lucashgrifoni/oss-policy-kit is planned
# for v5.9.x (release engineering — separate from this Dockerfile).

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

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
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        build-essential \
        git \
    && rm -rf /var/lib/apt/lists/*

# Create the venv we will copy into the runtime image.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install the package. Pinning the exact version makes the image
# reproducible; CI can override with --build-arg KIT_VERSION=...
ARG KIT_VERSION=5.9.0
RUN pip install --upgrade pip \
    && pip install "oss-policy-kit[all]==${KIT_VERSION}"

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# Container-baseline-1 expectations:
# - non-root user
# - no shell-as-PID-1
# - no extra capabilities
# - no writable system paths
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create the non-root user. Fixed uid/gid keeps adopter mounts predictable.
RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --home /home/appuser --shell /usr/sbin/nologin appuser \
    && mkdir -p /home/appuser \
    && chown -R appuser:appuser /home/appuser

# Copy the venv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Drop privileges before declaring the entrypoint. WORKDIR /work is the
# canonical mount point for the adopter's repository.
WORKDIR /work
USER appuser

# OCI labels for image discoverability and SBOM / provenance tooling.
LABEL org.opencontainers.image.title="oss-policy-kit" \
      org.opencontainers.image.description="Evaluate clone-visible OSS repository governance plus GitHub Actions / Azure Pipelines / AWS CodeBuild signals against composable policy profiles." \
      org.opencontainers.image.url="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit" \
      org.opencontainers.image.source="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Lucas Henrique Grifoni"

ENTRYPOINT ["python", "-m", "oss_policy_kit"]
CMD ["--help"]
