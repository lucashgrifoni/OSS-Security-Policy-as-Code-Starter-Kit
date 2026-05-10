"""Evaluators for the v5.6 ``CONT-RUNTIME-*`` and ``CONT-SIGN-001`` controls.

These controls extend the existing ``CONT-IMAGE-001/002/003`` family
(digest pinning, non-root USER, image scanning) with seven additional
clone-visible Dockerfile / workflow signals shipped in the new
``container-baseline-1`` advisory profile.

Detection is intentionally conservative:

- ``NOT_APPLICABLE`` when there is no Dockerfile in the clone (the rule
  cannot say anything useful);
- ``PASS`` when at least one Dockerfile passes the rule and **none**
  fails it;
- ``FAIL`` when one or more Dockerfiles violate the rule, with a sample
  of the offending files in the reason string.

``CONT-SIGN-001`` (image signing) reads ``EvalContext.workflows`` instead
of Dockerfiles because cosign / ``actions/attest-build-provenance`` /
``gh attestation`` calls live in CI YAML.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

_DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+(.+?)$", re.MULTILINE | re.IGNORECASE)
_HEALTHCHECK_RE = re.compile(r"^\s*HEALTHCHECK\b", re.MULTILINE | re.IGNORECASE)
_CURL_BASH_RE = re.compile(
    r"(curl|wget)[^|\n]+\|\s*(bash|sh|zsh|ksh)\b",
    re.IGNORECASE,
)
_APT_INSTALL_RE = re.compile(
    r"\bapt(?:-get)?\s+install\b",
    re.IGNORECASE,
)
_APT_NO_RECOMMENDS_RE = re.compile(r"--no-install-recommends", re.IGNORECASE)
_APT_LIST_CLEANUP_RE = re.compile(r"rm\s+-rf\s+/var/lib/apt/lists/\*", re.IGNORECASE)
_APT_CLEAN_RE = re.compile(r"apt(?:-get)?\s+clean", re.IGNORECASE)
_APT_PIN_RE = re.compile(r"\b[A-Za-z0-9.+\-]+=[A-Za-z0-9:.~+\-]+", re.IGNORECASE)
_APK_ADD_RE = re.compile(r"\bapk\s+add\b", re.IGNORECASE)
_APK_PIN_RE = re.compile(r"\b[A-Za-z0-9.+\-]+=[A-Za-z0-9:.~+\-]+", re.IGNORECASE)


def _find_dockerfiles(repo: Path) -> list[Path]:
    """Return up to 20 Dockerfile candidates (mirrors the legacy CONT-IMAGE-* helper)."""

    results: list[Path] = []
    seen: set[Path] = set()
    for name in ("Dockerfile", "dockerfile"):
        p = repo / name
        if p.is_file():
            results.append(p)
            seen.add(p.resolve())
    try:
        for p in repo.rglob("Dockerfile"):
            r = p.resolve()
            if r not in seen and p.is_file():
                results.append(p)
                seen.add(r)
        for p in repo.rglob("*.dockerfile"):
            r = p.resolve()
            if r not in seen and p.is_file():
                results.append(p)
                seen.add(r)
    except OSError:
        pass
    return results[:20]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _na_no_dockerfile() -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.NOT_APPLICABLE,
        reason="No Dockerfile detected in the repository.",
        remediation="Not applicable until a Dockerfile is added.",
        evidence_sources=[],
        confidence="high",
    )


# ---------------------------------------------------------------------------
# CONT-RUNTIME-001 — multi-stage build present
# ---------------------------------------------------------------------------


def eval_cont_runtime_001(ctx: Any) -> EvalOutcome:
    """CONT-RUNTIME-001: at least one Dockerfile uses a multi-stage build."""

    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return _na_no_dockerfile()
    single_stage: list[Path] = []
    for df in dockerfiles:
        text = _read_text(df)
        froms = _DOCKER_FROM_RE.findall(text)
        if len(froms) >= 2 or any(re.search(r"\sAS\s+\S+", f, re.IGNORECASE) for f in froms):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Multi-stage build detected in {df.name}.",
                remediation="Keep the final stage minimal and copy only release artefacts from build stages.",
                evidence_sources=[str(df.resolve())],
                confidence="medium",
            )
        single_stage.append(df)
    sample = ", ".join(p.name for p in single_stage[:3])
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=f"No multi-stage Dockerfile found (single-stage: {sample}).",
        remediation=(
            "Convert the build to a multi-stage Dockerfile: a 'builder' stage that compiles, then a "
            "minimal final stage that only COPYs the release artefact. Reduces image size and CVE surface."
        ),
        evidence_sources=[str(p.resolve()) for p in single_stage],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# CONT-RUNTIME-002 — HEALTHCHECK declared
# ---------------------------------------------------------------------------


def eval_cont_runtime_002(ctx: Any) -> EvalOutcome:
    """CONT-RUNTIME-002: at least one Dockerfile declares a HEALTHCHECK instruction."""

    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return _na_no_dockerfile()
    missing: list[Path] = []
    for df in dockerfiles:
        if _HEALTHCHECK_RE.search(_read_text(df)):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"HEALTHCHECK instruction found in {df.name}.",
                remediation="Verify the healthcheck exercises a meaningful endpoint, not just `exit 0`.",
                evidence_sources=[str(df.resolve())],
                confidence="medium",
            )
        missing.append(df)
    sample = ", ".join(p.name for p in missing[:3])
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=f"No HEALTHCHECK declared in any Dockerfile ({sample}).",
        remediation=(
            "Add a HEALTHCHECK instruction so orchestrators (Kubernetes, ECS, Compose) "
            "can detect a stuck process and restart the container."
        ),
        evidence_sources=[str(p.resolve()) for p in missing],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# CONT-RUNTIME-003 — no curl-bash / wget-sh patterns
# ---------------------------------------------------------------------------


def eval_cont_runtime_003(ctx: Any) -> EvalOutcome:
    """CONT-RUNTIME-003: Dockerfile RUN instructions do not pipe network downloads to a shell."""

    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return _na_no_dockerfile()
    offenders: list[Path] = []
    for df in dockerfiles:
        if _CURL_BASH_RE.search(_read_text(df)):
            offenders.append(df)
    if not offenders:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"No curl|bash / wget|sh pattern detected across {len(dockerfiles)} Dockerfile(s).",
            remediation="Keep installer scripts pinned to a known SHA-256 and verify before exec.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles],
            confidence="medium",
        )
    sample = ", ".join(p.name for p in offenders[:3])
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=f"Dockerfile(s) pipe a download into a shell (curl|bash style): {sample}.",
        remediation=(
            "Download the script with curl, verify its SHA-256 against a pinned digest, then exec it. "
            "Or use a package manager / pre-built binary instead."
        ),
        evidence_sources=[str(p.resolve()) for p in offenders],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# CONT-RUNTIME-004 — .dockerignore present
# ---------------------------------------------------------------------------


def eval_cont_runtime_004(ctx: Any) -> EvalOutcome:
    """CONT-RUNTIME-004: a .dockerignore file is present so build context stays minimal."""

    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return _na_no_dockerfile()
    dockerignore = ctx.repo_root / ".dockerignore"
    if dockerignore.is_file() and dockerignore.stat().st_size > 0:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=".dockerignore is present at repository root.",
            remediation="Ensure secrets, .git/, node_modules/, .venv/ and similar paths are excluded.",
            evidence_sources=[str(dockerignore.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="Dockerfile(s) present but no .dockerignore at repository root.",
        remediation=(
            "Add a .dockerignore that excludes .git, node_modules, .venv, dist, build, .env, "
            "and any local credential / cache directories from the build context."
        ),
        evidence_sources=[str(p.resolve()) for p in dockerfiles],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# CONT-RUNTIME-005 — apt/apk hygiene (cleanup or --no-install-recommends)
# ---------------------------------------------------------------------------


def eval_cont_runtime_005(ctx: Any) -> EvalOutcome:
    """CONT-RUNTIME-005: apt-based Dockerfiles either skip recommends or clean caches."""

    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return _na_no_dockerfile()
    offenders: list[Path] = []
    apt_used = False
    for df in dockerfiles:
        text = _read_text(df)
        if not _APT_INSTALL_RE.search(text):
            continue
        apt_used = True
        if _APT_NO_RECOMMENDS_RE.search(text):
            continue
        if _APT_LIST_CLEANUP_RE.search(text) or _APT_CLEAN_RE.search(text):
            continue
        offenders.append(df)
    if not apt_used:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No apt-get install lines detected in any Dockerfile.",
            remediation="Not applicable when the base image does not use Debian/Ubuntu apt.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles],
            confidence="medium",
        )
    if not offenders:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="apt-get install lines either use --no-install-recommends or clean /var/lib/apt/lists.",
            remediation="Keep the apt cache cleanup line in the same RUN as the install.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles],
            confidence="medium",
        )
    sample = ", ".join(p.name for p in offenders[:3])
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=f"apt-get install without --no-install-recommends or cache cleanup in: {sample}.",
        remediation=(
            "Add `--no-install-recommends` to apt-get install AND clean caches in the same RUN: "
            "`rm -rf /var/lib/apt/lists/*` to keep image size + CVE surface low."
        ),
        evidence_sources=[str(p.resolve()) for p in offenders],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# CONT-RUNTIME-006 — package versions pinned (heuristic)
# ---------------------------------------------------------------------------


def eval_cont_runtime_006(ctx: Any) -> EvalOutcome:
    """CONT-RUNTIME-006: apt/apk install lines pin package versions (pkg=ver) when present."""

    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return _na_no_dockerfile()
    offenders: list[Path] = []
    relevant = False
    for df in dockerfiles:
        text = _read_text(df)
        for line in text.splitlines():
            line = line.strip()
            if not (_APT_INSTALL_RE.search(line) or _APK_ADD_RE.search(line)):
                continue
            relevant = True
            if not _APT_PIN_RE.search(line) and not _APK_PIN_RE.search(line):
                if df not in offenders:
                    offenders.append(df)
                break
    if not relevant:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No apt/apk install lines detected; nothing to pin.",
            remediation="Not applicable until the Dockerfile installs OS packages.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles],
            confidence="medium",
        )
    if not offenders:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="OS package installs pin versions explicitly (pkg=version).",
            remediation="Refresh pinned versions on a cadence so security patches still flow.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles],
            confidence="medium",
        )
    sample = ", ".join(p.name for p in offenders[:3])
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=f"Unpinned OS package install lines (pkg without =version): {sample}.",
        remediation=(
            "Pin OS packages explicitly: `apt-get install -y curl=7.88.1-10 ca-certificates=20230311` "
            "(or the apk equivalent). Combine with `--no-install-recommends`."
        ),
        evidence_sources=[str(p.resolve()) for p in offenders],
        confidence="low",
    )


# ---------------------------------------------------------------------------
# CONT-SIGN-001 — image-signing workflow signal
# ---------------------------------------------------------------------------

_COSIGN_TOKENS: tuple[str, ...] = (
    "cosign sign",
    "cosign-installer",
    "sigstore/cosign-installer",
    "actions/attest-build-provenance",
    "actions/attest-sbom",
    "gh attestation",
)


def eval_cont_sign_001(ctx: Any) -> EvalOutcome:
    """CONT-SIGN-001: at least one workflow signs container images via cosign / GH attestations."""

    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return _na_no_dockerfile()
    repo_root: Path = ctx.repo_root
    workflow_dirs = [
        repo_root / ".github" / "workflows",
        repo_root / ".gitlab-ci.yml",
        repo_root / ".azure-pipelines",
    ]
    candidates: list[Path] = []
    for wd in workflow_dirs:
        if wd.is_dir():
            for ext in ("*.yml", "*.yaml"):
                with contextlib.suppress(OSError):
                    candidates.extend(p for p in wd.rglob(ext) if p.is_file())
        elif wd.is_file():
            candidates.append(wd)
    for path in candidates[:60]:
        text = _read_text(path).lower()
        for token in _COSIGN_TOKENS:
            if token.lower() in text:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"Image signing token '{token}' found in {path.relative_to(repo_root).as_posix()}.",
                    remediation=(
                        "Verify the signing step actually runs on releases and that signatures are "
                        "published with the image (registry annotation or sigstore TUF root)."
                    ),
                    evidence_sources=[str(path.resolve())],
                    confidence="medium",
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No cosign / GitHub artifact attestation reference found in the workflows.",
        remediation=(
            "Add cosign signing (`sigstore/cosign-installer` + `cosign sign --yes <image>@<digest>`) or "
            "switch to `actions/attest-build-provenance` for OIDC-based signatures."
        ),
        evidence_sources=[str(p.resolve()) for p in dockerfiles],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


CONT_RULES: tuple[tuple[str, str, Callable[[Any], EvalOutcome]], ...] = (
    ("CONT-RUNTIME-001", "Multi-stage Dockerfile build", eval_cont_runtime_001),
    ("CONT-RUNTIME-002", "Dockerfile HEALTHCHECK declared", eval_cont_runtime_002),
    ("CONT-RUNTIME-003", "No curl|bash / wget|sh in Dockerfile RUN", eval_cont_runtime_003),
    ("CONT-RUNTIME-004", ".dockerignore present", eval_cont_runtime_004),
    ("CONT-RUNTIME-005", "apt-get hygiene (--no-install-recommends or cache cleanup)", eval_cont_runtime_005),
    ("CONT-RUNTIME-006", "OS package versions pinned in apt/apk install", eval_cont_runtime_006),
    ("CONT-SIGN-001", "Container image signed via cosign / GH attestations", eval_cont_sign_001),
)


def build_container_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for the v5.6 container hardening pack."""

    return {rid: fn for rid, _summary, fn in CONT_RULES}
