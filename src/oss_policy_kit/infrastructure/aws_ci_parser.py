"""Discover and scan AWS CodeBuild buildspec and CodePipeline-shaped files in a clone."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

_AKIA_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_SECRETISH_KEY = re.compile(r"(password|secret|token|api[_-]?key)", re.IGNORECASE)


@dataclass(slots=True)
class AwsCiAnalysis:
    """Static signals from committed CodeBuild/CodePipeline configuration."""

    buildspec_paths: list[Path] = field(default_factory=list)
    codepipeline_paths: list[Path] = field(default_factory=list)
    #: Subset of ``codepipeline_paths`` whose JSON/YAML export includes stages or artifact store(s).
    codepipeline_valid_export_paths: list[Path] = field(default_factory=list)
    #: Subset of valid exports whose ``pipeline.roleArn`` is a plausible IAM service role ARN.
    codepipeline_committed_iam_role_paths: list[Path] = field(default_factory=list)
    parse_errors: list[tuple[Path, str]] = field(default_factory=list)
    parameter_store_signal_paths: list[Path] = field(default_factory=list)
    secrets_manager_signal_paths: list[Path] = field(default_factory=list)
    inline_secret_risk_paths: list[Path] = field(default_factory=list)
    security_scan_signal_paths: list[Path] = field(default_factory=list)
    dependency_audit_signal_paths: list[Path] = field(default_factory=list)
    sbom_signal_paths: list[Path] = field(default_factory=list)
    provenance_signal_paths: list[Path] = field(default_factory=list)


def _candidate_buildspec_paths(repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    for name in ("buildspec.yml", "buildspec.yaml"):
        p = repo_root / name
        if p.is_file():
            paths.append(p)
    paths.extend(repo_root.glob(".aws/buildspec*.yml"))
    paths.extend(repo_root.glob(".aws/buildspec*.yaml"))
    return sorted({p for p in paths if p.is_file()})


def _candidate_codepipeline_paths(repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    for ext in ("*.json", "*.yaml", "*.yml"):
        paths.extend((repo_root / "pipelines" / "aws").glob(f"codepipeline{ext}"))
    return sorted({p for p in paths if p.is_file()})


def load_committed_codepipeline_document(path: Path) -> dict[str, Any] | None:
    """Return the ``pipeline`` object from a committed export, or ``None`` when unusable."""

    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        else:
            data = load_yaml_file(path)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    pipe = data.get("pipeline")
    return pipe if isinstance(pipe, dict) else None


def committed_codepipeline_export_is_minimal(path: Path) -> tuple[bool, str]:
    """True when the export includes stages or artifact store configuration (not a name-only stub)."""

    pipe = load_committed_codepipeline_document(path)
    if pipe is None:
        return False, "pipeline root must be an object (use GetPipeline-style JSON, not name-only stubs)."
    stages = pipe.get("stages")
    if isinstance(stages, list) and len(stages) >= 1:
        return True, ""
    if pipe.get("artifactStore") or pipe.get("artifactStores"):
        return True, ""
    return False, "pipeline export must include at least one stage or an artifact store block."


def _scan_buildspec_raw_non_env(path: Path, raw: str, raw_lower: str, result: AwsCiAnalysis) -> None:
    """Heuristics that are not replaced by structured YAML env parsing."""

    if _AKIA_PATTERN.search(raw) or "aws_secret_access_key" in raw_lower:
        result.inline_secret_risk_paths.append(path)
    if "-----begin" in raw_lower and "private key-----" in raw_lower:
        result.inline_secret_risk_paths.append(path)

    scan_tokens = (
        "trivy",
        "semgrep",
        "bandit",
        "snyk",
        "codeql",
        "gitleaks",
        "trufflehog",
        "inspector-sbomgen",
        "amazon-inspector",
    )
    if any(t in raw_lower for t in scan_tokens):
        result.security_scan_signal_paths.append(path)

    sca_tokens = (
        "pip-audit",
        "npm audit",
        "yarn audit",
        "pnpm audit",
        "osv-scanner",
        "dependency-check",
        "bundler-audit",
    )
    if any(t in raw_lower for t in sca_tokens):
        result.dependency_audit_signal_paths.append(path)

    sbom_tokens = ("cyclonedx", "syft", "spdx", "sbom")
    if any(t in raw_lower for t in sbom_tokens):
        result.sbom_signal_paths.append(path)

    prov_tokens = (
        "cosign",
        "sigstore",
        "slsa",
        "attestation",
        "provenance",
    )
    if any(t in raw_lower for t in prov_tokens):
        result.provenance_signal_paths.append(path)


def _raw_env_fallback(path: Path, raw_lower: str, result: AwsCiAnalysis) -> None:
    """When YAML cannot be parsed, fall back to substring hints for managed secret blocks."""

    if "parameter-store" in raw_lower or "parameter_store" in raw_lower:
        result.parameter_store_signal_paths.append(path)
    if "secrets-manager" in raw_lower or "secretsmanager" in raw_lower or "secrets_manager" in raw_lower:
        result.secrets_manager_signal_paths.append(path)


def _plaintext_env_variables_risk(values: dict[str, Any], path: Path, result: AwsCiAnalysis) -> None:
    for key, val in values.items():
        if not isinstance(val, str):
            continue
        s = val.strip()
        if not s:
            continue
        if _AKIA_PATTERN.search(s):
            result.inline_secret_risk_paths.append(path)
            continue
        if len(s) >= 64 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
            result.inline_secret_risk_paths.append(path)
            continue
        if _SECRETISH_KEY.search(str(key)) and len(s) > 12:
            result.inline_secret_risk_paths.append(path)


def _record_env_block_signals(env_block: dict[str, Any], path: Path, result: AwsCiAnalysis) -> None:
    """Record parameter-store / secrets-manager / risky plaintext-variable signals from one ``env`` block."""

    ps = env_block.get("parameter-store") or env_block.get("parameter_store")
    sm = env_block.get("secrets-manager") or env_block.get("secrets_manager")
    if isinstance(ps, dict) and ps:
        result.parameter_store_signal_paths.append(path)
    if isinstance(sm, dict) and sm:
        result.secrets_manager_signal_paths.append(path)
    vars_block = env_block.get("variables")
    if isinstance(vars_block, dict) and vars_block:
        _plaintext_env_variables_risk(vars_block, path, result)


def _merge_structured_env_signals(data: Any, path: Path, result: AwsCiAnalysis, *, depth: int = 0) -> None:
    """Walk YAML and record structured env.parameter-store / env.secrets-manager / risky env.variables."""

    if depth > 40:
        return
    if isinstance(data, dict):
        env_block = data.get("env")
        if isinstance(env_block, dict):
            _record_env_block_signals(env_block, path, result)
        for child in data.values():
            _merge_structured_env_signals(child, path, result, depth=depth + 1)
    elif isinstance(data, list):
        for item in data:
            _merge_structured_env_signals(item, path, result, depth=depth + 1)


def analyze_aws_ci(repo_root: Path) -> AwsCiAnalysis:
    """Conservative scan of buildspec and committed CodePipeline exports."""

    result = AwsCiAnalysis()
    result.buildspec_paths = _candidate_buildspec_paths(repo_root)
    result.codepipeline_paths = _candidate_codepipeline_paths(repo_root)

    for path in result.buildspec_paths:
        raw = path.read_text(encoding="utf-8", errors="replace")
        raw_lower = raw.lower()
        _scan_buildspec_raw_non_env(path, raw, raw_lower, result)
        try:
            data = load_yaml_file(path)
            _merge_structured_env_signals(data, path, result)
        except Exception as exc:  # noqa: BLE001
            result.parse_errors.append((path, str(exc)))
            _raw_env_fallback(path, raw_lower, result)

    for path in result.codepipeline_paths:
        _scan_codepipeline_export(path, result)

    _dedupe_aws_ci_signals(result)
    return result


def _scan_codepipeline_export(path: Path, result: AwsCiAnalysis) -> None:
    """Validate one committed CodePipeline export and record valid-export / IAM-role signals."""

    try:
        if path.suffix.lower() == ".json":
            json.loads(path.read_text(encoding="utf-8", errors="replace"))
        else:
            load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001 - record parse failure and skip this export
        result.parse_errors.append((path, str(exc)))
        return
    ok, _msg = committed_codepipeline_export_is_minimal(path)
    if not ok:
        return
    result.codepipeline_valid_export_paths.append(path)
    pipe = load_committed_codepipeline_document(path)
    if isinstance(pipe, dict):
        role = str(pipe.get("roleArn", "")).strip()
        if role.startswith("arn:aws:iam::"):
            result.codepipeline_committed_iam_role_paths.append(path)


def _dedupe_aws_ci_signals(result: AwsCiAnalysis) -> None:
    """Deduplicate (by resolved path) every accumulated AWS CI signal list, in place."""

    def _dedupe(paths: list[Path]) -> list[Path]:
        return sorted({p.resolve() for p in paths})

    result.parameter_store_signal_paths = _dedupe(result.parameter_store_signal_paths)
    result.secrets_manager_signal_paths = _dedupe(result.secrets_manager_signal_paths)
    result.inline_secret_risk_paths = _dedupe(result.inline_secret_risk_paths)
    result.security_scan_signal_paths = _dedupe(result.security_scan_signal_paths)
    result.dependency_audit_signal_paths = _dedupe(result.dependency_audit_signal_paths)
    result.sbom_signal_paths = _dedupe(result.sbom_signal_paths)
    result.provenance_signal_paths = _dedupe(result.provenance_signal_paths)
    result.codepipeline_valid_export_paths = _dedupe(result.codepipeline_valid_export_paths)
    result.codepipeline_committed_iam_role_paths = _dedupe(result.codepipeline_committed_iam_role_paths)
