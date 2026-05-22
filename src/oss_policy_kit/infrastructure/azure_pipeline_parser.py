"""Parse Azure Pipelines YAML for static security and governance signals."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oss_policy_kit.infrastructure.yaml_io import load_yaml_file


@dataclass(slots=True)
class AzurePipelineAnalysis:
    """Aggregated static signals from Azure Pipelines YAML files."""

    pipeline_paths: list[Path] = field(default_factory=list)
    parse_errors: list[tuple[Path, str]] = field(default_factory=list)
    pr_validation_paths: list[Path] = field(default_factory=list)
    persist_credentials_true_paths: list[Path] = field(default_factory=list)
    missing_clean_checkout_paths: list[Path] = field(default_factory=list)
    extends_template_paths: list[Path] = field(default_factory=list)
    security_scan_signal_paths: list[Path] = field(default_factory=list)
    dependency_audit_signal_paths: list[Path] = field(default_factory=list)
    sbom_signal_paths: list[Path] = field(default_factory=list)
    azure_deploy_signal_paths: list[Path] = field(default_factory=list)
    workload_identity_signal_paths: list[Path] = field(default_factory=list)


def _candidate_pipeline_paths(repo_root: Path) -> list[Path]:
    """Return conservative Azure Pipelines file candidates."""

    patterns = (
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        "pipelines/azure/*.yml",
        "pipelines/azure/*.yaml",
        ".azure-pipelines/*.yml",
        ".azure-pipelines/*.yaml",
    )
    paths: list[Path] = []
    for pattern in patterns:
        paths.extend(repo_root.glob(pattern))
    return sorted({p for p in paths if p.is_file()})


def _flatten_steps(node: Any) -> list[dict[str, Any]]:
    """Collect step-like mappings from nested stage/job structure."""

    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        steps = node.get("steps")
        if isinstance(steps, list):
            out.extend(s for s in steps if isinstance(s, dict))
        for value in node.values():
            out.extend(_flatten_steps(value))
    elif isinstance(node, list):
        for item in node:
            out.extend(_flatten_steps(item))
    return out


def _has_pr_trigger(data: dict[str, Any]) -> bool:
    return data.get("pr") is not None


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


# (result attribute, keyword tokens) for raw-text Azure pipeline signal detection.
_AZURE_RAW_SIGNAL_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "security_scan_signal_paths",
        ("microsoftsecuritydevops", "credscan", "trivy", "semgrep", "bandit", "snyk", "codeql"),
    ),
    (
        "dependency_audit_signal_paths",
        ("pip-audit", "safety check", "npm audit", "osv-scanner", "dependency-check", "trivy fs"),
    ),
    ("sbom_signal_paths", ("sbom", "cyclonedx", "syft", "spdx")),
    (
        "azure_deploy_signal_paths",
        ("azurecli@2", "azurepowershell@5", "armdeployment", "az deployment", "kubectl", "helm"),
    ),
    ("workload_identity_signal_paths", ("workloadidentityfederation", "federated token", "idtoken")),
)

_AZURE_DEDUPE_LISTS: tuple[str, ...] = (
    "pr_validation_paths",
    "persist_credentials_true_paths",
    "missing_clean_checkout_paths",
    "extends_template_paths",
    "security_scan_signal_paths",
    "dependency_audit_signal_paths",
    "sbom_signal_paths",
    "azure_deploy_signal_paths",
    "workload_identity_signal_paths",
)


def _scan_azure_raw_signals(path: Path, raw_lower: str, result: AzurePipelineAnalysis) -> None:
    """Append ``path`` to each signal list whose keyword tokens appear in the raw pipeline text."""

    for attr, tokens in _AZURE_RAW_SIGNAL_GROUPS:
        if _contains_any(raw_lower, tokens):
            getattr(result, attr).append(path)


def _scan_azure_checkout_steps(data: dict[str, Any], path: Path, result: AzurePipelineAnalysis) -> None:
    """Flag checkout steps that persist credentials or omit ``clean: true``."""

    for step in _flatten_steps(data):
        checkout = step.get("checkout")
        if checkout != "self" and not (isinstance(checkout, str) and checkout.strip()):
            continue
        if str(step.get("persistCredentials")).lower() == "true":
            result.persist_credentials_true_paths.append(path)
        if str(step.get("clean")).lower() != "true":
            result.missing_clean_checkout_paths.append(path)


def _scan_azure_parsed(data: Any, path: Path, result: AzurePipelineAnalysis) -> None:
    """Record parsed-pipeline signals (PR trigger, extends template, checkout posture)."""

    if not isinstance(data, dict):
        result.parse_errors.append((path, "pipeline root must be a mapping"))
        return
    if _has_pr_trigger(data):
        result.pr_validation_paths.append(path)
    if "extends" in data:
        result.extends_template_paths.append(path)
    _scan_azure_checkout_steps(data, path, result)


def analyze_azure_pipelines(repo_root: Path) -> AzurePipelineAnalysis:
    """Scan known Azure Pipelines files for static posture signals."""

    result = AzurePipelineAnalysis()
    for path in _candidate_pipeline_paths(repo_root):
        result.pipeline_paths.append(path)
        raw_lower = path.read_text(encoding="utf-8", errors="replace").lower()
        _scan_azure_raw_signals(path, raw_lower, result)
        try:
            data: Any = load_yaml_file(path)
        except Exception as exc:  # noqa: BLE001 - record parse failure and continue
            result.parse_errors.append((path, str(exc)))
            continue
        _scan_azure_parsed(data, path, result)

    # de-duplicate while preserving deterministic order
    for name in _AZURE_DEDUPE_LISTS:
        setattr(result, name, sorted(set(getattr(result, name))))
    return result
