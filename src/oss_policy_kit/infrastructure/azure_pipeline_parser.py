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
        if "steps" in node and isinstance(node["steps"], list):
            for s in node["steps"]:
                if isinstance(s, dict):
                    out.append(s)
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


def analyze_azure_pipelines(repo_root: Path) -> AzurePipelineAnalysis:  # noqa: C901
    """Scan known Azure Pipelines files for static posture signals."""

    result = AzurePipelineAnalysis()
    for path in _candidate_pipeline_paths(repo_root):
        result.pipeline_paths.append(path)
        raw = path.read_text(encoding="utf-8", errors="replace")
        raw_lower = raw.lower()

        if _contains_any(
            raw_lower,
            (
                "microsoftsecuritydevops",
                "credscan",
                "trivy",
                "semgrep",
                "bandit",
                "snyk",
                "codeql",
            ),
        ):
            result.security_scan_signal_paths.append(path)

        if _contains_any(
            raw_lower,
            (
                "pip-audit",
                "safety check",
                "npm audit",
                "osv-scanner",
                "dependency-check",
                "trivy fs",
            ),
        ):
            result.dependency_audit_signal_paths.append(path)

        if _contains_any(
            raw_lower,
            (
                "sbom",
                "cyclonedx",
                "syft",
                "spdx",
            ),
        ):
            result.sbom_signal_paths.append(path)

        if _contains_any(
            raw_lower,
            (
                "azurecli@2",
                "azurepowershell@5",
                "armdeployment",
                "az deployment",
                "kubectl",
                "helm",
            ),
        ):
            result.azure_deploy_signal_paths.append(path)

        if _contains_any(
            raw_lower,
            (
                "workloadidentityfederation",
                "federated token",
                "idtoken",
            ),
        ):
            result.workload_identity_signal_paths.append(path)

        try:
            data: Any = load_yaml_file(path)
        except Exception as exc:  # noqa: BLE001
            result.parse_errors.append((path, str(exc)))
            continue

        if not isinstance(data, dict):
            result.parse_errors.append((path, "pipeline root must be a mapping"))
            continue

        if _has_pr_trigger(data):
            result.pr_validation_paths.append(path)

        if "extends" in data:
            result.extends_template_paths.append(path)

        for step in _flatten_steps(data):
            checkout = step.get("checkout")
            if checkout == "self" or (isinstance(checkout, str) and checkout.strip()):
                persist = step.get("persistCredentials")
                if str(persist).lower() == "true":
                    result.persist_credentials_true_paths.append(path)
                clean = step.get("clean")
                if str(clean).lower() != "true":
                    result.missing_clean_checkout_paths.append(path)

    # de-duplicate while preserving deterministic order
    unique_lists = (
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
    for name in unique_lists:
        items = getattr(result, name)
        setattr(result, name, sorted({p for p in items}))
    return result
