"""Kubernetes manifest scanner subsystem (v5.6).

Walks ``*.yaml`` / ``*.yml`` files under a clone, parses every YAML
document, indexes the manifests by ``(api_version, kind, namespace,
name)``, and runs the bundled rule pack. Helm template files are
detected via the ``{{ ... }}`` Jinja-like markers and skipped with a
``manual-review-required`` diagnostic so they are not silently treated
as Kubernetes manifests.
"""

from oss_policy_kit.infrastructure.k8s.scanner import (
    DEFAULT_INCLUDE_GLOBS,
    DEFAULT_TIMEOUT_SECONDS,
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    K8sFinding,
    K8sScanOutcome,
    all_rule_ids,
    render_evidence_payload,
    run_scan,
    write_evidence,
)

__all__ = [
    "DEFAULT_INCLUDE_GLOBS",
    "DEFAULT_TIMEOUT_SECONDS",
    "EVIDENCE_FILENAME",
    "EVIDENCE_SCHEMA_VERSION",
    "K8sFinding",
    "K8sScanOutcome",
    "all_rule_ids",
    "render_evidence_payload",
    "run_scan",
    "write_evidence",
]
