"""Terraform / OpenTofu HCL parsing and indexing primitives.

Soft dependency on ``python-hcl2``: importable without the extra installed
so the rest of the kit keeps working; ``oss-policy-kit scan-iac`` checks
availability at run time and writes ``status: not_available`` evidence
when the parser is missing (mirrors the Semgrep adapter contract).
"""

from .hcl_loader import HclLoadError, hcl2_available, load_hcl_file
from .scanner import (
    DEFAULT_TIMEOUT_SECONDS,
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    IacFinding,
    IacScanOutcome,
    all_rule_ids,
    render_evidence_payload,
    run_scan,
    write_evidence,
)
from .tf_resource_index import TfBlock, TfResourceIndex, build_index

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "EVIDENCE_FILENAME",
    "EVIDENCE_SCHEMA_VERSION",
    "HclLoadError",
    "IacFinding",
    "IacScanOutcome",
    "TfBlock",
    "TfResourceIndex",
    "all_rule_ids",
    "build_index",
    "hcl2_available",
    "load_hcl_file",
    "render_evidence_payload",
    "run_scan",
    "write_evidence",
]
