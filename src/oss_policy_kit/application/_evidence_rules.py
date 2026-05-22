"""Shared helpers for the scanner-evidence rule evaluators (IaC/K8s families).

Each ``_make_*_evaluator`` reads the same evidence shape (``files_scanned``,
``findings_by_rule``, ``findings``). Centralizing the list/count/sample plumbing
keeps every per-rule ``_eval`` closure flat (low cognitive complexity) while the
PASS/FAIL/NA messages stay in their family module.
"""

from __future__ import annotations

from typing import Any


def files_scanned_list(data: dict[str, Any]) -> list[Any]:
    """Return the evidence ``files_scanned`` list (empty when absent or malformed)."""

    fs = data.get("files_scanned") or []
    return fs if isinstance(fs, list) else []


def rule_finding_count(data: dict[str, Any], rule_id: str) -> int:
    """Return the count of findings recorded for ``rule_id`` in ``findings_by_rule``."""

    by_rule = data.get("findings_by_rule") or {}
    if not isinstance(by_rule, dict):
        return 0
    return int(by_rule.get(rule_id, 0) or 0)


def sample_finding_files(data: dict[str, Any], rule_id: str, limit: int = 3) -> list[str]:
    """Return up to ``limit`` distinct source files that triggered ``rule_id``."""

    out: list[str] = []
    for f in data.get("findings", []) or []:
        if isinstance(f, dict) and f.get("rule_id") == rule_id:
            file_ = f.get("file")
            if isinstance(file_, str) and file_ and file_ not in out:
                out.append(file_)
        if len(out) >= limit:
            break
    return out
