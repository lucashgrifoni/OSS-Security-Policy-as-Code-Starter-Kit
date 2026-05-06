"""Locks fixture purity for ``examples/hardened-repo/.oss-policy-kit/evidence/``.

The bundled hardened fixture is the only public demo that hard-gate / release-hardening profiles
have to contrast against. If a maintainer accidentally re-runs ``scaffold-evidence --force`` on
that fixture without re-filling the placeholders, the synthetic fixture would silently regress
into ``not-evaluated`` for every evidence-backed control on Azure/AWS L3 — and the
``test_hardened_repo_cloud_profiles`` invariants would still pass because they tolerate
``self-attested`` rows.

This test catches that regression directly: it validates that no JSON file under the fixture's
evidence directory contains any of the placeholder tokens that ``evidence_placeholders`` knows
how to detect, and that no file is shaped like a scaffold template digest. Complements the
fixture README under ``examples/hardened-repo/.oss-policy-kit/evidence/README.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.evidence_placeholders import (
    has_placeholder_values,
    is_placeholder_digest,
)


def _iter_evidence_files() -> list[Path]:
    ev_dir = EXAMPLE_HARDENED / ".oss-policy-kit" / "evidence"
    return sorted(p for p in ev_dir.glob("*.json"))


def test_hardened_repo_evidence_files_have_no_placeholder_tokens() -> None:
    """Every evidence JSON in the hardened fixture must be free of scaffold placeholders.

    A maintainer who re-runs ``scaffold-evidence --force`` on the fixture without re-filling the
    templates would replace real values with ``REPLACE_ME`` / ``YOUR_*`` tokens. That would
    silently demote evidence-backed controls to ``not-evaluated`` and invalidate the demo
    counts captured in ``test_hardened_repo_cloud_profiles``.
    """

    files = _iter_evidence_files()
    assert files, "Hardened fixture must ship at least one evidence JSON"
    failures: list[tuple[str, list[str]]] = []
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        hits = has_placeholder_values(data)
        if hits:
            failures.append((f.name, hits))
    assert not failures, f"Placeholder tokens found in fixture evidence: {failures}"


def test_hardened_repo_evidence_files_have_no_template_digests() -> None:
    """Any 64-char hex value in the fixture must be a real-shape SHA-256, not a scaffold digest.

    ``evidence_placeholders.is_placeholder_digest`` flags low-entropy / repeating digests that
    were copied from ``evidence_scaffold`` templates. The fixture is allowed to use synthetic
    digests, but they must look real (not ``"a"*64`` or ``"0"*64``).
    """

    files = _iter_evidence_files()
    suspicious: list[tuple[str, str]] = []

    def walk(path: str, node: object) -> None:
        if isinstance(node, str) and is_placeholder_digest(node):
            suspicious.append((path, node))
        elif isinstance(node, dict):
            for k, v in node.items():
                walk(f"{path}.{k}" if path else str(k), v)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(f"{path}[{i}]", v)

    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        walk("", data)

    assert not suspicious, f"Template-shaped digests in hardened fixture: {suspicious}"


def test_hardened_repo_evidence_files_carry_attested_metadata() -> None:
    """Every fixture evidence file must declare ``schema_version`` and an ``attested_by`` /
    ``schema_version`` pair so evaluators know the document is self-attested (not raw JSON).

    The fixture is intentionally **not** API-collected; the README explains that. But it still
    has to carry the minimum metadata the evaluators consume (``schema_version`` + at least one
    of ``attested_by`` / ``attested_at``) so the projection treats it as ``user_supplied``
    rather than ``static_clone``.
    """

    files = _iter_evidence_files()
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        assert isinstance(data, dict), f"{f.name}: must be a JSON object"
        assert isinstance(data.get("schema_version"), str) and data["schema_version"].strip(), (
            f"{f.name}: missing schema_version"
        )
        # Require at least one of the attestation hints.
        attested_by = data.get("attested_by")
        attested_at = data.get("attested_at")
        assert (isinstance(attested_by, str) and attested_by.strip()) or (
            isinstance(attested_at, str) and attested_at.strip()
        ), f"{f.name}: missing attested_by / attested_at metadata"
