"""appsec-sast-sca-1: AppSec native bundle (SAST + SCA + secret-scan + dep-hygiene).

Locks the v5.4.0 promotion of SAST-SEMGREP-064 to ``stable`` and the
introduction of the first bundled profile to consume it. The intent is to
keep the gate honest: with no SAST evidence file, the SAST control must
return ``manual-review-required`` (not ``fail``), because the kit cannot
prove a SAST run from a clone alone.
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)


def test_appsec_sast_sca_1_profile_loads() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "appsec-sast-sca-1")
    assert spec.id == "appsec-sast-sca-1"
    # v5.9.0 (Fase 4): added 4 SARIF adapters (zizmor / poutine / OSV / gitleaks)
    # to the AppSec native bundle, taking the count from 11 to 15.
    # v6.0.0 Cycle 2 (PR-23): added SCA-KEV-001 + SCA-EPSS-001, taking it to 17.
    assert len(spec.control_ids) == 17


def test_appsec_sast_sca_1_includes_sast_semgrep_064() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "appsec-sast-sca-1")
    assert "SAST-SEMGREP-064" in set(spec.control_ids)


def test_appsec_sast_sca_1_includes_v59_sarif_adapters() -> None:
    """v5.9.0 (Fase 4) SARIF adapters are part of the AppSec native bundle."""

    spec = load_profile_by_id(bundled_kit_root(), "appsec-sast-sca-1")
    cids = set(spec.control_ids)
    for new_id in ("SAST-ZIZMOR-066", "SAST-POUTINE-067", "SAST-OSV-068", "SAST-GITLEAKS-069"):
        assert new_id in cids, f"appsec-sast-sca-1 should include {new_id} after v5.9.0"


def test_appsec_sast_sca_1_controls_all_resolve_in_catalog() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "appsec-sast-sca-1")
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for cid in spec.control_ids:
        assert cid in catalog, f"Control '{cid}' referenced by appsec-sast-sca-1 missing from catalog."


def test_sast_semgrep_064_is_manual_review_without_evidence(tmp_path: Path) -> None:
    """Without a populated sast-semgrep.json evidence file, SAST-SEMGREP-064
    must return manual-review-required so ``--fail-on fail`` does not block on
    a gap the kit cannot honestly verify from a clone alone."""

    # Minimal repo layout — no .oss-policy-kit/evidence/sast-semgrep.json.
    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")

    root = bundled_kit_root()
    spec = load_profile_by_id(root, "appsec-sast-sca-1")
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    report = evaluate_repository(tmp_path, spec, catalog, waiver_outcome=None, scorecard=None)
    statuses = {r.control_id: r.status.value for r in report.results}
    assert statuses.get("SAST-SEMGREP-064") == "manual-review-required"
