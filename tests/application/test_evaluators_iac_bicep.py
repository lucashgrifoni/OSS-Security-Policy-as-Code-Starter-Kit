"""Tests for the v5.7.0 ``IAC-BICEP-*`` Bicep controls."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_iac_bicep import IAC_BICEP_RULES
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.iac.bicep.scanner import (
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    all_rule_ids,
    render_evidence_payload,
    run_scan,
    write_evidence,
)


def test_all_iac_bicep_controls_present_in_catalog() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for rule_id, _ in IAC_BICEP_RULES:
        assert rule_id in catalog, f"Catalog missing {rule_id}."
        spec = catalog[rule_id]
        assert spec.lifecycle == "experimental"
        assert spec.assurance == "evidence-backed"
        assert spec.category == "iac"


def test_all_iac_bicep_controls_have_evaluators() -> None:
    for rule_id, _ in IAC_BICEP_RULES:
        assert rule_id in EVALUATOR_REGISTRY


def test_iac_bicep_baseline_1_profile_loads() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "iac-bicep-baseline-1")
    assert spec.id == "iac-bicep-baseline-1"
    bicep_in_profile = {c for c in spec.control_ids if c.startswith("IAC-BICEP-")}
    assert bicep_in_profile == set(all_rule_ids())


def _scan_and_dump(tmp_path: Path, body: str, *, filename: str = "main.bicep") -> dict:
    (tmp_path / filename).write_text(body, encoding="utf-8")
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    return payload


def test_scan_emits_versioned_evidence(tmp_path: Path) -> None:
    body = (
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'safe'\n"
        "  location: 'eastus'\n"
        "  sku: { name: 'Standard_LRS' }\n"
        "  kind: 'StorageV2'\n"
        "  properties: { allowBlobPublicAccess: false }\n"
        "}\n"
    )
    payload = _scan_and_dump(tmp_path, body)
    assert payload["schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert payload["status"] == "ok"
    assert payload["attested_by"] == "oss-policy-kit scan-bicep"


def test_iac_bicep_001_public_storage(tmp_path: Path) -> None:
    body = (
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'public'\n"
        "  location: 'eastus'\n"
        "  sku: { name: 'Standard_LRS' }\n"
        "  kind: 'StorageV2'\n"
        "  properties: { allowBlobPublicAccess: true }\n"
        "}\n"
    )
    payload = _scan_and_dump(tmp_path, body)
    assert payload["findings_by_rule"]["IAC-BICEP-001"] >= 1


def test_iac_bicep_002_open_management_port(tmp_path: Path) -> None:
    body = (
        "resource rule 'Microsoft.Network/networkSecurityGroups/securityRules@2023-04-01' = {\n"
        "  name: 'allow-ssh'\n"
        "  properties: {\n"
        "    access: 'Allow'\n"
        "    direction: 'Inbound'\n"
        "    sourceAddressPrefix: '*'\n"
        "    destinationPortRange: '22'\n"
        "    protocol: 'Tcp'\n"
        "    priority: 100\n"
        "  }\n"
        "}\n"
    )
    payload = _scan_and_dump(tmp_path, body)
    assert payload["findings_by_rule"]["IAC-BICEP-002"] >= 1


def test_iac_bicep_003_owner_role_assignment(tmp_path: Path) -> None:
    body = (
        "resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n"
        "  name: guid('owner')\n"
        "  properties: {\n"
        "    principalId: 'pid'\n"
        "    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', "
        "'8e3af657-a8ff-443c-a75c-2fe8c4bcb635')\n"
        "  }\n"
        "}\n"
    )
    payload = _scan_and_dump(tmp_path, body)
    assert payload["findings_by_rule"]["IAC-BICEP-003"] >= 1


def test_iac_bicep_006_public_ip(tmp_path: Path) -> None:
    body = (
        "resource pip 'Microsoft.Network/publicIPAddresses@2023-04-01' = {\n"
        "  name: 'public-ip'\n"
        "  location: 'eastus'\n"
        "  sku: { name: 'Standard' }\n"
        "  properties: { publicIPAllocationMethod: 'Static' }\n"
        "}\n"
    )
    payload = _scan_and_dump(tmp_path, body)
    assert payload["findings_by_rule"]["IAC-BICEP-006"] >= 1


def test_bicep_evaluator_returns_manual_review_when_evidence_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    for rid in all_rule_ids():
        eval_fn = EVALUATOR_REGISTRY[rid]
        out = eval_fn(SimpleNamespace(repo_root=tmp_path))
        assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_bicep_evaluator_returns_not_applicable_when_no_bicep_files(tmp_path: Path) -> None:
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    assert payload["files_scanned"] == []
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    for rid in all_rule_ids():
        eval_fn = EVALUATOR_REGISTRY[rid]
        out = eval_fn(SimpleNamespace(repo_root=tmp_path))
        assert out.status is ControlStatus.NOT_APPLICABLE
