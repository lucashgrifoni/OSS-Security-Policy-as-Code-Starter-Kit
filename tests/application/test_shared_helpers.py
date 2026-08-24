"""Direct unit tests for pure helpers in ``application.evaluators._shared``.

These helpers are exercised indirectly by the per-control evaluator tests, but
many edge branches (malformed JSON, type guards, locale phrasing, freshness
windows) are easier to pin down — and keep pinned — with focused unit tests.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import _shared as s
from oss_policy_kit.domain.models import ControlStatus, utc_now
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.gitlab_ci_parser import GitLabCiAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, profile_id: str = "github-level-3", **over: object) -> s.EvalContext:
    kwargs: dict[str, object] = {
        "repo_root": tmp_path,
        "profile_id": profile_id,
        "workflows": WorkflowAnalysis(),
        "azure_pipelines": AzurePipelineAnalysis(),
        "aws_ci": AwsCiAnalysis(),
        "scorecard": None,
    }
    kwargs.update(over)
    return s.EvalContext(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Azure API-support completeness
# --------------------------------------------------------------------------- #


def test_azure_bp_api_support_complete() -> None:
    assert s._azure_branch_policies_api_support_complete({"posture_support": {"policies_api_reachable": True}})
    assert not s._azure_branch_policies_api_support_complete({"posture_support": {"policies_api_reachable": False}})
    assert not s._azure_branch_policies_api_support_complete({"posture_support": "x"})
    assert not s._azure_branch_policies_api_support_complete({})


def test_azure_gov_api_support_complete() -> None:
    full = dict.fromkeys(s._AZURE_GOV_SUPPORT_KEYS, True)
    assert s._azure_pipeline_governance_api_support_complete({"posture_support": full})
    partial = dict.fromkeys(list(s._AZURE_GOV_SUPPORT_KEYS)[:1], True)
    assert not s._azure_pipeline_governance_api_support_complete({"posture_support": partial})
    assert not s._azure_pipeline_governance_api_support_complete({"posture_support": 7})


# --------------------------------------------------------------------------- #
# SECURITY.md heuristics
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("marker", ["placeholder", "TODO", "tbd", "update this file with a working contact"])
def test_placeholder_security_contact_true(marker: str) -> None:
    assert s._has_placeholder_security_contact(f"Contact: {marker}")


def test_placeholder_security_contact_false() -> None:
    assert not s._has_placeholder_security_contact("Email security@example.com to report.")


@pytest.mark.parametrize(
    "text",
    [
        "Email security@example.com",
        "mailto:team@example.com",
        "We support private vulnerability reporting via GitHub.",
        "Use HackerOne to report.",
        "GitHub Security Advisories — please report privately first.",
        "Responsible disclosure: contact us privately.",
        "Canal privado para reporte.",
        "Divulgação responsável: use o canal privado.",
    ],
)
def test_gov_disc_013_signals_true(text: str) -> None:
    assert s._gov_disc_013_private_reporting_signals(text.lower())


def test_gov_disc_013_signals_false() -> None:
    assert not s._gov_disc_013_private_reporting_signals("open a public issue on the tracker")
    # GHSA wording alone (no private context) must not pass.
    assert not s._gov_disc_013_private_reporting_signals("we use github security advisories")


# --------------------------------------------------------------------------- #
# Workflow text heuristics
# --------------------------------------------------------------------------- #


def test_github_workflow_release_or_deploy() -> None:
    assert s._github_workflow_raw_suggests_release_or_deploy("on:\n  release:\n    types: [published]\n")
    assert s._github_workflow_raw_suggests_release_or_deploy(
        "on:\n  push:\n    branches: [main]\njobs:\n  x:\n    steps:\n      - run: npm publish\n"
    )
    assert not s._github_workflow_raw_suggests_release_or_deploy("on:\n  pull_request:\n")


def test_workflow_long_lived_cloud_secret() -> None:
    assert s._workflow_text_has_long_lived_cloud_secret("key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}")
    assert s._workflow_text_has_long_lived_cloud_secret("token: ${{ secrets.MY_CLIENT_SECRET }}")
    assert not s._workflow_text_has_long_lived_cloud_secret("token: ${{ secrets.GITHUB_TOKEN }}")


def test_reusable_workflow_ref_has_full_sha() -> None:
    sha = "a" * 40
    assert s._reusable_workflow_ref_has_full_sha(f"./.github/workflows/x.yml@{sha}")
    assert not s._reusable_workflow_ref_has_full_sha("org/repo/.github/workflows/x.yml@v1")
    assert not s._reusable_workflow_ref_has_full_sha("./.github/workflows/x.yml")  # no @
    # Non-reusable (action ref) is out of scope -> treated as fine.
    assert s._reusable_workflow_ref_has_full_sha("actions/checkout@v4")


# --------------------------------------------------------------------------- #
# Structured workflow uses iteration
# --------------------------------------------------------------------------- #


def test_iter_workflow_jobs_and_uses_locations() -> None:
    doc = {
        "jobs": {
            "build": {
                "uses": "./.github/workflows/reusable.yml@abc",
                "steps": [
                    {"name": "checkout", "uses": "actions/checkout@v4"},
                    {"uses": "actions/setup-python@v5"},
                    "not-a-dict",
                    {"run": "echo hi"},  # no uses
                ],
            },
            "broken": "not-a-dict",
        }
    }
    locs = s._iter_structured_workflow_uses_with_location(doc)
    labels = {label for _job, label, _uses in locs}
    assert "job" in labels
    assert "checkout" in labels
    assert "step[1]" in labels
    uses = s._iter_structured_workflow_uses_strings(doc)
    assert "actions/checkout@v4" in uses
    reusable = s._reusable_workflow_uses_from_strings(uses)
    assert reusable == ["./.github/workflows/reusable.yml@abc"]


def test_iter_workflow_jobs_non_dict_jobs() -> None:
    assert list(s._iter_workflow_jobs({"jobs": "x"})) == []


def test_job_uses_locations_steps_not_list() -> None:
    out = s._job_uses_locations("j", {"uses": "a/b@v1", "steps": "nope"})
    assert out == [("j", "job", "a/b@v1")]


# --------------------------------------------------------------------------- #
# Dependency / lock detection
# --------------------------------------------------------------------------- #


def test_python_lock_or_pins(tmp_path: Path) -> None:
    assert not s._python_lock_or_pins(tmp_path)
    (tmp_path / "poetry.lock").write_text("x", encoding="utf-8")
    assert s._python_lock_or_pins(tmp_path)


def test_python_lock_alt_lockfiles(tmp_path: Path) -> None:
    (tmp_path / "requirements.lock").write_text("x", encoding="utf-8")
    assert s._python_lock_or_pins(tmp_path)


def test_python_lock_pinned_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    assert s._python_lock_or_pins(tmp_path)
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    assert not s._python_lock_or_pins(tmp_path)


# --------------------------------------------------------------------------- #
# Evidence date parsing
# --------------------------------------------------------------------------- #


def test_parse_evidence_date_variants() -> None:
    assert s._parse_evidence_date("2026-05-21") == date(2026, 5, 21)
    assert s._parse_evidence_date("2026-05-21T10:11:12Z") == date(2026, 5, 21)
    assert s._parse_evidence_date("not-a-date") is None
    assert s._parse_evidence_date("short") is None


# --------------------------------------------------------------------------- #
# Digest string extraction
# --------------------------------------------------------------------------- #


def test_sbom_artifact_digest_strings() -> None:
    data = {"artifact": {"digest_sha256": "a"}, "sbom": {"digest_sha256": "b"}, "junk": 1}
    assert s._sbom_artifact_digest_strings(data) == ["a", "b"]
    assert s._sbom_artifact_digest_strings({"artifact": {"digest_sha256": 5}}) == []


def test_provenance_artifact_digest_strings() -> None:
    data = {"artifact": {"digest_sha256": "a"}, "attestation": {"digest_sha256": "b"}}
    assert s._provenance_artifact_digest_strings(data) == ["a", "b"]
    assert s._provenance_artifact_digest_strings({}) == []


# --------------------------------------------------------------------------- #
# SBOM format / version detection + BSI scope
# --------------------------------------------------------------------------- #


def test_detect_sbom_format() -> None:
    assert s._detect_sbom_format('{"bomFormat": "CycloneDX"}') == "cyclonedx"
    assert s._detect_sbom_format("SPDXVersion: SPDX-2.3") == "spdx"
    assert s._detect_sbom_format("nothing here") is None


def test_detect_spdx_version() -> None:
    assert s._detect_spdx_version('"specVersion": "3.0.1" spdx.dev/spec/3') == ("spdx", "3.0.1")
    assert s._detect_spdx_version("spdx.dev/spec/3/foo") == ("spdx", "3.0")
    assert s._detect_spdx_version('{"spdxVersion": "SPDX-2.3"}') == ("spdx", "2.3")
    assert s._detect_spdx_version("SPDXVersion: SPDX-2.2") == ("spdx", "2.2")
    assert s._detect_spdx_version("no spdx here") is None


def test_detect_sbom_format_and_version() -> None:
    assert s._detect_sbom_format_and_version('{"bomFormat":"CycloneDX","specVersion":"1.6"}') == ("cyclonedx", "1.6")
    assert s._detect_sbom_format_and_version('{"bomFormat":"CycloneDX"}') == ("cyclonedx", None)
    assert s._detect_sbom_format_and_version('{"spdxVersion":"SPDX-2.3"}') == ("spdx", "2.3")
    assert s._detect_sbom_format_and_version("plain text") == (None, None)


def test_bsi_v2_1_in_scope() -> None:
    assert s._bsi_v2_1_in_scope("cyclonedx", "1.6")
    assert not s._bsi_v2_1_in_scope("cyclonedx", "1.4")
    assert not s._bsi_v2_1_in_scope("cyclonedx", None)
    assert not s._bsi_v2_1_in_scope("cyclonedx", "bad.version.x")
    assert s._bsi_v2_1_in_scope("spdx", "3.0")
    assert not s._bsi_v2_1_in_scope("spdx", "2.3")
    assert not s._bsi_v2_1_in_scope("other", "1.0")


def test_validate_bsi_out_of_scope_returns_none() -> None:
    assert s._validate_bsi_tr_03183_v2_1("{}", "spdx", "2.3") is None


def test_validate_bsi_in_scope() -> None:
    content = '{"purl":"pkg:pypi/x","hashes":[],"licenses":[],"supplier":"acme"}'
    res = s._validate_bsi_tr_03183_v2_1(content, "cyclonedx", "1.6")
    assert res is not None
    assert res["identifiers_present"]
    assert res["hashes_present"]
    assert res["licenses_present"]
    assert res["supplier_present"]
    assert res["vulnerability_data_separated"] is True


def test_validate_bsi_with_embedded_vulns() -> None:
    content = '{"purl":"pkg:x","vulnerabilities": [ {"id":"CVE-1"} ]}'
    res = s._validate_bsi_tr_03183_v2_1(content, "spdx", "3.0")
    assert res is not None
    assert res["vulnerability_data_separated"] is False


def test_find_sbom_files(tmp_path: Path) -> None:
    (tmp_path / "sbom.json").write_text("{}", encoding="utf-8")
    (tmp_path / "bom.xml").write_text("<bom/>", encoding="utf-8")
    found = s._find_sbom_files(tmp_path)
    names = {p.name for p in found}
    assert "sbom.json" in names
    assert "bom.xml" in names


# --------------------------------------------------------------------------- #
# Signal-match helpers
# --------------------------------------------------------------------------- #


def test_audit_stream_signal_match_yaml(tmp_path: Path) -> None:
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "audit-log-streaming.yml").write_text("on: schedule\n", encoding="utf-8")
    assert s._audit_stream_signal_match(tmp_path) is not None


def test_audit_stream_signal_match_doc_keyword(tmp_path: Path) -> None:
    (tmp_path / "RELEASE_OPERATIONS.md").write_text("We enable audit log streaming.\n", encoding="utf-8")
    assert s._audit_stream_signal_match(tmp_path) is not None


def test_audit_stream_signal_no_match(tmp_path: Path) -> None:
    (tmp_path / "RELEASE_OPERATIONS.md").write_text("nothing relevant\n", encoding="utf-8")
    assert s._audit_stream_signal_match(tmp_path) is None


def test_disclosure_sla_signal_match(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text("We will respond within 48 hours.\n", encoding="utf-8")
    out = s._disclosure_sla_signal_match(tmp_path)
    assert out is not None
    assert out[1] in s._DISCLOSURE_SLA_KEYWORDS


def test_disclosure_sla_signal_no_match(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text("Contact us.\n", encoding="utf-8")
    assert s._disclosure_sla_signal_match(tmp_path) is None


def test_release_archive_signal_match(tmp_path: Path) -> None:
    (tmp_path / "RELEASE_ARCHIVAL.md").write_text("retention policy: 7 years\n", encoding="utf-8")
    assert s._release_archive_signal_match(tmp_path) is not None
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "release-readiness.md").write_text("unrelated\n", encoding="utf-8")
    # RELEASE_ARCHIVAL.md still matches; remove it to test the doc no-keyword path.


def test_release_archive_signal_no_match(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "release-archival.md").write_text("nothing here\n", encoding="utf-8")
    assert s._release_archive_signal_match(tmp_path) is None


# --------------------------------------------------------------------------- #
# Provenance lookup order + freshness
# --------------------------------------------------------------------------- #


def test_prov_verify_lookup_order() -> None:
    assert s._prov_verify_lookup_order("github-level-3")[0][0].startswith("github-")
    assert s._prov_verify_lookup_order("azure-level-2")[0][0].startswith("azure-")
    assert s._prov_verify_lookup_order("aws-level-2")[0][0].startswith("aws-")
    assert s._prov_verify_lookup_order("other") == s._PROV_VERIFY_FILES


def test_verification_freshness_status() -> None:
    now = utc_now()
    assert s._verification_freshness_status((now - timedelta(days=1)).isoformat(), max_age_days=90) == "fresh"
    assert s._verification_freshness_status((now - timedelta(days=200)).isoformat(), max_age_days=90) == "stale"
    assert s._verification_freshness_status((now + timedelta(days=5)).isoformat(), max_age_days=90) == "future"
    assert s._verification_freshness_status("garbage", max_age_days=90) == "unparseable"
    # Naive timestamp gets UTC attached, still fresh.
    assert s._verification_freshness_status(now.replace(tzinfo=None).isoformat(), max_age_days=90) == "fresh"


# --------------------------------------------------------------------------- #
# Self-hosted runner classification
# --------------------------------------------------------------------------- #


def test_classify_self_hosted_runner() -> None:
    assert s._classify_self_hosted_runner("runs-on: [self-hosted, ephemeral]") == (True, True)
    assert s._classify_self_hosted_runner("runs-on: self-hosted") == (True, False)
    assert s._classify_self_hosted_runner("runs-on: ubuntu-latest") == (False, False)


def test_workflow_text_unreadable(tmp_path: Path) -> None:
    assert s._workflow_text(tmp_path / "missing.yml") == ""


def test_self_hosted_workflow_paths(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "a.yml").write_text("runs-on: [self-hosted, ephemeral]\n", encoding="utf-8")
    (wf / "b.yaml").write_text("runs-on: ubuntu-latest\n", encoding="utf-8")
    (wf / "empty.yml").write_text("", encoding="utf-8")
    all_self, ephemeral = s._self_hosted_workflow_paths(tmp_path)
    assert len(all_self) == 1
    assert len(ephemeral) == 1


def test_self_hosted_workflow_paths_no_dir(tmp_path: Path) -> None:
    assert s._self_hosted_workflow_paths(tmp_path) == ([], [])


# --------------------------------------------------------------------------- #
# JSON depth scanning + SARIF parsing
# --------------------------------------------------------------------------- #


def test_advance_json_string() -> None:
    assert s._advance_json_string("a", escaped=True) == (True, False)
    assert s._advance_json_string("\\", escaped=False) == (True, True)
    assert s._advance_json_string('"', escaped=False) == (False, False)
    assert s._advance_json_string("x", escaped=False) == (True, False)


def test_max_json_nesting_depth() -> None:
    assert s._max_json_nesting_depth('{"a": [1, [2, {"b": 3}]]}') == 4
    # Brackets inside strings are ignored.
    assert s._max_json_nesting_depth('{"a": "[[[[["}') == 1


def test_load_sarif_runs_ok(tmp_path: Path) -> None:
    p = tmp_path / "x.sarif.json"
    p.write_text(json.dumps({"runs": [{"results": []}]}), encoding="utf-8")
    runs, err = s._load_sarif_runs(p)
    assert err is None
    assert isinstance(runs, list)
    assert len(runs) == 1


def test_load_sarif_runs_missing(tmp_path: Path) -> None:
    runs, err = s._load_sarif_runs(tmp_path / "nope.json")
    assert runs is None
    assert err
    assert "Could not read" in err


def test_load_sarif_runs_bad_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    runs, err = s._load_sarif_runs(p)
    assert runs is None
    assert "Could not parse" in (err or "")


def test_load_sarif_runs_too_deep(tmp_path: Path) -> None:
    p = tmp_path / "deep.json"
    p.write_text("[" * 250 + "]" * 250, encoding="utf-8")
    runs, err = s._load_sarif_runs(p)
    assert runs is None
    assert "too deeply nested" in (err or "")


def test_load_sarif_runs_no_runs_key(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")
    runs, err = s._load_sarif_runs(p)
    assert runs is None
    assert "missing top-level 'runs'" in (err or "")


def test_load_sarif_runs_runs_not_array(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"runs": "x"}), encoding="utf-8")
    runs, err = s._load_sarif_runs(p)
    assert runs is None
    assert "not an array" in (err or "")


def test_sarif_rule_levels() -> None:
    run = {"tool": {"driver": {"rules": [{"id": "R1", "defaultConfiguration": {"level": "error"}}, {"no": "id"}, "x"]}}}
    assert s._sarif_rule_levels(run) == {"R1": "error"}
    assert s._sarif_rule_levels({"tool": {"driver": {"rules": "x"}}}) == {}


def test_count_sarif_run() -> None:
    counts = {"error": 0, "warning": 0, "note": 0, "none": 0}
    run = {
        "results": [
            {"level": "error"},
            {"ruleId": "R1"},  # no level -> rule_levels lookup
            {"level": "bogus"},  # unknown -> warning
            "not-a-dict",
        ]
    }
    s._count_sarif_run(run, {"R1": "note"}, counts)
    assert counts == {"error": 1, "warning": 1, "note": 1, "none": 0}


def test_count_sarif_run_results_not_list() -> None:
    counts = {"warning": 0}
    s._count_sarif_run({"results": "x"}, {}, counts)
    assert counts == {"warning": 0}


def test_iter_sarif_results() -> None:
    doc = {"runs": [{"results": [{"a": 1}, "x"]}, "bad", {"results": "x"}]}
    out = list(s._iter_sarif_results(doc))
    assert out == [{"a": 1}]
    assert list(s._iter_sarif_results({"runs": "x"})) == []


def test_parse_zizmor_severity_properties(tmp_path: Path) -> None:
    p = tmp_path / "z.sarif.json"
    doc = {
        "runs": [
            {
                "results": [
                    {"properties": {"security_severity_level": "High"}},
                    {"properties": {"security_severity_level": "Bizarre"}},  # -> unknown
                    {"properties": {"no_sev": True}},
                    {"properties": "not-a-dict"},
                ]
            }
        ]
    }
    p.write_text(json.dumps(doc), encoding="utf-8")
    counts, err = s._parse_zizmor_severity_properties(p)
    assert err is None
    assert counts is not None
    assert counts["high"] == 1
    assert counts["unknown"] == 1


def test_parse_zizmor_bad_paths(tmp_path: Path) -> None:
    assert s._parse_zizmor_severity_properties(tmp_path / "missing.json")[0] is None
    bad = tmp_path / "bad.json"
    bad.write_text("{x", encoding="utf-8")
    assert s._parse_zizmor_severity_properties(bad)[0] is None
    notobj = tmp_path / "arr.json"
    notobj.write_text("[]", encoding="utf-8")
    assert s._parse_zizmor_severity_properties(notobj)[0] is None
    notarr = tmp_path / "nr.json"
    notarr.write_text(json.dumps({"runs": "x"}), encoding="utf-8")
    assert s._parse_zizmor_severity_properties(notarr)[0] is None


# --------------------------------------------------------------------------- #
# EPSS / KEV classification
# --------------------------------------------------------------------------- #


def test_safe_float() -> None:
    assert s._safe_float(None) is None
    assert s._safe_float("3.5") == 3.5
    assert s._safe_float("nope") is None
    assert s._safe_float(2) == 2.0


def test_classify_epss_kev_result() -> None:
    kev, high = s._classify_epss_kev_result(
        {"ruleId": "CVE-1", "properties": {"kev": True, "epss_score": 0.9, "cvss_score": 8.0}}, 0.5, 7.0
    )
    assert kev == "CVE-1"
    assert high == "CVE-1"
    # kev as string + low epss
    kev2, high2 = s._classify_epss_kev_result({"properties": {"kev": "yes", "cve": "CVE-2", "epss": 0.1}}, 0.5, 7.0)
    assert kev2 == "CVE-2"
    assert high2 is None
    # non-dict / no props
    assert s._classify_epss_kev_result("x", 0.5, 7.0) == (None, None)
    assert s._classify_epss_kev_result({"properties": "x"}, 0.5, 7.0) == (None, None)


def test_scan_sarif_epss_kev(tmp_path: Path) -> None:
    p = tmp_path / "epss.sarif.json"
    doc = {
        "runs": [
            {
                "results": [
                    {"ruleId": "CVE-A", "properties": {"kev": True}},
                    {"ruleId": "CVE-B", "properties": {"epss_score": 0.95, "cvss_score": 9.0}},
                ]
            }
        ]
    }
    p.write_text(json.dumps(doc), encoding="utf-8")
    scan = s._scan_sarif_epss_kev(p)
    assert scan.error is None
    assert scan.kev == ["CVE-A"]
    assert scan.high_epss == ["CVE-B"]
    # The fields that let a caller tell "enrichment ran and found nothing" apart from
    # "there is no enrichment here" -- the distinction SCA-KEV-001 was missing.
    assert scan.saw_kev_property
    assert scan.saw_epss_property


def test_scan_sarif_epss_kev_errors(tmp_path: Path) -> None:
    assert s._scan_sarif_epss_kev(tmp_path / "missing.json")[2]
    bad = tmp_path / "b.json"
    bad.write_text("{x", encoding="utf-8")
    assert "parse" in (s._scan_sarif_epss_kev(bad)[2] or "")
    arr = tmp_path / "arr.json"
    arr.write_text("[]", encoding="utf-8")
    assert "not an object" in (s._scan_sarif_epss_kev(arr)[2] or "")


# --------------------------------------------------------------------------- #
# AI-agent text scanning + CODEOWNERS
# --------------------------------------------------------------------------- #


def test_read_lower(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    p.write_text("ABC", encoding="utf-8")
    assert s._read_lower(p) == "abc"
    assert s._read_lower(tmp_path / "missing.txt") == ""


def test_is_ai_agent_text_file(tmp_path: Path) -> None:
    good = tmp_path / "README.md"
    good.write_text("x", encoding="utf-8")
    assert s._is_ai_agent_text_file(good, tmp_path)
    skip = tmp_path / "node_modules" / "x.md"
    skip.parent.mkdir()
    skip.write_text("x", encoding="utf-8")
    assert not s._is_ai_agent_text_file(skip, tmp_path)


def test_find_any_text_hint(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("This uses an LLM system prompt.\n", encoding="utf-8")
    matched = s._find_any_text_hint(tmp_path, ("system prompt",))
    assert matched


def test_find_prompt_registry(tmp_path: Path) -> None:
    assert s._find_prompt_registry(tmp_path) is None
    (tmp_path / "prompts").mkdir()
    assert s._find_prompt_registry(tmp_path) == tmp_path / "prompts"


def test_codeowners_text_and_coverage(tmp_path: Path) -> None:
    assert s._codeowners_text(tmp_path) is None
    (tmp_path / "CODEOWNERS").write_text("/prompts/ @team\n", encoding="utf-8")
    entry = s._codeowners_text(tmp_path)
    assert entry is not None
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    owner, covered = s._codeowners_covers_prompt_path(tmp_path, prompts)  # type: ignore[misc]
    assert covered is True


def test_codeowners_covers_prompt_path_none(tmp_path: Path) -> None:
    (tmp_path / "prompts").mkdir()
    assert s._codeowners_covers_prompt_path(tmp_path, tmp_path / "prompts") is None


# --------------------------------------------------------------------------- #
# Publish workflows + first-existing
# --------------------------------------------------------------------------- #


def test_publish_workflows(tmp_path: Path) -> None:
    a = tmp_path / "a.yml"
    a.write_text("steps:\n  - run: twine upload dist/*\n", encoding="utf-8")
    b = tmp_path / "b.yml"
    b.write_text("steps:\n  - run: echo hi\n", encoding="utf-8")
    assert s._publish_workflows([a, b]) == [a]


def test_read_first_existing(tmp_path: Path) -> None:
    assert s._read_first_existing(tmp_path, ("X.md", "Y.md")) == (None, "")
    (tmp_path / "Y.md").write_text("Hello\n", encoding="utf-8")
    p, text = s._read_first_existing(tmp_path, ("X.md", "Y.md"))
    assert p is not None
    assert text == "hello\n"


# --------------------------------------------------------------------------- #
# AI system doc / Annex IV (ctx-based)
# --------------------------------------------------------------------------- #


def _write_ai_doc(tmp_path: Path, payload: object) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ai-system-technical-doc.json").write_text(json.dumps(payload), encoding="utf-8")


def test_load_ai_system_doc(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    assert s._load_ai_system_doc(ctx)[0] is None
    _write_ai_doc(tmp_path, {"a": 1})
    assert s._load_ai_system_doc(ctx)[0] == {"a": 1}


def test_load_ai_system_doc_non_dict(tmp_path: Path) -> None:
    _write_ai_doc(tmp_path, [1, 2])
    assert s._load_ai_system_doc(_ctx(tmp_path))[0] is None


def test_annex_iv_section(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    # No evidence -> manual review.
    out = s._annex_iv_section(ctx, "system_overview", "system overview", "do it")
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    # Populated field -> PASS.
    _write_ai_doc(tmp_path, {"system_overview": "An overview."})
    out = s._annex_iv_section(ctx, "system_overview", "system overview", "do it")
    assert out.status == ControlStatus.PASS
    # Empty field -> FAIL.
    _write_ai_doc(tmp_path, {"system_overview": ""})
    out = s._annex_iv_section(ctx, "system_overview", "system overview", "do it")
    assert out.status == ControlStatus.FAIL


# --------------------------------------------------------------------------- #
# MCP / agentic detection
# --------------------------------------------------------------------------- #


def test_mcp_applicable(tmp_path: Path) -> None:
    applicable, found = s._mcp_applicable(tmp_path)
    assert not applicable
    assert found == []
    (tmp_path / "mcp.json").write_text("{}", encoding="utf-8")
    applicable, found = s._mcp_applicable(tmp_path)
    assert applicable
    assert found


def test_mcp_applicable_via_dependency(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("dependencies = ['fastmcp']\n", encoding="utf-8")
    applicable, _found = s._mcp_applicable(tmp_path)
    assert applicable


def test_mcp_applicable_via_dotmcp_dir(tmp_path: Path) -> None:
    (tmp_path / ".mcp").mkdir()
    applicable, found = s._mcp_applicable(tmp_path)
    assert applicable
    assert any(p.name == ".mcp" for p in found)


def test_mcp_na() -> None:
    out = s._mcp_na("injection")
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_mcp_text_signal(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text("We validate every MCP tool call.\n", encoding="utf-8")
    assert s._mcp_text_signal(tmp_path, [], ("validate",)) is not None
    assert s._mcp_text_signal(tmp_path, [], ("nonexistent-needle",)) is None


def test_mcp_text_signal_skips_dirs(tmp_path: Path) -> None:
    (tmp_path / ".mcp").mkdir()
    # Directory in `found` is skipped without error.
    assert s._mcp_text_signal(tmp_path, [tmp_path / ".mcp"], ("x",)) is None


def test_agentic_applicable(tmp_path: Path) -> None:
    applicable, found = s._agentic_applicable(tmp_path)
    assert not applicable
    assert found == []
    (tmp_path / "requirements.txt").write_text("langchain==0.1.0\n", encoding="utf-8")
    applicable, _found = s._agentic_applicable(tmp_path)
    assert applicable


def test_agentic_applicable_via_path_hint(tmp_path: Path) -> None:
    (tmp_path / "agents").mkdir()
    applicable, found = s._agentic_applicable(tmp_path)
    assert applicable
    assert found


def test_agentic_na() -> None:
    assert s._agentic_na("ASI-001").status == ControlStatus.NOT_APPLICABLE


def test_agentic_signal(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Our agent enforces tool authorization.\n", encoding="utf-8")
    assert s._agentic_signal(tmp_path, [], ("authorization",)) is not None
    assert s._agentic_signal(tmp_path, [], ("missing-needle",)) is None


# --------------------------------------------------------------------------- #
# GitLab pipeline scanning
# --------------------------------------------------------------------------- #


def test_scan_gitlab_pipelines(tmp_path: Path) -> None:
    pipe = tmp_path / ".gitlab-ci.yml"
    pipe.write_text("sast:\n  stage: test\n", encoding="utf-8")
    ctx = _ctx(tmp_path, gitlab_ci=GitLabCiAnalysis(pipeline_paths=[pipe]))
    assert s._scan_gitlab_pipelines(ctx, ("sast",)) == [pipe]
    assert s._scan_gitlab_pipelines(ctx, ("nonexistent",)) == []


def test_gl_no_pipeline_response() -> None:
    out = s._gl_no_pipeline_response("GL-001", "add a pipeline")
    assert out.status == ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# README section + LLM SDK scanning
# --------------------------------------------------------------------------- #


def test_scan_readme_for_section(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text("## AI Security Considerations\nfoo\n", encoding="utf-8")
    assert s._scan_readme_for_section(tmp_path, s._AI_SECURITY_HEADINGS) is not None
    assert s._scan_readme_for_section(tmp_path, ("nonexistent heading",)) is None


def test_scan_for_llm_sdks(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("anthropic==0.30.0\n", encoding="utf-8")
    assert s._scan_for_llm_sdks(tmp_path) is not None
    assert s._scan_for_llm_sdks(tmp_path / "empty") is None
