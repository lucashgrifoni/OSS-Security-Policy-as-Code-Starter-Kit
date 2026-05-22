"""Branch-coverage gaps for the Terraform IaC scanner helpers."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.iac import scanner as tf
from oss_policy_kit.infrastructure.iac.tf_resource_index import TfResourceIndex


def _index(raw: dict[Path, dict]) -> TfResourceIndex:
    return TfResourceIndex(raw_files=raw)


# --------------------------------------------------------------------------- #
# _normalize_target outside repo (lines 144-145)
# --------------------------------------------------------------------------- #


def test_normalize_target_outside_repo(tmp_path: Path) -> None:
    other = tmp_path.parent / "main.tf"
    assert tf._normalize_target(tmp_path / "repo", other).endswith("main.tf")


# --------------------------------------------------------------------------- #
# _is_truthy (line 175 region — all branches)
# --------------------------------------------------------------------------- #


def test_is_truthy_branches() -> None:
    assert tf._is_truthy(True) is True
    assert tf._is_truthy("yes") is True
    assert tf._is_truthy(1) is True
    assert tf._is_truthy(0) is False
    assert tf._is_truthy(None) is False
    assert tf._is_truthy(["x"]) is False


# --------------------------------------------------------------------------- #
# _tf_ingress_open_mgmt_port (lines 285, 293-294, 296)
# --------------------------------------------------------------------------- #


def test_tf_ingress_open_mgmt_port_scalar_cidr() -> None:
    out = tf._tf_ingress_open_mgmt_port({"cidr_blocks": "0.0.0.0/0", "from_port": 22, "to_port": 22})
    assert out == (22, 22, 22)


def test_tf_ingress_open_mgmt_port_unparseable_ports() -> None:
    assert tf._tf_ingress_open_mgmt_port({"cidr_blocks": ["0.0.0.0/0"], "from_port": "abc"}) is None


def test_tf_ingress_open_mgmt_port_missing_ports() -> None:
    assert tf._tf_ingress_open_mgmt_port({"cidr_blocks": ["0.0.0.0/0"]}) is None


# --------------------------------------------------------------------------- #
# _policy_statements / _stmt_has_wildcard_principal (lines 781, 788)
# --------------------------------------------------------------------------- #


def test_policy_statements_single_dict_wrapped() -> None:
    out = tf._policy_statements({"statement": {"actions": ["*"]}})
    assert out == [{"actions": ["*"]}]


def test_stmt_has_wildcard_principal_single_dict_wrapped() -> None:
    assert tf._stmt_has_wildcard_principal({"principals": {"identifiers": ["*"]}}) is True
    assert tf._stmt_has_wildcard_principal({"principals": {"identifiers": ["arn:x"]}}) is False


# --------------------------------------------------------------------------- #
# _unpinned_providers / _local_backend_names (lines 624, 674)
# --------------------------------------------------------------------------- #


def test_unpinned_providers_single_dict_no_version() -> None:
    assert tf._unpinned_providers({"aws": {}}) == ["aws"]


def test_local_backend_names_single_dict() -> None:
    assert tf._local_backend_names({"backend": {"local": {}}}) == ["local"]


# --------------------------------------------------------------------------- #
# _iter_data_entries / _iter_iam_policy_docs (lines 758, 760, 772)
# --------------------------------------------------------------------------- #


def test_iter_data_entries_dict_wrapped_and_skip_nonlist() -> None:
    idx = _index(
        {
            Path("a.tf"): {"data": {"aws_iam_policy_document": {"d": {}}}},  # dict -> wrapped
            Path("b.tf"): {"data": 123},  # non-list -> skipped
        }
    )
    entries = list(tf._iter_data_entries(idx))
    assert len(entries) == 1


def test_iter_iam_policy_docs_skips_non_dict_section() -> None:
    idx = _index({Path("a.tf"): {"data": [{"aws_iam_policy_document": "not-a-dict"}]}})
    assert list(tf._iter_iam_policy_docs(idx)) == []


def test_iter_iam_policy_docs_yields_docs() -> None:
    idx = _index({Path("a.tf"): {"data": [{"aws_iam_policy_document": {"d": {"statement": []}}}]}})
    out = list(tf._iter_iam_policy_docs(idx))
    assert out and out[0][1] == "d"
