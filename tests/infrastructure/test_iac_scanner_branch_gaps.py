"""Branch-coverage gaps for the Pulumi / Bicep / CloudFormation IaC scanners."""

from __future__ import annotations

import ast
from pathlib import Path

from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep
from oss_policy_kit.infrastructure.iac.bicep.scanner import BicepResource
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi
from oss_policy_kit.infrastructure.iac.pulumi.scanner import PulumiCall


def _call(src: str) -> ast.Call:
    """Return the first ast.Call in a one-expression source string."""
    return next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call))


def _pc(**kwargs) -> PulumiCall:
    return PulumiCall(
        resource_type="aws.ec2.SecurityGroup", resource_name="sg", kwargs=kwargs, source=Path("p.py"), line=1
    )


def _br(body: str, *, type_full: str = "Microsoft.Storage/storageAccounts@2023-01-01") -> BicepResource:
    return BicepResource(symbolic="r", type_full=type_full, body=body, source=Path("m.bicep"))


# --------------------------------------------------------------------------- #
# Pulumi AST helpers
# --------------------------------------------------------------------------- #


def test_pulumi_normalize_target_outside_repo(tmp_path: Path) -> None:
    other = tmp_path.parent / "elsewhere.py"
    assert pulumi._normalize_target(tmp_path / "repo", other).endswith("elsewhere.py")


def test_pulumi_attr_chain_impure_root_returns_none() -> None:
    # `(x()).attr` — chain root is a Call, not a Name.
    attr = ast.parse("(x()).attr").body[0].value  # type: ignore[attr-defined]
    assert pulumi._attr_chain(attr) is None


def test_pulumi_literal_kwargs_star_and_nonliteral() -> None:
    call = _call("f(**d, x=undefined_name)")
    out = pulumi._literal_kwargs(call)
    assert "d" not in out  # **d has kw.arg None and is skipped
    assert out["x"] is None  # non-literal -> None


def test_pulumi_first_string_positional_branches() -> None:
    assert pulumi._first_string_positional(_call("f()")) == ""
    assert pulumi._first_string_positional(_call("f(123)")) == ""
    assert pulumi._first_string_positional(_call("f('name')")) == "name"


def test_pulumi_file_imports_pulumi_importfrom() -> None:
    tree = ast.parse("from pulumi_aws import s3\n")
    assert pulumi._file_imports_pulumi(tree) is True


def test_pulumi_extract_skips_non_provider_call() -> None:
    tree = ast.parse("import pulumi_aws\nimport os\nos.path.join('a', 'b')\n")
    # os.* is not a Pulumi provider root, so no calls are extracted.
    assert pulumi._extract_pulumi_calls(tree, Path("p.py")) == []


def test_pulumi_ingress_entries_dict_and_nonlist() -> None:
    assert pulumi._pul_ingress_entries(_pc(ingress={"from_port": 22})) == [{"from_port": 22}]
    assert pulumi._pul_ingress_entries(_pc(ingress="bogus")) == []


def test_pulumi_open_mgmt_port_none_and_unparseable() -> None:
    # Open to world but ports missing -> None.
    assert pulumi._pul_open_mgmt_port({"cidr_blocks": ["0.0.0.0/0"]}) is None
    # Ports present but not integers -> None.
    assert pulumi._pul_open_mgmt_port({"cidr_blocks": ["0.0.0.0/0"], "from_port": "x", "to_port": "y"}) is None


def test_pulumi_run_scan_rule_engine_error(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "infra.py").write_text("import pulumi_aws as aws\naws.s3.Bucket('b')\n", encoding="utf-8")

    def _boom(_repo: Path, _calls: list) -> list:
        raise RuntimeError("boom")

    monkeypatch.setattr(pulumi, "_RULES", [("IAC-PUL-BAD", _boom)])
    out = pulumi.run_scan(tmp_path)
    assert out.status == "error" and "RuntimeError" in out.diagnostics


# --------------------------------------------------------------------------- #
# Bicep text helpers
# --------------------------------------------------------------------------- #


def test_bicep_normalize_target_outside_repo(tmp_path: Path) -> None:
    other = tmp_path.parent / "x.bicep"
    assert bicep._normalize_target(tmp_path / "repo", other).endswith("x.bicep")


def test_bicep_skip_single_quoted_with_escape() -> None:
    text = "{ name: 'a\\'b' }"
    # Balanced block must not be confused by the escaped quote inside the literal.
    assert bicep._balanced_block(text, 0) == " name: 'a\\'b' "


def test_bicep_balanced_block_non_brace_start() -> None:
    assert bicep._balanced_block("not a brace", 0) == ""


def test_bicep_balanced_block_unterminated() -> None:
    assert bicep._balanced_block("{ unclosed body", 0) == " unclosed body"


def test_bicep_parse_resources_skips_decl_without_brace() -> None:
    text = "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' ="  # no opening brace follows
    assert bicep._parse_resources(text, Path("m.bicep")) == []


def test_bicep_body_has_int_range_absent() -> None:
    assert bicep._body_has_int_range(_br("no port here"), "destinationPortRange") is None


def test_bicep_001_public_network_access_medium() -> None:
    r = _br("publicNetworkAccess: 'Enabled'")
    findings = bicep._rule_iac_bicep_001_public_storage(Path("."), [r])
    assert len(findings) == 1 and findings[0].severity == "MEDIUM"


def test_bicep_open_inbound_nsg_range_guards() -> None:
    # Wrong resource type.
    assert (
        bicep._open_inbound_nsg_range(_br("access: 'Allow'", type_full="Microsoft.Storage/storageAccounts@x")) is None
    )
    nsg_type = "Microsoft.Network/networkSecurityGroups/securityRules@2023-01-01"
    # Right type, but not an Allow rule.
    assert bicep._open_inbound_nsg_range(_br("access: 'Deny'", type_full=nsg_type)) is None
    # Allow but not Inbound.
    assert bicep._open_inbound_nsg_range(_br("access: 'Allow'\ndirection: 'Outbound'", type_full=nsg_type)) is None
    # Allow + Inbound but source not world-open.
    assert (
        bicep._open_inbound_nsg_range(
            _br("access: 'Allow'\ndirection: 'Inbound'\nsourceAddressPrefix: '10.0.0.0/8'", type_full=nsg_type)
        )
        is None
    )


def test_bicep_run_scan_rule_engine_error(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'x'\n}\n", encoding="utf-8"
    )

    def _boom(_repo: Path, _res: list) -> list:
        raise RuntimeError("boom")

    monkeypatch.setattr(bicep, "_RULES", [("IAC-BICEP-BAD", _boom)])
    out = bicep.run_scan(tmp_path)
    assert out.status == "error" and "RuntimeError" in out.diagnostics


# --------------------------------------------------------------------------- #
# CloudFormation helpers
# --------------------------------------------------------------------------- #


def test_cfn_normalize_target_outside_repo(tmp_path: Path) -> None:
    other = tmp_path.parent / "tpl.yaml"
    assert cfn._normalize_target(tmp_path / "repo", other).endswith("tpl.yaml")


def test_cfn_load_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert cfn._load_cfn(p) is None


def test_cfn_load_invalid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("key: : : [\n  - {", encoding="utf-8")
    assert cfn._load_cfn(p) is None


def test_cfn_looks_like_cfn_guards() -> None:
    assert cfn._looks_like_cfn("not-a-dict") is False
    assert cfn._looks_like_cfn({"Resources": {}}) is False  # empty resources
    assert cfn._looks_like_cfn({"Resources": {"R": {"NoType": True}}}) is False


def test_cfn_iter_resources_skips_malformed() -> None:
    tpl = {
        "Resources": {
            "Good": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "b"}},
            "BadBody": "not-a-dict",
            "NoType": {"Properties": {}},
        }
    }
    out = list(cfn._iter_resources(tpl))
    assert len(out) == 1 and out[0][0] == "Good"


def test_cfn_iter_resources_non_dict_resources_block() -> None:
    assert list(cfn._iter_resources({"Resources": ["nope"]})) == []


def test_cfn_load_short_form_intrinsics_sequence_and_mapping(tmp_path: Path) -> None:
    """!GetAtt sequence + !Sub mapping exercise the intrinsic constructor branches."""
    p = tmp_path / "tpl.yaml"
    p.write_text(
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      Name: !GetAtt [Other, Arn]\n"
        "      Tag: !Sub\n"
        "        Fn::Join: ['', ['a', 'b']]\n",
        encoding="utf-8",
    )
    tpl = cfn._load_cfn(p)
    assert tpl is not None
    props = tpl["Resources"]["Bucket"]["Properties"]
    assert props["Name"] == {"Fn::GetAtt": ["Other", "Arn"]}
    assert "Fn::Sub" in props["Tag"]


def test_cfn_run_scan_rule_engine_error(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "tpl.json").write_text(
        '{"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {}}}}', encoding="utf-8"
    )

    def _boom(_repo: Path, _parsed: list) -> list:
        raise RuntimeError("boom")

    monkeypatch.setattr(cfn, "_RULES", [("IAC-CFN-BAD", _boom)])
    out = cfn.run_scan(tmp_path)
    assert out.status == "error" and "RuntimeError" in out.diagnostics
