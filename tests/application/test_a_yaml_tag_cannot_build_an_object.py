"""A YAML file from the scanned repository cannot make the loader build a Python object.

Every YAML the kit reads from a repository goes through a SafeLoader: `load_capped_document`
calls `yaml.safe_load`, and the CloudFormation scanner uses `_CfnSafeLoader`, a SafeLoader
subclass that only adds constructors turning `!Ref`-style intrinsics into plain dicts. A
`!!python/object/apply` tag is the classic way to run code from a YAML document.

The payload would create a marker file by calling `open`. The control composes it without
constructing anything and checks that the node really carries the `python/object/apply` tag,
so the refusals below are refusals of a well-formed payload, and the absent marker shows the
call never happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oss_policy_kit.application.input_limits import load_capped_document
from oss_policy_kit.domain.errors import InvalidInputError
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn


def _payload(marker: Path) -> str:
    return f"!!python/object/apply:builtins.open [{marker.as_posix()!r}, 'w']"


def test_the_payload_is_a_well_formed_python_tag(tmp_path: Path) -> None:
    """The control: the text parses, and its node is tagged for object construction."""

    node = yaml.compose(f"x: {_payload(tmp_path / 'built')}\n")
    assert isinstance(node, yaml.MappingNode)
    (_, value), *_ = node.value
    assert value.tag == "tag:yaml.org,2002:python/object/apply:builtins.open"


def test_the_capped_document_loader_refuses_a_python_tag(tmp_path: Path) -> None:
    marker = tmp_path / "built"
    doc = tmp_path / "oss-policy-kit.yaml"
    doc.write_text(f"schema_version: 1\nprofile: {_payload(marker)}\n", encoding="utf-8")

    with pytest.raises(InvalidInputError):
        load_capped_document(doc, 1_000_000, label="Config")
    assert not marker.exists()


def test_the_cloudformation_loader_refuses_a_python_tag(tmp_path: Path) -> None:
    marker = tmp_path / "built"
    template = tmp_path / "template.yaml"
    template.write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        f"    Properties: {_payload(marker)}\n",
        encoding="utf-8",
    )

    with pytest.raises(cfn.CfnParseError):
        cfn._load_cfn(template)
    assert not marker.exists()
