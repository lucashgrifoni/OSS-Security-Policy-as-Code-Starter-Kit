"""CloudFormation rule pack and evidence writer (v5.7.0).

Mirrors the design of ``infrastructure/iac/scanner.py`` for Terraform: walk
the clone, parse CloudFormation templates (YAML or JSON) via PyYAML/json,
run the bundled rule pack, and write evidence under
``.oss-policy-kit/evidence/iac-cfn.json`` (schema
``oss-policy-kit/evidence/iac-cfn/v1``).

PyYAML and json are stdlib/hard-dep, so this scanner has no
``status: not_available`` path. CloudFormation intrinsic functions
(``Ref``, ``Fn::GetAtt``, ``!Ref``, ``!Sub``, etc.) are preserved as dicts
or strings; rule code reads only the literal attributes it understands and
treats anything else as "indeterminate" (does not raise).

The 6 bundled rules cover the highest-leverage clone-visible CFN posture
gaps: public S3, open management ports, IAM AdministratorAccess and
wildcard Action+Resource, missing encryption-at-rest, audit/logging gaps,
and accidental public IP exposure.
"""

from __future__ import annotations

import json as _json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

import yaml

EVIDENCE_SCHEMA_VERSION = "oss-policy-kit/evidence/iac-cfn/v1"
EVIDENCE_FILENAME = "iac-cfn.json"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = ("**/*.yaml", "**/*.yml", "**/*.json", "**/*.template")

_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".terraform", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".oss-policy-kit"}
)

_MANAGEMENT_PORTS: frozenset[int] = frozenset({22, 3389, 3306, 5432, 1433, 6379, 27017, 9200})

# Resource types whose physical resource carries an encryption flag.
_ENCRYPTION_REQUIRED_TYPES: frozenset[str] = frozenset(
    {
        "AWS::S3::Bucket",
        "AWS::RDS::DBInstance",
        "AWS::RDS::DBCluster",
        "AWS::EC2::Volume",
        "AWS::DynamoDB::Table",
        "AWS::SNS::Topic",
        "AWS::SQS::Queue",
    }
)


@dataclass(slots=True)
class CfnFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    resource_type: str
    resource_name: str


@dataclass(slots=True)
class CfnScanOutcome:
    status: str
    tool_version: str | None
    files_scanned: list[str] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    findings: list[CfnFinding] = field(default_factory=list)
    scanned_at: str = ""
    diagnostics: str = ""


def _kit_version() -> str:
    from oss_policy_kit import __version__ as _src_version

    try:
        installed = _pkg_version("oss-policy-kit")
    except PackageNotFoundError:  # pragma: no cover - dev-only fallback
        return _src_version
    if installed != _src_version:
        return _src_version
    return installed


def _utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_target(repo_root: Path, p: Path) -> str:
    try:
        return p.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def _walk_candidate_files(
    repo_root: Path,
    include_globs: Iterable[str],
    exclude_globs: Iterable[str] | None,
) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    excludes = tuple(exclude_globs or ())
    for pat in include_globs:
        for p in repo_root.glob(pat):
            if not p.is_file():
                continue
            try:
                rel = p.resolve().relative_to(repo_root.resolve())
            except ValueError:
                continue
            if any(part in _SKIP_DIRS for part in rel.parts):
                continue
            if excludes and any(p.match(eg) for eg in excludes):
                continue
            r = p.resolve()
            if r in seen:
                continue
            seen.add(r)
            out.append(p)
    return out


class _CfnSafeLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics like ``!Ref``."""


def _intrinsic_constructor(tag: str) -> Callable[[yaml.SafeLoader, yaml.Node], Any]:
    """Constructor that re-encodes short-form intrinsics into the long-form dict shape."""

    def _ctor(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
        if isinstance(node, yaml.ScalarNode):
            return {tag: loader.construct_scalar(node)}
        if isinstance(node, yaml.SequenceNode):
            return {tag: loader.construct_sequence(node, deep=True)}
        if isinstance(node, yaml.MappingNode):
            return {tag: loader.construct_mapping(node, deep=True)}
        return None

    return _ctor


for _shortcut in (
    "Ref",
    "Condition",
    "GetAtt",
    "GetAZs",
    "ImportValue",
    "Join",
    "Sub",
    "Select",
    "Split",
    "Base64",
    "Cidr",
    "FindInMap",
    "If",
    "Not",
    "And",
    "Or",
    "Equals",
    "Transform",
):
    _CfnSafeLoader.add_constructor(f"!{_shortcut}", _intrinsic_constructor(f"Fn::{_shortcut}"))


def _looks_like_cfn(doc: Any) -> bool:
    """Return True if ``doc`` looks like a CloudFormation template."""

    if not isinstance(doc, dict):
        return False
    resources = doc.get("Resources")
    if not isinstance(resources, dict) or not resources:
        return False
    # Each resource must be a dict with a string Type.
    return any(isinstance(entry, dict) and isinstance(entry.get("Type"), str) for entry in resources.values())


def _load_cfn(path: Path) -> dict[str, Any] | None:
    """Parse one candidate file. Return the template dict, or ``None`` if not CFN."""

    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            parsed = _json.loads(text)
        except _json.JSONDecodeError:
            return None
        return parsed if _looks_like_cfn(parsed) else None
    try:
        # _CfnSafeLoader is a SafeLoader subclass that only adds constructors
        # for CloudFormation short-form intrinsics (!Ref/!Sub/!GetAtt/...).
        # SafeLoader semantics are preserved; yaml.load is required so the
        # custom Loader= argument can be passed (yaml.safe_load forbids it).
        parsed = yaml.load(text, Loader=_CfnSafeLoader)  # nosec B506
    except yaml.YAMLError:
        return None
    return parsed if _looks_like_cfn(parsed) else None


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------


def _iter_resources(template: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any]]]:
    """Yield ``(logical_id, type, properties)`` for every resource in a template."""

    resources = template.get("Resources") or {}
    if not isinstance(resources, dict):
        return
    for logical_id, body in resources.items():
        if not isinstance(body, dict):
            continue
        rtype = body.get("Type")
        if not isinstance(rtype, str):
            continue
        props = body.get("Properties") if isinstance(body.get("Properties"), dict) else {}
        yield logical_id, rtype, props or {}


def _rule_iac_cfn_001_public_s3(repo_root: Path, parsed: list[tuple[Path, dict[str, Any]]]) -> list[CfnFinding]:
    findings: list[CfnFinding] = []
    for path, tpl in parsed:
        for lid, rtype, props in _iter_resources(tpl):
            if rtype != "AWS::S3::Bucket":
                continue
            ac = props.get("AccessControl")
            if isinstance(ac, str) and ac in {"PublicRead", "PublicReadWrite", "AuthenticatedRead"}:
                findings.append(
                    CfnFinding(
                        rule_id="IAC-CFN-001",
                        severity="HIGH",
                        message=f"AWS::S3::Bucket {lid} has AccessControl={ac!r}; use Private.",
                        file=_normalize_target(repo_root, path),
                        resource_type=rtype,
                        resource_name=lid,
                    )
                )
            pab = props.get("PublicAccessBlockConfiguration")
            if isinstance(pab, dict):
                for key in (
                    "BlockPublicAcls",
                    "BlockPublicPolicy",
                    "IgnorePublicAcls",
                    "RestrictPublicBuckets",
                ):
                    if pab.get(key) is False:
                        findings.append(
                            CfnFinding(
                                rule_id="IAC-CFN-001",
                                severity="HIGH",
                                message=(
                                    f"AWS::S3::Bucket {lid} has PublicAccessBlockConfiguration.{key}=false; "
                                    "all four flags should be true."
                                ),
                                file=_normalize_target(repo_root, path),
                                resource_type=rtype,
                                resource_name=lid,
                            )
                        )
    return findings


def _flatten_to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rule_iac_cfn_002_open_mgmt_ports(repo_root: Path, parsed: list[tuple[Path, dict[str, Any]]]) -> list[CfnFinding]:
    findings: list[CfnFinding] = []
    for path, tpl in parsed:
        for lid, rtype, props in _iter_resources(tpl):
            if rtype != "AWS::EC2::SecurityGroup":
                continue
            ingress = props.get("SecurityGroupIngress") or []
            if isinstance(ingress, dict):
                ingress = [ingress]
            if not isinstance(ingress, list):
                continue
            for entry in ingress:
                if not isinstance(entry, dict):
                    continue
                cidr_v4 = entry.get("CidrIp")
                cidr_v6 = entry.get("CidrIpv6")
                if cidr_v4 != "0.0.0.0/0" and cidr_v6 != "::/0":
                    continue
                fp = _flatten_to_int(entry.get("FromPort"))
                tp = _flatten_to_int(entry.get("ToPort"))
                if fp is None or tp is None:
                    continue
                for port in _MANAGEMENT_PORTS:
                    if fp <= port <= tp:
                        findings.append(
                            CfnFinding(
                                rule_id="IAC-CFN-002",
                                severity="HIGH",
                                message=(
                                    f"AWS::EC2::SecurityGroup {lid} ingress {fp}-{tp} "
                                    f"from 0.0.0.0/0 covers management port {port}."
                                ),
                                file=_normalize_target(repo_root, path),
                                resource_type=rtype,
                                resource_name=lid,
                            )
                        )
                        break
    return findings


def _policy_has_wildcards(policy: Any) -> bool:
    """True if a ``PolicyDocument`` dict has ``Action=*`` + ``Resource=*``."""

    if not isinstance(policy, dict):
        return False
    stmts = policy.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if not isinstance(s, dict):
            continue
        if s.get("Effect") != "Allow":
            continue
        actions = s.get("Action")
        resources = s.get("Resource")
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if isinstance(actions, list) and "*" in actions and isinstance(resources, list) and "*" in resources:
            return True
    return False


def _rule_iac_cfn_003_iam_wildcards(repo_root: Path, parsed: list[tuple[Path, dict[str, Any]]]) -> list[CfnFinding]:
    findings: list[CfnFinding] = []
    candidate_types = (
        "AWS::IAM::Role",
        "AWS::IAM::ManagedPolicy",
        "AWS::IAM::Policy",
        "AWS::IAM::User",
        "AWS::IAM::Group",
    )
    for path, tpl in parsed:
        for lid, rtype, props in _iter_resources(tpl):
            if rtype not in candidate_types:
                continue
            # Managed policy ARN attachments.
            for managed in props.get("ManagedPolicyArns") or []:
                if isinstance(managed, str) and managed.endswith(":policy/AdministratorAccess"):
                    findings.append(
                        CfnFinding(
                            rule_id="IAC-CFN-003",
                            severity="HIGH",
                            message=f"{rtype} {lid} attaches AdministratorAccess ({managed}).",
                            file=_normalize_target(repo_root, path),
                            resource_type=rtype,
                            resource_name=lid,
                        )
                    )
            # Inline policies on Roles/Users/Groups.
            for inline in props.get("Policies") or []:
                if isinstance(inline, dict) and _policy_has_wildcards(inline.get("PolicyDocument")):
                    findings.append(
                        CfnFinding(
                            rule_id="IAC-CFN-003",
                            severity="HIGH",
                            message=(
                                f"{rtype} {lid}: inline policy {inline.get('PolicyName')!r} "
                                "allows Action=* on Resource=*."
                            ),
                            file=_normalize_target(repo_root, path),
                            resource_type=rtype,
                            resource_name=lid,
                        )
                    )
            # ManagedPolicy own document.
            if rtype == "AWS::IAM::ManagedPolicy" and _policy_has_wildcards(props.get("PolicyDocument")):
                findings.append(
                    CfnFinding(
                        rule_id="IAC-CFN-003",
                        severity="HIGH",
                        message=f"AWS::IAM::ManagedPolicy {lid} allows Action=* on Resource=*.",
                        file=_normalize_target(repo_root, path),
                        resource_type=rtype,
                        resource_name=lid,
                    )
                )
    return findings


def _rule_iac_cfn_004_no_encryption(repo_root: Path, parsed: list[tuple[Path, dict[str, Any]]]) -> list[CfnFinding]:
    findings: list[CfnFinding] = []
    for path, tpl in parsed:
        for lid, rtype, props in _iter_resources(tpl):
            if rtype not in _ENCRYPTION_REQUIRED_TYPES:
                continue
            encrypted: Any = None
            if rtype == "AWS::S3::Bucket":
                encrypted = props.get("BucketEncryption")
            elif rtype in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"}:
                encrypted = props.get("StorageEncrypted")
            elif rtype == "AWS::EC2::Volume":
                encrypted = props.get("Encrypted")
            elif rtype == "AWS::DynamoDB::Table":
                encrypted = props.get("SSESpecification")
            elif rtype == "AWS::SNS::Topic":
                encrypted = props.get("KmsMasterKeyId")
            elif rtype == "AWS::SQS::Queue":
                encrypted = props.get("KmsMasterKeyId") or props.get("SqsManagedSseEnabled")
            if (
                encrypted is None
                or encrypted is False
                or (isinstance(encrypted, str) and encrypted.strip().lower() == "false")
            ):
                findings.append(
                    CfnFinding(
                        rule_id="IAC-CFN-004",
                        severity="MEDIUM",
                        message=f"{rtype} {lid} has no encryption-at-rest configured.",
                        file=_normalize_target(repo_root, path),
                        resource_type=rtype,
                        resource_name=lid,
                    )
                )
    return findings


def _rule_iac_cfn_005_logging_disabled(repo_root: Path, parsed: list[tuple[Path, dict[str, Any]]]) -> list[CfnFinding]:
    findings: list[CfnFinding] = []
    for path, tpl in parsed:
        for lid, rtype, props in _iter_resources(tpl):
            if rtype == "AWS::CloudTrail::Trail":
                if props.get("IsLogging") is False:
                    findings.append(
                        CfnFinding(
                            rule_id="IAC-CFN-005",
                            severity="MEDIUM",
                            message=f"AWS::CloudTrail::Trail {lid} has IsLogging=false.",
                            file=_normalize_target(repo_root, path),
                            resource_type=rtype,
                            resource_name=lid,
                        )
                    )
            elif rtype == "AWS::S3::Bucket" and "LoggingConfiguration" not in props:
                findings.append(
                    CfnFinding(
                        rule_id="IAC-CFN-005",
                        severity="LOW",
                        message=f"AWS::S3::Bucket {lid} has no LoggingConfiguration.",
                        file=_normalize_target(repo_root, path),
                        resource_type=rtype,
                        resource_name=lid,
                    )
                )
    return findings


def _rule_iac_cfn_006_public_ip(repo_root: Path, parsed: list[tuple[Path, dict[str, Any]]]) -> list[CfnFinding]:
    findings: list[CfnFinding] = []
    for path, tpl in parsed:
        for lid, rtype, props in _iter_resources(tpl):
            if rtype == "AWS::EC2::Subnet":
                if props.get("MapPublicIpOnLaunch") is True:
                    findings.append(
                        CfnFinding(
                            rule_id="IAC-CFN-006",
                            severity="MEDIUM",
                            message=f"AWS::EC2::Subnet {lid} has MapPublicIpOnLaunch=true.",
                            file=_normalize_target(repo_root, path),
                            resource_type=rtype,
                            resource_name=lid,
                        )
                    )
            elif rtype == "AWS::EC2::Instance":
                nis = props.get("NetworkInterfaces") or []
                if isinstance(nis, dict):
                    nis = [nis]
                for ni in nis:
                    if isinstance(ni, dict) and ni.get("AssociatePublicIpAddress") is True:
                        findings.append(
                            CfnFinding(
                                rule_id="IAC-CFN-006",
                                severity="MEDIUM",
                                message=(f"AWS::EC2::Instance {lid} NetworkInterfaces.AssociatePublicIpAddress=true."),
                                file=_normalize_target(repo_root, path),
                                resource_type=rtype,
                                resource_name=lid,
                            )
                        )
                        break
    return findings


_RuleFn = Callable[[Path, list[tuple[Path, dict[str, Any]]]], list[CfnFinding]]

_RULES: tuple[tuple[str, _RuleFn], ...] = (
    ("IAC-CFN-001", _rule_iac_cfn_001_public_s3),
    ("IAC-CFN-002", _rule_iac_cfn_002_open_mgmt_ports),
    ("IAC-CFN-003", _rule_iac_cfn_003_iam_wildcards),
    ("IAC-CFN-004", _rule_iac_cfn_004_no_encryption),
    ("IAC-CFN-005", _rule_iac_cfn_005_logging_disabled),
    ("IAC-CFN-006", _rule_iac_cfn_006_public_ip),
)


def all_rule_ids() -> tuple[str, ...]:
    return tuple(rid for rid, _ in _RULES)


def run_scan(
    repo_root: Path,
    *,
    include_globs: Iterable[str] = DEFAULT_INCLUDE_GLOBS,
    exclude_globs: Iterable[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> CfnScanOutcome:
    _ = timeout_seconds
    files = _walk_candidate_files(repo_root, include_globs, exclude_globs)
    parsed: list[tuple[Path, dict[str, Any]]] = []
    files_scanned: list[Path] = []
    parse_errors: list[dict[str, str]] = []
    for f in files:
        try:
            tpl = _load_cfn(f)
        except OSError as exc:
            parse_errors.append({"file": _normalize_target(repo_root, f), "error": str(exc)})
            continue
        if tpl is None:
            continue
        files_scanned.append(f)
        parsed.append((f, tpl))

    findings: list[CfnFinding] = []
    try:
        for _rid, fn in _RULES:
            # Rule helpers each take ``(path, parsed)`` -- but ``path`` is unused at
            # the rule level (rules iterate over ``parsed`` themselves). We pass
            # ``repo_root`` to honor the same signature shape as iac/scanner.py.
            findings.extend(fn(repo_root, parsed))
    except Exception as exc:  # noqa: BLE001 - rule engine errors must not crash the scan
        return CfnScanOutcome(
            status="error",
            tool_version=_kit_version(),
            files_scanned=[_normalize_target(repo_root, f) for f in files_scanned],
            parse_errors=parse_errors,
            findings=[],
            scanned_at=_utc_iso(),
            diagnostics=f"rule engine raised {type(exc).__name__}: {exc}",
        )
    return CfnScanOutcome(
        status="ok",
        tool_version=_kit_version(),
        files_scanned=[_normalize_target(repo_root, f) for f in files_scanned],
        parse_errors=parse_errors,
        findings=findings,
        scanned_at=_utc_iso(),
    )


def render_evidence_payload(outcome: CfnScanOutcome, *, target: Path) -> dict[str, Any]:
    by_rule: dict[str, int] = {rid: 0 for rid in all_rule_ids()}
    by_severity: dict[str, int] = {}
    for f in outcome.findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": "oss-policy-kit-cfn-parser",
        "tool_version": outcome.tool_version,
        "status": outcome.status,
        "target": str(target.resolve()),
        "scanned_at": outcome.scanned_at,
        "attested_at": outcome.scanned_at,
        "attested_by": "oss-policy-kit scan-cfn",
        "files_scanned": outcome.files_scanned,
        "files_failed": [pe["file"] for pe in outcome.parse_errors],
        "findings_total": len(outcome.findings),
        "findings_by_rule": by_rule,
        "findings_by_severity": by_severity,
        "findings": [asdict(f) for f in outcome.findings],
        "diagnostics": {
            "parse_errors": outcome.parse_errors,
            "raw_message": outcome.diagnostics,
        },
    }


def write_evidence(payload: dict[str, Any], *, repo_root: Path, filename: str = EVIDENCE_FILENAME) -> Path:
    import json

    target_dir = repo_root / ".oss-policy-kit" / "evidence"
    target_dir.mkdir(parents=True, exist_ok=True)
    out = target_dir / filename
    out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return out.resolve()
