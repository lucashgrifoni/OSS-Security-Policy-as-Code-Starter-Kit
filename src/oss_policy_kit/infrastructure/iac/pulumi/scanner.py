"""Pulumi rule pack and evidence writer (v5.7.0).

Pulumi programs are real source code (Python, TypeScript, Go, etc.). This
scanner targets the **Python** flavor and uses the stdlib :mod:`ast` module
to extract Pulumi resource constructor calls of the form ::

    aws.s3.Bucket("name", acl="public-read")
    aws.ec2.SecurityGroup("sg", ingress=[...])
    pulumi_aws.iam.RolePolicyAttachment("a", policy_arn=...)

The scanner is **best-effort by design**: complex resource keyword arguments
that come from variables, expressions, or non-literal constructs are
treated as "indeterminate" and never cause a rule to flag (no false
positives from unresolved references). Files that fail to parse are
recorded as diagnostics and never crash the run.

TypeScript / Go / .NET Pulumi programs are out of scope for v5.7.0 and
will be tracked in a future release. The evidence file still writes
``files_scanned`` so the next ``evaluate`` correctly returns
``not-applicable`` when no Python Pulumi program is present.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

EVIDENCE_SCHEMA_VERSION = "oss-policy-kit/evidence/iac-pulumi/v1"
EVIDENCE_FILENAME = "iac-pulumi.json"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = ("**/*.py",)

_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".terraform", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".oss-policy-kit"}
)

_MANAGEMENT_PORTS: frozenset[int] = frozenset({22, 3389, 3306, 5432, 1433, 6379, 27017, 9200})

_PULUMI_IMPORT_MARKERS: tuple[str, ...] = ("pulumi", "pulumi_aws", "pulumi_azure", "pulumi_gcp", "pulumi_kubernetes")


@dataclass(slots=True)
class PulumiFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    resource_type: str
    resource_name: str


@dataclass(slots=True)
class PulumiCall:
    """One Pulumi resource constructor call extracted from a Python source file."""

    resource_type: str  # e.g. "aws.s3.Bucket" or "pulumi_aws.iam.Role"
    resource_name: str  # first positional string argument, when literal
    kwargs: dict[str, Any]
    source: Path
    line: int


@dataclass(slots=True)
class PulumiScanOutcome:
    status: str
    tool_version: str | None
    files_scanned: list[str] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    findings: list[PulumiFinding] = field(default_factory=list)
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


def _walk_python_files(
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


def _attr_chain(node: ast.AST) -> str | None:
    """Return ``aws.s3.Bucket`` for a chained Attribute, or None when the chain is impure."""

    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return None
    return ".".join(reversed(parts))


def _literal_kwargs(call: ast.Call) -> dict[str, Any]:
    """Best-effort literal evaluation of keyword arguments; non-literals become ``None``."""

    out: dict[str, Any] = {}
    for kw in call.keywords:
        if kw.arg is None:
            continue
        try:
            out[kw.arg] = ast.literal_eval(kw.value)
        except (ValueError, SyntaxError, TypeError):
            out[kw.arg] = None
    return out


def _first_string_positional(call: ast.Call) -> str:
    if not call.args:
        return ""
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return ""


def _file_imports_pulumi(tree: ast.AST) -> bool:
    """True when the module imports any Pulumi provider package."""

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _PULUMI_IMPORT_MARKERS:
                    return True
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in _PULUMI_IMPORT_MARKERS:
            return True
    return False


def _extract_pulumi_calls(tree: ast.AST, source: Path) -> list[PulumiCall]:
    """Walk a parsed AST and emit a :class:`PulumiCall` per recognized Pulumi constructor."""

    calls: list[PulumiCall] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        rtype = _attr_chain(node.func)
        if rtype is None:
            continue
        # Heuristic: the chain root is a known Pulumi package OR includes one of the
        # Pulumi service modules (s3, ec2, iam, storage, etc.) — but to keep false
        # positives down we anchor on the package root being a Pulumi marker.
        root = rtype.split(".")[0]
        if root not in _PULUMI_IMPORT_MARKERS and not rtype.startswith(("aws.", "azure.", "gcp.", "kubernetes.")):
            continue
        name = _first_string_positional(node)
        kwargs = _literal_kwargs(node)
        calls.append(
            PulumiCall(
                resource_type=rtype,
                resource_name=name,
                kwargs=kwargs,
                source=source,
                line=getattr(node, "lineno", 0),
            )
        )
    return calls


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------


def _is_s3_bucket(c: PulumiCall) -> bool:
    return c.resource_type.endswith(".s3.Bucket") or c.resource_type.endswith(".s3.BucketV2")


def _is_security_group(c: PulumiCall) -> bool:
    return c.resource_type.endswith(".ec2.SecurityGroup")


def _is_iam_role_or_policy(c: PulumiCall) -> bool:
    return c.resource_type.endswith((".iam.Role", ".iam.Policy", ".iam.RolePolicyAttachment"))


def _is_rds(c: PulumiCall) -> bool:
    return c.resource_type.endswith((".rds.Instance", ".rds.Cluster"))


def _is_ebs(c: PulumiCall) -> bool:
    return c.resource_type.endswith(".ebs.Volume")


def _is_dynamodb(c: PulumiCall) -> bool:
    return c.resource_type.endswith(".dynamodb.Table")


def _is_instance(c: PulumiCall) -> bool:
    return c.resource_type.endswith(".ec2.Instance")


def _is_subnet(c: PulumiCall) -> bool:
    return c.resource_type.endswith(".ec2.Subnet")


def _rule_iac_pul_001_public_storage(repo_root: Path, calls: list[PulumiCall]) -> list[PulumiFinding]:
    findings: list[PulumiFinding] = []
    for c in calls:
        if not _is_s3_bucket(c):
            continue
        acl = c.kwargs.get("acl")
        if isinstance(acl, str) and acl in {"public-read", "public-read-write", "authenticated-read"}:
            findings.append(
                PulumiFinding(
                    rule_id="IAC-PUL-001",
                    severity="HIGH",
                    message=f"{c.resource_type}({c.resource_name!r}) has acl={acl!r}; use 'private'.",
                    file=_normalize_target(repo_root, c.source),
                    resource_type=c.resource_type,
                    resource_name=c.resource_name,
                )
            )
    return findings


def _rule_iac_pul_002_open_mgmt_ports(repo_root: Path, calls: list[PulumiCall]) -> list[PulumiFinding]:  # noqa: C901
    findings: list[PulumiFinding] = []
    for c in calls:
        if not _is_security_group(c):
            continue
        ingresses = c.kwargs.get("ingress") or []
        if isinstance(ingresses, dict):
            ingresses = [ingresses]
        if not isinstance(ingresses, list):
            continue
        for entry in ingresses:
            if not isinstance(entry, dict):
                continue
            cidrs = entry.get("cidr_blocks") or entry.get("cidrBlocks") or []
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
                continue
            raw_fp = entry.get("from_port", entry.get("fromPort"))
            raw_tp = entry.get("to_port", entry.get("toPort", raw_fp))
            if raw_fp is None or raw_tp is None:
                continue
            try:
                fp = int(raw_fp)
                tp = int(raw_tp)
            except (TypeError, ValueError):
                continue
            for port in _MANAGEMENT_PORTS:
                if fp <= port <= tp:
                    findings.append(
                        PulumiFinding(
                            rule_id="IAC-PUL-002",
                            severity="HIGH",
                            message=(
                                f"{c.resource_type}({c.resource_name!r}) ingress {fp}-{tp} from 0.0.0.0/0 "
                                f"covers management port {port}."
                            ),
                            file=_normalize_target(repo_root, c.source),
                            resource_type=c.resource_type,
                            resource_name=c.resource_name,
                        )
                    )
                    break
    return findings


def _rule_iac_pul_003_iam_wildcards(repo_root: Path, calls: list[PulumiCall]) -> list[PulumiFinding]:
    findings: list[PulumiFinding] = []
    for c in calls:
        if not _is_iam_role_or_policy(c):
            continue
        # RolePolicyAttachment carries a literal policy_arn.
        if c.resource_type.endswith(".RolePolicyAttachment"):
            arn = c.kwargs.get("policy_arn") or c.kwargs.get("policyArn")
            if isinstance(arn, str) and arn.endswith(":policy/AdministratorAccess"):
                findings.append(
                    PulumiFinding(
                        rule_id="IAC-PUL-003",
                        severity="HIGH",
                        message=f"{c.resource_type}({c.resource_name!r}) attaches AdministratorAccess.",
                        file=_normalize_target(repo_root, c.source),
                        resource_type=c.resource_type,
                        resource_name=c.resource_name,
                    )
                )
        # Inline policy bodies (JSON strings) flagged when Action=* + Resource=*.
        policy = c.kwargs.get("policy")
        if (
            isinstance(policy, str)
            and ('"Action": "*"' in policy or '"Action":"*"' in policy)
            and ('"Resource": "*"' in policy or '"Resource":"*"' in policy)
        ):
            findings.append(
                PulumiFinding(
                    rule_id="IAC-PUL-003",
                    severity="HIGH",
                    message=(f"{c.resource_type}({c.resource_name!r}): inline policy grants Action=* on Resource=*."),
                    file=_normalize_target(repo_root, c.source),
                    resource_type=c.resource_type,
                    resource_name=c.resource_name,
                )
            )
    return findings


def _rule_iac_pul_004_no_encryption(repo_root: Path, calls: list[PulumiCall]) -> list[PulumiFinding]:
    findings: list[PulumiFinding] = []
    for c in calls:
        if _is_rds(c):
            storage_encrypted = c.kwargs.get("storage_encrypted", c.kwargs.get("storageEncrypted"))
            if storage_encrypted is None or storage_encrypted is False:
                findings.append(
                    PulumiFinding(
                        rule_id="IAC-PUL-004",
                        severity="MEDIUM",
                        message=f"{c.resource_type}({c.resource_name!r}) has no storage_encrypted=true.",
                        file=_normalize_target(repo_root, c.source),
                        resource_type=c.resource_type,
                        resource_name=c.resource_name,
                    )
                )
        elif _is_ebs(c):
            encrypted = c.kwargs.get("encrypted")
            if encrypted is None or encrypted is False:
                findings.append(
                    PulumiFinding(
                        rule_id="IAC-PUL-004",
                        severity="MEDIUM",
                        message=f"{c.resource_type}({c.resource_name!r}) has no encrypted=true.",
                        file=_normalize_target(repo_root, c.source),
                        resource_type=c.resource_type,
                        resource_name=c.resource_name,
                    )
                )
        elif _is_dynamodb(c):
            sse = c.kwargs.get("server_side_encryption", c.kwargs.get("serverSideEncryption"))
            if sse is None:
                findings.append(
                    PulumiFinding(
                        rule_id="IAC-PUL-004",
                        severity="MEDIUM",
                        message=f"{c.resource_type}({c.resource_name!r}) has no server_side_encryption configured.",
                        file=_normalize_target(repo_root, c.source),
                        resource_type=c.resource_type,
                        resource_name=c.resource_name,
                    )
                )
    return findings


def _rule_iac_pul_005_default_network(repo_root: Path, calls: list[PulumiCall]) -> list[PulumiFinding]:
    """Pulumi-AWS DefaultVpc / DefaultSubnet / DefaultSecurityGroup usage."""

    findings: list[PulumiFinding] = []
    for c in calls:
        if c.resource_type.endswith(
            (".ec2.DefaultVpc", ".ec2.DefaultSubnet", ".ec2.DefaultSecurityGroup", ".ec2.DefaultRouteTable")
        ):
            findings.append(
                PulumiFinding(
                    rule_id="IAC-PUL-005",
                    severity="MEDIUM",
                    message=f"{c.resource_type}({c.resource_name!r}): relying on AWS default network primitive.",
                    file=_normalize_target(repo_root, c.source),
                    resource_type=c.resource_type,
                    resource_name=c.resource_name,
                )
            )
    return findings


def _rule_iac_pul_006_public_ip(repo_root: Path, calls: list[PulumiCall]) -> list[PulumiFinding]:
    findings: list[PulumiFinding] = []
    for c in calls:
        if _is_subnet(c):
            v = c.kwargs.get("map_public_ip_on_launch", c.kwargs.get("mapPublicIpOnLaunch"))
            if v is True:
                findings.append(
                    PulumiFinding(
                        rule_id="IAC-PUL-006",
                        severity="MEDIUM",
                        message=f"{c.resource_type}({c.resource_name!r}) has map_public_ip_on_launch=True.",
                        file=_normalize_target(repo_root, c.source),
                        resource_type=c.resource_type,
                        resource_name=c.resource_name,
                    )
                )
        elif _is_instance(c):
            v = c.kwargs.get("associate_public_ip_address", c.kwargs.get("associatePublicIpAddress"))
            if v is True:
                findings.append(
                    PulumiFinding(
                        rule_id="IAC-PUL-006",
                        severity="MEDIUM",
                        message=f"{c.resource_type}({c.resource_name!r}) has associate_public_ip_address=True.",
                        file=_normalize_target(repo_root, c.source),
                        resource_type=c.resource_type,
                        resource_name=c.resource_name,
                    )
                )
    return findings


_RuleFn = Callable[[Path, list[PulumiCall]], list[PulumiFinding]]

_RULES: tuple[tuple[str, _RuleFn], ...] = (
    ("IAC-PUL-001", _rule_iac_pul_001_public_storage),
    ("IAC-PUL-002", _rule_iac_pul_002_open_mgmt_ports),
    ("IAC-PUL-003", _rule_iac_pul_003_iam_wildcards),
    ("IAC-PUL-004", _rule_iac_pul_004_no_encryption),
    ("IAC-PUL-005", _rule_iac_pul_005_default_network),
    ("IAC-PUL-006", _rule_iac_pul_006_public_ip),
)


def all_rule_ids() -> tuple[str, ...]:
    return tuple(rid for rid, _ in _RULES)


def run_scan(
    repo_root: Path,
    *,
    include_globs: Iterable[str] = DEFAULT_INCLUDE_GLOBS,
    exclude_globs: Iterable[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> PulumiScanOutcome:
    _ = timeout_seconds
    files = _walk_python_files(repo_root, include_globs, exclude_globs)
    calls: list[PulumiCall] = []
    files_scanned: list[Path] = []
    parse_errors: list[dict[str, str]] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            parse_errors.append({"file": _normalize_target(repo_root, f), "error": str(exc)})
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            parse_errors.append({"file": _normalize_target(repo_root, f), "error": f"{exc.msg} (line {exc.lineno})"})
            continue
        if not _file_imports_pulumi(tree):
            continue
        files_scanned.append(f)
        calls.extend(_extract_pulumi_calls(tree, f))

    findings: list[PulumiFinding] = []
    try:
        for _rid, fn in _RULES:
            findings.extend(fn(repo_root, calls))
    except Exception as exc:  # noqa: BLE001 - rule engine errors must not crash the scan
        return PulumiScanOutcome(
            status="error",
            tool_version=_kit_version(),
            files_scanned=[_normalize_target(repo_root, f) for f in files_scanned],
            parse_errors=parse_errors,
            findings=[],
            scanned_at=_utc_iso(),
            diagnostics=f"rule engine raised {type(exc).__name__}: {exc}",
        )
    return PulumiScanOutcome(
        status="ok",
        tool_version=_kit_version(),
        files_scanned=[_normalize_target(repo_root, f) for f in files_scanned],
        parse_errors=parse_errors,
        findings=findings,
        scanned_at=_utc_iso(),
    )


def render_evidence_payload(outcome: PulumiScanOutcome, *, target: Path) -> dict[str, Any]:
    by_rule: dict[str, int] = {rid: 0 for rid in all_rule_ids()}
    by_severity: dict[str, int] = {}
    for f in outcome.findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": "oss-policy-kit-pulumi-parser",
        "tool_version": outcome.tool_version,
        "status": outcome.status,
        "target": str(target.resolve()),
        "scanned_at": outcome.scanned_at,
        "attested_at": outcome.scanned_at,
        "attested_by": "oss-policy-kit scan-pulumi",
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
