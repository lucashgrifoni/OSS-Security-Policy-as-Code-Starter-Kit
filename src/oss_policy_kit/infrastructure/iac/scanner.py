"""Native Terraform / OpenTofu rule pack and evidence writer.

Mirrors the design of ``infrastructure/scanners/semgrep_adapter.py``: scan
the target, normalize findings into a versioned evidence file under
``.oss-policy-kit/evidence/iac-terraform.json``, and let each ``IAC-TF-*``
evaluator read that JSON. Keeps evaluators trivial and the parsing path
in one place.

The 12 rules cover the high-leverage clone-visible posture surface:
public storage, internet-exposed management ports, IAM wildcards, missing
encryption, audit/logging gaps, default-VPC reliance, accidental public
IPs, missing tags, unpinned providers, local backend state, missing
``prevent_destroy`` on data stores, and wildcard IAM principals.

The scanner is **best-effort by design**: parser failures on individual
files are recorded as diagnostics, never crash the run. ``scan-iac`` exits
0 even when the parser library is missing -- the evidence is written with
``status: not_available`` so the next ``evaluate`` surfaces the gap
honestly. This mirrors the SAST contract exactly.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

from .hcl_loader import hcl2_available
from .tf_resource_index import TfBlock, TfResourceIndex, build_index

#: Schema version for the on-disk evidence file. Bumped only on shape changes.
EVIDENCE_SCHEMA_VERSION = "oss-policy-kit/evidence/iac-terraform/v1"

#: Stable evidence filename consumed by every ``IAC-TF-*`` evaluator.
EVIDENCE_FILENAME = "iac-terraform.json"

#: Default upper bound for parsing wall-clock time. The HCL parser is fast,
#: but a pathological tree might take a while; bail out instead of hanging.
DEFAULT_TIMEOUT_SECONDS = 120

#: Glob patterns we treat as Terraform / OpenTofu sources.
DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = ("**/*.tf",)

#: Directory names we always skip (vendored modules, cache, version-control).
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".terraform",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".oss-policy-kit",
    }
)

#: Management-plane ports that must never be exposed to the public internet.
_MANAGEMENT_PORTS: frozenset[int] = frozenset({22, 3389, 3306, 5432, 1433, 6379, 27017, 9200})

#: Resource types that must always have encryption configured.
_ENCRYPTION_REQUIRED_TYPES: frozenset[str] = frozenset(
    {
        "aws_s3_bucket",
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_ebs_volume",
        "aws_dynamodb_table",
        "aws_sns_topic",
        "aws_sqs_queue",
        "aws_kinesis_stream",
        "google_storage_bucket",
        "azurerm_storage_account",
        "azurerm_managed_disk",
    }
)

#: Resource types whose audit/logging trail must be enabled.
_AUDIT_REQUIRED_TYPES: frozenset[str] = frozenset(
    {
        "aws_cloudtrail",
        "aws_s3_bucket",
        "aws_db_instance",
        "azurerm_monitor_diagnostic_setting",
    }
)

#: Production-naming heuristics for IAC-TF-011.
_PROD_NAME_PATTERN = re.compile(r"prod|production|prd|live", re.IGNORECASE)


@dataclass(slots=True)
class IacFinding:
    """One normalized IaC finding embedded in the evidence JSON."""

    rule_id: str
    severity: str
    message: str
    file: str
    resource_type: str
    resource_name: str


@dataclass(slots=True)
class IacScanOutcome:
    """Structured outcome of one ``scan-iac`` run."""

    status: str
    tool_version: str | None
    files_scanned: list[str] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    findings: list[IacFinding] = field(default_factory=list)
    scanned_at: str = ""
    diagnostics: str = ""


def _kit_version() -> str:
    try:
        return _pkg_version("oss-policy-kit")
    except PackageNotFoundError:  # pragma: no cover - dev-only fallback
        return "0.0.0+local"


def _utc_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_target(repo_root: Path, path: Path) -> str:
    """Render a parser-discovered file as a repo-relative POSIX path for evidence."""

    try:
        rel = path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return path.as_posix()
    return rel.as_posix()


def _walk_tf_files(
    repo_root: Path,
    include_globs: Iterable[str],
    exclude_globs: Iterable[str] | None,
) -> list[Path]:
    """Discover ``*.tf`` files honoring ``_SKIP_DIRS`` and operator excludes."""

    seen: set[Path] = set()
    excludes = tuple(exclude_globs or ())
    for pattern in include_globs:
        for path in repo_root.glob(pattern):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if any(path.match(ex) for ex in excludes):
                continue
            seen.add(path.resolve())
    return sorted(seen)


# ---------------------------------------------------------------------------
# Rule implementations. Each rule reads the index and yields IacFinding(s).
# ---------------------------------------------------------------------------


def _is_truthy(value: Any) -> bool:
    """Treat ``True``, ``"true"``, ``1`` as truthy. Anything else is falsy."""

    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "on", "1"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _block_file(repo_root: Path, block: TfBlock) -> str:
    return _normalize_target(repo_root, block.source_path)


def _rule_iac_tf_001_public_storage(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """S3 / GCS bucket configured for public access."""

    findings: list[IacFinding] = []
    for block in index.resources("aws_s3_bucket"):
        acl = block.get("acl")
        if isinstance(acl, str) and acl in {"public-read", "public-read-write", "authenticated-read"}:
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-001",
                    severity="HIGH",
                    message=(
                        f"aws_s3_bucket.{block.name} has acl={acl!r}; "
                        'set acl="private" or use aws_s3_bucket_public_access_block.'
                    ),
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    for block in index.resources("aws_s3_bucket_public_access_block"):
        # If any of the four block flags is explicitly false, that's a finding.
        for key in (
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        ):
            value = block.get(key)
            if value is False or (isinstance(value, str) and value.strip().lower() == "false"):
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-001",
                        severity="HIGH",
                        message=(
                            f"aws_s3_bucket_public_access_block.{block.name} has {key}=false; "
                            "all four flags should be true."
                        ),
                        file=_block_file(repo_root, block),
                        resource_type=block.resource_type,
                        resource_name=block.name,
                    )
                )
    for block in index.resources("google_storage_bucket"):
        # GCS-level public access prevention.
        ppa = block.get("public_access_prevention")
        if isinstance(ppa, str) and ppa.lower() == "inherited":
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-001",
                    severity="HIGH",
                    message=(
                        f"google_storage_bucket.{block.name} has public_access_prevention='inherited'; set 'enforced'."
                    ),
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    return findings


def _rule_iac_tf_002_open_mgmt_ports(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """Security groups exposing management ports to ``0.0.0.0/0``."""

    findings: list[IacFinding] = []
    for block in index.resources("aws_security_group"):
        ingresses = block.get("ingress") or []
        if isinstance(ingresses, dict):
            ingresses = [ingresses]
        for entry in ingresses:
            if not isinstance(entry, dict):
                continue
            cidrs = entry.get("cidr_blocks") or []
            if not isinstance(cidrs, list):
                cidrs = [cidrs]
            if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
                continue
            from_port = entry.get("from_port")
            to_port = entry.get("to_port", from_port)
            try:
                fp = int(from_port) if from_port is not None else None
                tp = int(to_port) if to_port is not None else fp
            except (TypeError, ValueError):
                continue
            if fp is None or tp is None:
                continue
            for port in _MANAGEMENT_PORTS:
                if fp <= port <= tp:
                    findings.append(
                        IacFinding(
                            rule_id="IAC-TF-002",
                            severity="HIGH",
                            message=(
                                f"aws_security_group.{block.name} ingress {fp}-{tp} "
                                f"from 0.0.0.0/0 covers management port {port}."
                            ),
                            file=_block_file(repo_root, block),
                            resource_type=block.resource_type,
                            resource_name=block.name,
                        )
                    )
                    break
    return findings


def _iam_policy_documents_with_wildcards(block: TfBlock) -> list[str]:
    """Return human-readable hints about wildcard Action/Resource pairs in a policy block."""

    issues: list[str] = []
    policy = block.get("policy")
    if (
        isinstance(policy, str)
        and ('"Action": "*"' in policy or '"Action":"*"' in policy)
        and ('"Resource": "*"' in policy or '"Resource":"*"' in policy)
    ):
        issues.append("inline policy grants Action=* on Resource=*")
    managed = block.get("managed_policy_arns") or []
    if isinstance(managed, list):
        for arn in managed:
            if isinstance(arn, str) and arn.endswith(":policy/AdministratorAccess"):
                issues.append(f"managed policy {arn} attached")
    return issues


def _rule_iac_tf_003_iam_wildcards(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """IAM roles / policies granting AdministratorAccess or wildcard Action+Resource."""

    findings: list[IacFinding] = []
    candidate_types = (
        "aws_iam_role",
        "aws_iam_policy",
        "aws_iam_user_policy",
        "aws_iam_role_policy",
        "aws_iam_group_policy",
    )
    for rt in candidate_types:
        for block in index.resources(rt):
            for issue in _iam_policy_documents_with_wildcards(block):
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-003",
                        severity="HIGH",
                        message=f"{rt}.{block.name}: {issue}.",
                        file=_block_file(repo_root, block),
                        resource_type=rt,
                        resource_name=block.name,
                    )
                )
    for block in index.resources("aws_iam_role_policy_attachment"):
        arn = block.get("policy_arn")
        if isinstance(arn, str) and arn.endswith(":policy/AdministratorAccess"):
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-003",
                    severity="HIGH",
                    message=f"aws_iam_role_policy_attachment.{block.name} attaches AdministratorAccess.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    return findings


def _rule_iac_tf_004_no_encryption(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """Storage / RDS / EBS resources without encryption-at-rest."""

    findings: list[IacFinding] = []
    for rt in _ENCRYPTION_REQUIRED_TYPES:
        for block in index.resources(rt):
            encrypted = block.get("storage_encrypted") or block.get("encrypted") or block.get("enable_kms_encryption")
            sse = block.get("server_side_encryption_configuration")
            kms_key = block.get("kms_key_id") or block.get("kms_master_key_id")
            if encrypted is None and sse is None and kms_key is None:
                # No encryption attribute set at all on a type that needs one.
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-004",
                        severity="MEDIUM",
                        message=f"{rt}.{block.name} has no encryption-at-rest configured.",
                        file=_block_file(repo_root, block),
                        resource_type=rt,
                        resource_name=block.name,
                    )
                )
            elif encrypted is False or (isinstance(encrypted, str) and encrypted.strip().lower() == "false"):
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-004",
                        severity="MEDIUM",
                        message=f"{rt}.{block.name} explicitly disables encryption.",
                        file=_block_file(repo_root, block),
                        resource_type=rt,
                        resource_name=block.name,
                    )
                )
    return findings


def _rule_iac_tf_005_logging_disabled(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """CloudTrail / RDS / S3 access-log style resources with logging off."""

    findings: list[IacFinding] = []
    for block in index.resources("aws_cloudtrail"):
        if block.get("enable_logging") is False:
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-005",
                    severity="MEDIUM",
                    message=f"aws_cloudtrail.{block.name} has enable_logging=false.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    for block in index.resources("aws_s3_bucket"):
        # Look for a paired aws_s3_bucket_logging resource referencing this bucket.
        # If the bucket itself sets ``logging`` block to absent, that's a finding.
        logging = block.get("logging")
        if logging is None and not any(
            isinstance(b.get("bucket"), str) and block.name in b.get("bucket", "")
            for b in index.resources("aws_s3_bucket_logging")
        ):
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-005",
                    severity="MEDIUM",
                    message=f"aws_s3_bucket.{block.name} has no access logging configured.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    for block in index.resources("aws_db_instance"):
        if not block.get("enabled_cloudwatch_logs_exports"):
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-005",
                    severity="MEDIUM",
                    message=f"aws_db_instance.{block.name} has no enabled_cloudwatch_logs_exports.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    return findings


def _rule_iac_tf_006_default_network(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """Use of ``default_vpc`` / ``default_subnet`` / default security group."""

    findings: list[IacFinding] = []
    for rt in ("aws_default_vpc", "aws_default_subnet", "aws_default_security_group", "aws_default_route_table"):
        for block in index.resources(rt):
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-006",
                    severity="MEDIUM",
                    message=f"{rt}.{block.name}: relying on AWS default network primitive; declare an explicit one.",
                    file=_block_file(repo_root, block),
                    resource_type=rt,
                    resource_name=block.name,
                )
            )
    return findings


def _rule_iac_tf_007_public_ip(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """Workloads with ``map_public_ip_on_launch = true`` or ``associate_public_ip_address = true``."""

    findings: list[IacFinding] = []
    for block in index.resources("aws_subnet"):
        if _is_truthy(block.get("map_public_ip_on_launch")):
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-007",
                    severity="MEDIUM",
                    message=f"aws_subnet.{block.name} has map_public_ip_on_launch=true.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    for block in index.resources("aws_instance"):
        if _is_truthy(block.get("associate_public_ip_address")):
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-007",
                    severity="MEDIUM",
                    message=f"aws_instance.{block.name} has associate_public_ip_address=true.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    for block in index.resources("aws_launch_template"):
        nis = block.get("network_interfaces") or []
        if isinstance(nis, dict):
            nis = [nis]
        for ni in nis:
            if isinstance(ni, dict) and _is_truthy(ni.get("associate_public_ip_address")):
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-007",
                        severity="MEDIUM",
                        message=(
                            f"aws_launch_template.{block.name} network_interfaces.associate_public_ip_address=true."
                        ),
                        file=_block_file(repo_root, block),
                        resource_type=block.resource_type,
                        resource_name=block.name,
                    )
                )
                break
    return findings


def _rule_iac_tf_008_missing_tags(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """AWS resources without any ``tags`` (or without ``owner``/``cost_center``)."""

    findings: list[IacFinding] = []
    for rt in list(index.types_matching("aws_")):
        # Skip *iam* and *_attachment / *_policy* — they don't accept tags universally.
        if "iam_role_policy" in rt or "_attachment" in rt:
            continue
        for block in index.resources(rt):
            tags = block.get("tags")
            if not tags or not isinstance(tags, dict):
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-008",
                        severity="LOW",
                        message=f"{rt}.{block.name} has no tags block.",
                        file=_block_file(repo_root, block),
                        resource_type=rt,
                        resource_name=block.name,
                    )
                )
                continue
            if "owner" not in tags and "cost_center" not in tags and "Owner" not in tags:
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-008",
                        severity="LOW",
                        message=f"{rt}.{block.name} tags missing owner/cost_center.",
                        file=_block_file(repo_root, block),
                        resource_type=rt,
                        resource_name=block.name,
                    )
                )
    return findings


def _rule_iac_tf_009_unpinned_providers(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """``required_providers`` block missing or providers without a pinned version."""

    findings: list[IacFinding] = []
    for path, parsed in index.raw_files.items():
        terraform = parsed.get("terraform") or []
        if not isinstance(terraform, list):
            terraform = [terraform]
        for tf in terraform:
            if not isinstance(tf, dict):
                continue
            required = tf.get("required_providers") or []
            if isinstance(required, dict):
                required = [required]
            if not required:
                findings.append(
                    IacFinding(
                        rule_id="IAC-TF-009",
                        severity="LOW",
                        message=f"{_normalize_target(repo_root, path)}: terraform.required_providers is missing.",
                        file=_normalize_target(repo_root, path),
                        resource_type="terraform.required_providers",
                        resource_name="",
                    )
                )
                continue
            for entry in required:
                if not isinstance(entry, dict):
                    continue
                for provider, spec in entry.items():
                    version_ = None
                    if isinstance(spec, dict):
                        version_ = spec.get("version")
                    if not version_:
                        findings.append(
                            IacFinding(
                                rule_id="IAC-TF-009",
                                severity="LOW",
                                message=(
                                    f"{_normalize_target(repo_root, path)}: "
                                    f"provider {provider!r} has no pinned version."
                                ),
                                file=_normalize_target(repo_root, path),
                                resource_type="terraform.required_providers",
                                resource_name=provider,
                            )
                        )
    return findings


def _rule_iac_tf_010_local_backend(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """``terraform { backend "local" }`` block (or no backend at all in production layouts)."""

    findings: list[IacFinding] = []
    for path, parsed in index.raw_files.items():
        terraform = parsed.get("terraform") or []
        if not isinstance(terraform, list):
            terraform = [terraform]
        for tf in terraform:
            if not isinstance(tf, dict):
                continue
            backend = tf.get("backend") or []
            if isinstance(backend, dict):
                backend = [backend]
            for entry in backend:
                if not isinstance(entry, dict):
                    continue
                # backend block: { "<backend_name>": {...} }
                for backend_name in entry:
                    if backend_name == "local":
                        findings.append(
                            IacFinding(
                                rule_id="IAC-TF-010",
                                severity="LOW",
                                message=(
                                    f"{_normalize_target(repo_root, path)}: terraform backend is 'local'; "
                                    "use a remote backend with encryption + locking."
                                ),
                                file=_normalize_target(repo_root, path),
                                resource_type="terraform.backend",
                                resource_name=backend_name,
                            )
                        )
    return findings


def _rule_iac_tf_011_prevent_destroy(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """``lifecycle.prevent_destroy = false`` (or absent) on data stores in production naming patterns."""

    findings: list[IacFinding] = []
    data_store_types = (
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_dynamodb_table",
        "aws_s3_bucket",
        "azurerm_storage_account",
        "google_sql_database_instance",
    )
    for rt in data_store_types:
        for block in index.resources(rt):
            looks_prod = _PROD_NAME_PATTERN.search(block.name) or _PROD_NAME_PATTERN.search(
                str(block.get("name") or block.get("identifier") or "")
            )
            if not looks_prod:
                continue
            lifecycle = block.get("lifecycle")
            if isinstance(lifecycle, list) and lifecycle:
                lifecycle = lifecycle[0]
            prevent = lifecycle.get("prevent_destroy") if isinstance(lifecycle, dict) else None
            if prevent is True:
                continue
            findings.append(
                IacFinding(
                    rule_id="IAC-TF-011",
                    severity="MEDIUM",
                    message=(
                        f"{rt}.{block.name} looks like a production data store "
                        "but lifecycle.prevent_destroy is not true."
                    ),
                    file=_block_file(repo_root, block),
                    resource_type=rt,
                    resource_name=block.name,
                )
            )
    return findings


def _rule_iac_tf_012_wildcard_principals(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """``data.aws_iam_policy_document`` statements with ``principals.identifiers = ["*"]``.

    The HCL hcl2 6.x parser exposes ``data`` blocks under the ``data`` key in
    each parsed file. We inspect them directly because they are not part of
    the resource index.
    """

    findings: list[IacFinding] = []
    for path, parsed in index.raw_files.items():
        data = parsed.get("data") or []
        if not isinstance(data, list):
            data = [data]
        for entry in data:
            if not isinstance(entry, dict):
                continue
            doc_section = entry.get("aws_iam_policy_document")
            if not isinstance(doc_section, dict):
                continue
            for name, body in doc_section.items():
                if not isinstance(body, dict):
                    continue
                statements = body.get("statement") or []
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue
                    principals = stmt.get("principals") or []
                    if isinstance(principals, dict):
                        principals = [principals]
                    for p in principals:
                        if not isinstance(p, dict):
                            continue
                        idents = p.get("identifiers") or []
                        if "*" in idents:
                            findings.append(
                                IacFinding(
                                    rule_id="IAC-TF-012",
                                    severity="LOW",
                                    message=(
                                        f"data.aws_iam_policy_document.{name}: statement has wildcard principal '*'."
                                    ),
                                    file=_normalize_target(repo_root, path),
                                    resource_type="data.aws_iam_policy_document",
                                    resource_name=name,
                                )
                            )
                            break
    return findings


_RuleFn = Callable[[Path, TfResourceIndex], list[IacFinding]]

_RULES: tuple[tuple[str, _RuleFn], ...] = (
    ("IAC-TF-001", _rule_iac_tf_001_public_storage),
    ("IAC-TF-002", _rule_iac_tf_002_open_mgmt_ports),
    ("IAC-TF-003", _rule_iac_tf_003_iam_wildcards),
    ("IAC-TF-004", _rule_iac_tf_004_no_encryption),
    ("IAC-TF-005", _rule_iac_tf_005_logging_disabled),
    ("IAC-TF-006", _rule_iac_tf_006_default_network),
    ("IAC-TF-007", _rule_iac_tf_007_public_ip),
    ("IAC-TF-008", _rule_iac_tf_008_missing_tags),
    ("IAC-TF-009", _rule_iac_tf_009_unpinned_providers),
    ("IAC-TF-010", _rule_iac_tf_010_local_backend),
    ("IAC-TF-011", _rule_iac_tf_011_prevent_destroy),
    ("IAC-TF-012", _rule_iac_tf_012_wildcard_principals),
)


def all_rule_ids() -> tuple[str, ...]:
    """Return the canonical (ordered) list of bundled rule IDs."""

    return tuple(rid for rid, _ in _RULES)


def run_scan(
    repo_root: Path,
    *,
    include_globs: Iterable[str] = DEFAULT_INCLUDE_GLOBS,
    exclude_globs: Iterable[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,  # accepted for API symmetry; parser is in-process
) -> IacScanOutcome:
    """Discover ``.tf`` files, run every bundled rule, return a structured outcome."""

    _ = timeout_seconds  # currently unused; kept for symmetry with scan-sast
    if not hcl2_available():
        return IacScanOutcome(
            status="not_available",
            tool_version=_kit_version(),
            scanned_at=_utc_iso(),
            diagnostics="python-hcl2 is not installed; install the 'iac' extra: pip install 'oss-policy-kit[iac]'.",
        )

    files = _walk_tf_files(repo_root, include_globs, exclude_globs)
    if not files:
        return IacScanOutcome(
            status="ok",
            tool_version=_kit_version(),
            files_scanned=[],
            findings=[],
            scanned_at=_utc_iso(),
        )

    index = build_index(files)

    parse_errors: list[dict[str, str]] = [
        {"file": _normalize_target(repo_root, p), "error": str(err)} for p, err in index.parse_errors
    ]

    findings: list[IacFinding] = []
    try:
        for _, fn in _RULES:
            findings.extend(fn(repo_root, index))
    except Exception as exc:  # noqa: BLE001 - one bad rule should not crash the scan
        return IacScanOutcome(
            status="error",
            tool_version=_kit_version(),
            files_scanned=[_normalize_target(repo_root, p) for p in index.files_parsed],
            parse_errors=parse_errors,
            findings=[],
            scanned_at=_utc_iso(),
            diagnostics=f"rule engine raised {type(exc).__name__}: {exc}",
        )

    return IacScanOutcome(
        status="ok",
        tool_version=_kit_version(),
        files_scanned=[_normalize_target(repo_root, p) for p in index.files_parsed],
        parse_errors=parse_errors,
        findings=findings,
        scanned_at=_utc_iso(),
    )


def render_evidence_payload(outcome: IacScanOutcome, *, target: Path) -> dict[str, Any]:
    """Build the on-disk evidence dict consumed by every ``IAC-TF-*`` evaluator."""

    by_rule: dict[str, int] = {rid: 0 for rid in all_rule_ids()}
    by_severity: dict[str, int] = {}
    for f in outcome.findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": "oss-policy-kit-tf-parser",
        "tool_version": outcome.tool_version,
        "status": outcome.status,
        "target": str(target.resolve()),
        "scanned_at": outcome.scanned_at,
        "attested_at": outcome.scanned_at,
        "attested_by": "oss-policy-kit scan-iac",
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
    """Write evidence under ``.oss-policy-kit/evidence/<filename>``."""

    import json

    target_dir = repo_root / ".oss-policy-kit" / "evidence"
    target_dir.mkdir(parents=True, exist_ok=True)
    out = target_dir / filename
    out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return out.resolve()
