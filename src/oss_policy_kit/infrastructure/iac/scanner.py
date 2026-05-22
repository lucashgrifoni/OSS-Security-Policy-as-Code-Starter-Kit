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
    from oss_policy_kit import __version__ as _src_version

    try:
        installed = _pkg_version("oss-policy-kit")
    except PackageNotFoundError:  # pragma: no cover - dev-only fallback
        return _src_version
    if installed != _src_version:
        return _src_version
    return installed


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


def _iac_finding(
    rule_id: str,
    severity: str,
    message: str,
    *,
    file: str,
    resource_type: str,
    resource_name: str,
) -> IacFinding:
    """Construct an :class:`IacFinding` (thin factory to keep rule bodies flat)."""

    return IacFinding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        file=file,
        resource_type=resource_type,
        resource_name=resource_name,
    )


def _s3_pab_findings(block: TfBlock, repo_root: Path) -> list[IacFinding]:
    """One IAC-TF-001 finding per public-access-block flag explicitly set to false."""

    out: list[IacFinding] = []
    for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
        value = block.get(key)
        if value is False or (isinstance(value, str) and value.strip().lower() == "false"):
            out.append(
                _iac_finding(
                    "IAC-TF-001",
                    "HIGH",
                    f"aws_s3_bucket_public_access_block.{block.name} has {key}=false; all four flags should be true.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    return out


def _rule_iac_tf_001_public_storage(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """S3 / GCS bucket configured for public access."""

    findings: list[IacFinding] = []
    for block in index.resources("aws_s3_bucket"):
        acl = block.get("acl")
        if isinstance(acl, str) and acl in {"public-read", "public-read-write", "authenticated-read"}:
            findings.append(
                _iac_finding(
                    "IAC-TF-001",
                    "HIGH",
                    (
                        f"aws_s3_bucket.{block.name} has acl={acl!r}; "
                        'set acl="private" or use aws_s3_bucket_public_access_block.'
                    ),
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    for block in index.resources("aws_s3_bucket_public_access_block"):
        findings.extend(_s3_pab_findings(block, repo_root))
    for block in index.resources("google_storage_bucket"):
        # GCS-level public access prevention.
        ppa = block.get("public_access_prevention")
        if isinstance(ppa, str) and ppa.lower() == "inherited":
            findings.append(
                _iac_finding(
                    "IAC-TF-001",
                    "HIGH",
                    f"google_storage_bucket.{block.name} has public_access_prevention='inherited'; set 'enforced'.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            )
    return findings


def _sg_ingress_entries(block: TfBlock) -> list[dict[str, Any]]:
    """Normalize a security group's ``ingress`` to a list of dict entries."""

    ingresses = block.get("ingress") or []
    if isinstance(ingresses, dict):
        ingresses = [ingresses]
    return [e for e in ingresses if isinstance(e, dict)]


def _tf_ingress_open_mgmt_port(entry: dict[str, Any]) -> tuple[int, int, int] | None:
    """Return ``(from, to, covered_mgmt_port)`` if this ingress opens a mgmt port to the world."""

    cidrs = entry.get("cidr_blocks") or []
    if not isinstance(cidrs, list):
        cidrs = [cidrs]
    if "0.0.0.0/0" not in cidrs and "::/0" not in cidrs:
        return None
    from_port = entry.get("from_port")
    to_port = entry.get("to_port", from_port)
    try:
        fp = int(from_port) if from_port is not None else None
        tp = int(to_port) if to_port is not None else fp
    except (TypeError, ValueError):
        return None
    if fp is None or tp is None:
        return None
    covered = next((port for port in _MANAGEMENT_PORTS if fp <= port <= tp), None)
    return (fp, tp, covered) if covered is not None else None


def _rule_iac_tf_002_open_mgmt_ports(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """Security groups exposing management ports to ``0.0.0.0/0``."""

    findings: list[IacFinding] = []
    for block in index.resources("aws_security_group"):
        for entry in _sg_ingress_entries(block):
            hit = _tf_ingress_open_mgmt_port(entry)
            if hit is not None:
                fp, tp, port = hit
                findings.append(
                    _iac_finding(
                        "IAC-TF-002",
                        "HIGH",
                        (
                            f"aws_security_group.{block.name} ingress {fp}-{tp} "
                            f"from 0.0.0.0/0 covers management port {port}."
                        ),
                        file=_block_file(repo_root, block),
                        resource_type=block.resource_type,
                        resource_name=block.name,
                    )
                )
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


def _has_separate_s3_encryption(bucket_name: str, index: TfResourceIndex) -> bool:
    """True when an ``aws_s3_bucket_server_side_encryption_configuration`` resource references *bucket_name*.

    AWS S3 moved encryption out of ``aws_s3_bucket`` into a dedicated resource
    starting with terraform-provider-aws v4. Hardened modules following the
    modern pattern (``resource "aws_s3_bucket" "x" {}`` paired with
    ``resource "aws_s3_bucket_server_side_encryption_configuration" "x" { bucket = aws_s3_bucket.x.id }``)
    used to fail IAC-TF-004 because the evaluator only looked at attributes
    inside the bucket block. Cross-referencing eliminates that false positive
    while keeping the rule honest for unencrypted buckets.
    """

    for sep in index.resources("aws_s3_bucket_server_side_encryption_configuration"):
        bucket_ref = sep.get("bucket")
        if isinstance(bucket_ref, str) and bucket_name in bucket_ref:
            return True
    return False


def _encryption_finding(rt: str, block: TfBlock, index: TfResourceIndex, repo_root: Path) -> IacFinding | None:
    """Return an IAC-TF-004 finding for one resource block, or None when encryption looks present."""

    encrypted = block.get("storage_encrypted") or block.get("encrypted") or block.get("enable_kms_encryption")
    sse = block.get("server_side_encryption_configuration")
    kms_key = block.get("kms_key_id") or block.get("kms_master_key_id")
    # AWS S3 modern pattern: encryption can live in a separate resource.
    if rt == "aws_s3_bucket" and _has_separate_s3_encryption(block.name, index):
        return None
    if encrypted is None and sse is None and kms_key is None:
        return _iac_finding(
            "IAC-TF-004",
            "MEDIUM",
            f"{rt}.{block.name} has no encryption-at-rest configured.",
            file=_block_file(repo_root, block),
            resource_type=rt,
            resource_name=block.name,
        )
    if encrypted is False or (isinstance(encrypted, str) and encrypted.strip().lower() == "false"):
        return _iac_finding(
            "IAC-TF-004",
            "MEDIUM",
            f"{rt}.{block.name} explicitly disables encryption.",
            file=_block_file(repo_root, block),
            resource_type=rt,
            resource_name=block.name,
        )
    return None


def _rule_iac_tf_004_no_encryption(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """Storage / RDS / EBS resources without encryption-at-rest."""

    findings: list[IacFinding] = []
    for rt in _ENCRYPTION_REQUIRED_TYPES:
        for block in index.resources(rt):
            finding = _encryption_finding(rt, block, index, repo_root)
            if finding is not None:
                findings.append(finding)
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


def _launch_template_public_ip_findings(block: TfBlock, repo_root: Path) -> list[IacFinding]:
    """Return a single IAC-TF-007 finding when a launch template assigns a public IP."""

    nis = block.get("network_interfaces") or []
    if isinstance(nis, dict):
        nis = [nis]
    for ni in nis:
        if isinstance(ni, dict) and _is_truthy(ni.get("associate_public_ip_address")):
            return [
                _iac_finding(
                    "IAC-TF-007",
                    "MEDIUM",
                    f"aws_launch_template.{block.name} network_interfaces.associate_public_ip_address=true.",
                    file=_block_file(repo_root, block),
                    resource_type=block.resource_type,
                    resource_name=block.name,
                )
            ]
    return []


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
        findings.extend(_launch_template_public_ip_findings(block, repo_root))
    return findings


def _missing_tags_finding(rt: str, block: TfBlock, repo_root: Path) -> IacFinding | None:
    """Return an IAC-TF-008 finding for a missing tags block or missing owner/cost_center tag."""

    tags = block.get("tags")
    if not tags or not isinstance(tags, dict):
        return _iac_finding(
            "IAC-TF-008",
            "LOW",
            f"{rt}.{block.name} has no tags block.",
            file=_block_file(repo_root, block),
            resource_type=rt,
            resource_name=block.name,
        )
    if "owner" not in tags and "cost_center" not in tags and "Owner" not in tags:
        return _iac_finding(
            "IAC-TF-008",
            "LOW",
            f"{rt}.{block.name} tags missing owner/cost_center.",
            file=_block_file(repo_root, block),
            resource_type=rt,
            resource_name=block.name,
        )
    return None


def _rule_iac_tf_008_missing_tags(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """AWS resources without any ``tags`` (or without ``owner``/``cost_center``)."""

    findings: list[IacFinding] = []
    for rt in index.types_matching("aws_"):
        # Skip *iam* and *_attachment / *_policy* — they don't accept tags universally.
        if "iam_role_policy" in rt or "_attachment" in rt:
            continue
        for block in index.resources(rt):
            finding = _missing_tags_finding(rt, block, repo_root)
            if finding is not None:
                findings.append(finding)
    return findings


def _iter_terraform_blocks(index: TfResourceIndex) -> Iterable[tuple[Path, dict[str, Any]]]:
    """Yield ``(path, terraform_block)`` for every ``terraform { ... }`` block."""

    for path, parsed in index.raw_files.items():
        terraform = parsed.get("terraform") or []
        if not isinstance(terraform, list):
            terraform = [terraform]
        for tf in terraform:
            if isinstance(tf, dict):
                yield path, tf


def _unpinned_providers(required: Any) -> list[str]:
    """Return provider names declared in ``required_providers`` without a pinned version."""

    if isinstance(required, dict):
        required = [required]
    out: list[str] = []
    for entry in required:
        if not isinstance(entry, dict):
            continue
        for provider, spec in entry.items():
            version_ = spec.get("version") if isinstance(spec, dict) else None
            if not version_:
                out.append(provider)
    return out


def _rule_iac_tf_009_unpinned_providers(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """``required_providers`` block missing or providers without a pinned version."""

    findings: list[IacFinding] = []
    for path, tf in _iter_terraform_blocks(index):
        target = _normalize_target(repo_root, path)
        required = tf.get("required_providers") or []
        if not required:
            findings.append(
                _iac_finding(
                    "IAC-TF-009",
                    "LOW",
                    f"{target}: terraform.required_providers is missing.",
                    file=target,
                    resource_type="terraform.required_providers",
                    resource_name="",
                )
            )
            continue
        for provider in _unpinned_providers(required):
            findings.append(
                _iac_finding(
                    "IAC-TF-009",
                    "LOW",
                    f"{target}: provider {provider!r} has no pinned version.",
                    file=target,
                    resource_type="terraform.required_providers",
                    resource_name=provider,
                )
            )
    return findings


def _local_backend_names(tf: dict[str, Any]) -> list[str]:
    """Return ``['local']`` when the terraform block declares a local backend, else ``[]``."""

    backend = tf.get("backend") or []
    if isinstance(backend, dict):
        backend = [backend]
    names: list[str] = []
    for entry in backend:
        if isinstance(entry, dict) and "local" in entry:
            names.append("local")
    return names


def _rule_iac_tf_010_local_backend(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """``terraform { backend "local" }`` block (or no backend at all in production layouts)."""

    findings: list[IacFinding] = []
    for path, tf in _iter_terraform_blocks(index):
        target = _normalize_target(repo_root, path)
        for backend_name in _local_backend_names(tf):
            findings.append(
                _iac_finding(
                    "IAC-TF-010",
                    "LOW",
                    f"{target}: terraform backend is 'local'; use a remote backend with encryption + locking.",
                    file=target,
                    resource_type="terraform.backend",
                    resource_name=backend_name,
                )
            )
    return findings


def _looks_prod_datastore(block: TfBlock) -> bool:
    """True when a block's name/identifier matches the production naming pattern."""

    return bool(
        _PROD_NAME_PATTERN.search(block.name)
        or _PROD_NAME_PATTERN.search(str(block.get("name") or block.get("identifier") or ""))
    )


def _prevent_destroy_enabled(block: TfBlock) -> bool:
    """True when ``lifecycle.prevent_destroy`` is explicitly ``true``."""

    lifecycle = block.get("lifecycle")
    if isinstance(lifecycle, list) and lifecycle:
        lifecycle = lifecycle[0]
    prevent = lifecycle.get("prevent_destroy") if isinstance(lifecycle, dict) else None
    return prevent is True


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
            if _looks_prod_datastore(block) and not _prevent_destroy_enabled(block):
                findings.append(
                    _iac_finding(
                        "IAC-TF-011",
                        "MEDIUM",
                        (
                            f"{rt}.{block.name} looks like a production data store "
                            "but lifecycle.prevent_destroy is not true."
                        ),
                        file=_block_file(repo_root, block),
                        resource_type=rt,
                        resource_name=block.name,
                    )
                )
    return findings


def _iter_data_entries(index: TfResourceIndex) -> Iterable[tuple[Path, dict[str, Any]]]:
    """Yield ``(path, data_block)`` for every ``data { ... }`` block dict."""

    for path, parsed in index.raw_files.items():
        data = parsed.get("data") or []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            continue
        for entry in data:
            if isinstance(entry, dict):
                yield path, entry


def _iter_iam_policy_docs(index: TfResourceIndex) -> Iterable[tuple[Path, str, dict[str, Any]]]:
    """Yield ``(path, doc_name, doc_body)`` for every ``data.aws_iam_policy_document``."""

    for path, entry in _iter_data_entries(index):
        doc_section = entry.get("aws_iam_policy_document")
        if not isinstance(doc_section, dict):
            continue
        for name, body in doc_section.items():
            if isinstance(body, dict):
                yield path, name, body


def _policy_statements(body: dict[str, Any]) -> list[dict[str, Any]]:
    statements = body.get("statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    return [s for s in statements if isinstance(s, dict)]


def _stmt_has_wildcard_principal(stmt: dict[str, Any]) -> bool:
    principals = stmt.get("principals") or []
    if isinstance(principals, dict):
        principals = [principals]
    return any(isinstance(p, dict) and "*" in (p.get("identifiers") or []) for p in principals)


def _rule_iac_tf_012_wildcard_principals(repo_root: Path, index: TfResourceIndex) -> list[IacFinding]:
    """``data.aws_iam_policy_document`` statements with ``principals.identifiers = ["*"]``.

    The HCL hcl2 6.x parser exposes ``data`` blocks under the ``data`` key in
    each parsed file. We inspect them directly because they are not part of
    the resource index.
    """

    findings: list[IacFinding] = []
    for path, name, body in _iter_iam_policy_docs(index):
        for stmt in _policy_statements(body):
            if _stmt_has_wildcard_principal(stmt):
                findings.append(
                    _iac_finding(
                        "IAC-TF-012",
                        "LOW",
                        f"data.aws_iam_policy_document.{name}: statement has wildcard principal '*'.",
                        file=_normalize_target(repo_root, path),
                        resource_type="data.aws_iam_policy_document",
                        resource_name=name,
                    )
                )
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

    by_rule: dict[str, int] = dict.fromkeys(all_rule_ids(), 0)
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
