"""Bicep rule pack and evidence writer (v5.7.0).

Bicep is a declarative DSL that compiles to ARM JSON. The Microsoft
``bicep`` CLI is not always available in CI runners, and there is no
stable Python AST library for Bicep. This scanner uses a **bounded
regex-based tokenizer** that extracts ``resource <symbolic> '<type>@<ver>'
= { ... }`` declarations and the literal properties block, then runs the
6 bundled rules on those literal property keys.

The tokenizer is **best-effort by design**: nested complex expressions
(parameter references, string interpolation, conditions) are treated as
opaque and never cause a rule to flag (no false positives from unresolved
references). When the kit cannot determine a value, the rule skips it.

The 6 bundled rules cover the highest-leverage clone-visible Bicep
posture gaps for Azure: public storage, open NSG management ports, broad
Azure role assignments, missing encryption-at-rest, no diagnostic
settings, and accidental public IPs.
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

EVIDENCE_SCHEMA_VERSION = "oss-policy-kit/evidence/iac-bicep/v1"
EVIDENCE_FILENAME = "iac-bicep.json"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = ("**/*.bicep",)

_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".terraform", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".oss-policy-kit"}
)

_MANAGEMENT_PORTS: frozenset[int] = frozenset({22, 3389, 3306, 5432, 1433, 6379, 27017, 9200})

# Match: resource <symbolic> '<provider>/<type>@<api>' = { ...body... }
# Captures the symbolic name and the type@apiVersion, then the matching braces.
_RESOURCE_RE = re.compile(
    r"resource\s+([A-Za-z_][A-Za-z0-9_]*)\s+'([^']+)'\s*=\s*",
    re.MULTILINE,
)


@dataclass(slots=True)
class BicepFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    resource_type: str
    resource_name: str


@dataclass(slots=True)
class BicepResource:
    symbolic: str
    type_full: str  # "Microsoft.Storage/storageAccounts@2023-01-01"
    body: str
    source: Path


@dataclass(slots=True)
class BicepScanOutcome:
    status: str
    tool_version: str | None
    files_scanned: list[str] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    findings: list[BicepFinding] = field(default_factory=list)
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


def _walk_bicep_files(
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


def _balanced_block(text: str, brace_start: int) -> str:
    """Return the body between matching braces starting at ``brace_start`` (``{``)."""

    if brace_start >= len(text) or text[brace_start] != "{":
        return ""
    depth = 0
    i = brace_start
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start + 1 : i]
        elif ch == "'":
            # Skip single-quoted string literal to avoid counting braces inside.
            i += 1
            while i < len(text) and text[i] != "'":
                if text[i] == "\\":
                    i += 1
                i += 1
        i += 1
    return text[brace_start + 1 :]


def _parse_resources(text: str, source: Path) -> list[BicepResource]:
    """Extract every ``resource ... = { ... }`` declaration from a Bicep file."""

    resources: list[BicepResource] = []
    for m in _RESOURCE_RE.finditer(text):
        # Find the next '{' after the match (skipping whitespace).
        brace_pos = text.find("{", m.end())
        if brace_pos < 0:
            continue
        body = _balanced_block(text, brace_pos)
        resources.append(
            BicepResource(
                symbolic=m.group(1),
                type_full=m.group(2),
                body=body,
                source=source,
            )
        )
    return resources


def _type_root(r: BicepResource) -> str:
    """Return ``Microsoft.Storage/storageAccounts`` from ``Microsoft.Storage/storageAccounts@2023-01-01``."""

    return r.type_full.split("@", 1)[0]


def _body_has(r: BicepResource, key: str, *values: str) -> bool:
    """True if ``r.body`` contains a ``key: <val>`` pair where ``<val>`` is one of ``values``.

    Accepts both bare identifiers (``Allow``) and quoted literals (``'*'``,
    ``'0.0.0.0/0'``). Non-literal expressions (parameter references, string
    interpolation) are ignored — they evaluate to ``None`` here, which is
    the conservative "indeterminate" outcome.
    """

    # Two passes: quoted-string literals first (broadest character class),
    # then bare identifier-like values.
    quoted = re.compile(rf"\b{re.escape(key)}\s*:\s*'([^']*)'")
    bare = re.compile(rf"\b{re.escape(key)}\s*:\s*([A-Za-z0-9._-]+)\b")
    if any(hit.group(1) in values for hit in quoted.finditer(r.body)):
        return True
    return any(hit.group(1) in values for hit in bare.finditer(r.body))


def _body_has_bool(r: BicepResource, key: str) -> bool | None:
    """Return literal boolean of ``key: true|false`` or None if not present / non-literal."""

    pattern = re.compile(rf"\b{re.escape(key)}\s*:\s*(true|false)\b")
    m = pattern.search(r.body)
    if not m:
        return None
    return m.group(1) == "true"


def _body_has_int_range(r: BicepResource, key: str) -> tuple[int, int] | None:
    """Match ``key: <int>`` or ``key: '<int>-<int>'`` (Azure NSG style ``destinationPortRange``)."""

    pattern = re.compile(rf"\b{re.escape(key)}\s*:\s*'?(\d+)(?:-(\d+))?'?")
    m = pattern.search(r.body)
    if not m:
        return None
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    return (lo, hi)


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------


def _rule_iac_bicep_001_public_storage(repo_root: Path, resources: list[BicepResource]) -> list[BicepFinding]:
    findings: list[BicepFinding] = []
    for r in resources:
        if _type_root(r) != "Microsoft.Storage/storageAccounts":
            continue
        # allowBlobPublicAccess literal true is the canonical "public blob" signal.
        if _body_has_bool(r, "allowBlobPublicAccess") is True:
            findings.append(
                BicepFinding(
                    rule_id="IAC-BICEP-001",
                    severity="HIGH",
                    message=f"{_type_root(r)} {r.symbolic!r} has allowBlobPublicAccess=true.",
                    file=_normalize_target(repo_root, r.source),
                    resource_type=_type_root(r),
                    resource_name=r.symbolic,
                )
            )
            continue
        # publicNetworkAccess: 'Enabled' is the broader signal.
        if _body_has(r, "publicNetworkAccess", "Enabled"):
            findings.append(
                BicepFinding(
                    rule_id="IAC-BICEP-001",
                    severity="MEDIUM",
                    message=f"{_type_root(r)} {r.symbolic!r} has publicNetworkAccess='Enabled'.",
                    file=_normalize_target(repo_root, r.source),
                    resource_type=_type_root(r),
                    resource_name=r.symbolic,
                )
            )
    return findings


def _rule_iac_bicep_002_open_mgmt_ports(repo_root: Path, resources: list[BicepResource]) -> list[BicepFinding]:
    findings: list[BicepFinding] = []
    for r in resources:
        # NSG security rules ship as nested children. We look for the literal
        # destinationPortRange + sourceAddressPrefix combo.
        if _type_root(r) not in {
            "Microsoft.Network/networkSecurityGroups",
            "Microsoft.Network/networkSecurityGroups/securityRules",
        }:
            continue
        if not _body_has(r, "access", "Allow"):
            continue
        if not _body_has(r, "direction", "Inbound"):
            continue
        if not _body_has(r, "sourceAddressPrefix", "*", "0.0.0.0/0", "Internet"):
            continue
        port_range = _body_has_int_range(r, "destinationPortRange")
        if port_range is None:
            continue
        lo, hi = port_range
        for port in _MANAGEMENT_PORTS:
            if lo <= port <= hi:
                findings.append(
                    BicepFinding(
                        rule_id="IAC-BICEP-002",
                        severity="HIGH",
                        message=(
                            f"{_type_root(r)} {r.symbolic!r}: NSG rule allows {lo}-{hi} inbound "
                            f"from '*' covering management port {port}."
                        ),
                        file=_normalize_target(repo_root, r.source),
                        resource_type=_type_root(r),
                        resource_name=r.symbolic,
                    )
                )
                break
    return findings


# Built-in Azure role definition IDs that grant broad write access.
_HIGH_PRIV_ROLE_IDS: tuple[str, ...] = (
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
)


def _rule_iac_bicep_003_broad_role(repo_root: Path, resources: list[BicepResource]) -> list[BicepFinding]:
    findings: list[BicepFinding] = []
    for r in resources:
        if _type_root(r) != "Microsoft.Authorization/roleAssignments":
            continue
        body = r.body
        for role_id in _HIGH_PRIV_ROLE_IDS:
            if role_id in body:
                findings.append(
                    BicepFinding(
                        rule_id="IAC-BICEP-003",
                        severity="HIGH",
                        message=(
                            f"Microsoft.Authorization/roleAssignments {r.symbolic!r} binds high-privilege "
                            f"built-in role definition {role_id}."
                        ),
                        file=_normalize_target(repo_root, r.source),
                        resource_type=_type_root(r),
                        resource_name=r.symbolic,
                    )
                )
                break
    return findings


def _rule_iac_bicep_004_no_encryption(repo_root: Path, resources: list[BicepResource]) -> list[BicepFinding]:
    findings: list[BicepFinding] = []
    for r in resources:
        t = _type_root(r)
        if t == "Microsoft.Storage/storageAccounts":
            # Storage accounts encrypt by default but users sometimes disable
            # `supportsHttpsTrafficOnly: false` (related but distinct).
            if _body_has_bool(r, "supportsHttpsTrafficOnly") is False:
                findings.append(
                    BicepFinding(
                        rule_id="IAC-BICEP-004",
                        severity="MEDIUM",
                        message=f"{t} {r.symbolic!r} has supportsHttpsTrafficOnly=false (plaintext traffic allowed).",
                        file=_normalize_target(repo_root, r.source),
                        resource_type=t,
                        resource_name=r.symbolic,
                    )
                )
        elif t == "Microsoft.Sql/servers/databases":
            # Look for transparentDataEncryption block or its 'state: Enabled' literal.
            if not _body_has(r, "state", "Enabled"):
                findings.append(
                    BicepFinding(
                        rule_id="IAC-BICEP-004",
                        severity="MEDIUM",
                        message=f"{t} {r.symbolic!r} has no transparentDataEncryption.state='Enabled' literal.",
                        file=_normalize_target(repo_root, r.source),
                        resource_type=t,
                        resource_name=r.symbolic,
                    )
                )
        elif (
            t == "Microsoft.Compute/disks"
            and _body_has_bool(r, "encryptionSettings") is None
            and "diskEncryptionSetId" not in r.body
        ):
            findings.append(
                BicepFinding(
                    rule_id="IAC-BICEP-004",
                    severity="MEDIUM",
                    message=f"{t} {r.symbolic!r} has no encryptionSettings or diskEncryptionSetId.",
                    file=_normalize_target(repo_root, r.source),
                    resource_type=t,
                    resource_name=r.symbolic,
                )
            )
    return findings


def _rule_iac_bicep_005_no_diag(repo_root: Path, resources: list[BicepResource]) -> list[BicepFinding]:
    findings: list[BicepFinding] = []
    has_diag: set[str] = set()
    for r in resources:
        if _type_root(r).endswith("/providers/diagnosticSettings") or _type_root(r).endswith(
            "Microsoft.Insights/diagnosticSettings"
        ):
            # Capture scope name in scope: '<name>' literal so we can match later.
            m = re.search(r"scope\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", r.body)
            if m:
                has_diag.add(m.group(1))
    for r in resources:
        if _type_root(r) not in {
            "Microsoft.Storage/storageAccounts",
            "Microsoft.KeyVault/vaults",
            "Microsoft.Sql/servers",
        }:
            continue
        if r.symbolic in has_diag:
            continue
        findings.append(
            BicepFinding(
                rule_id="IAC-BICEP-005",
                severity="LOW",
                message=(
                    f"{_type_root(r)} {r.symbolic!r} has no paired Microsoft.Insights/diagnosticSettings resource."
                ),
                file=_normalize_target(repo_root, r.source),
                resource_type=_type_root(r),
                resource_name=r.symbolic,
            )
        )
    return findings


def _rule_iac_bicep_006_public_ip(repo_root: Path, resources: list[BicepResource]) -> list[BicepFinding]:
    findings: list[BicepFinding] = []
    for r in resources:
        if _type_root(r) != "Microsoft.Network/publicIPAddresses":
            continue
        # A bare publicIPAddresses resource is a finding unless the body says
        # publicIPAllocationMethod is 'Static' and is explicitly bound via a
        # Private Endpoint -- which we cannot determine from a clone. So we
        # flag every direct public IP declaration as an explicit-intent prompt.
        findings.append(
            BicepFinding(
                rule_id="IAC-BICEP-006",
                severity="MEDIUM",
                message=f"Microsoft.Network/publicIPAddresses {r.symbolic!r} declared; ensure intent is documented.",
                file=_normalize_target(repo_root, r.source),
                resource_type=_type_root(r),
                resource_name=r.symbolic,
            )
        )
    return findings


_RuleFn = Callable[[Path, list[BicepResource]], list[BicepFinding]]

_RULES: tuple[tuple[str, _RuleFn], ...] = (
    ("IAC-BICEP-001", _rule_iac_bicep_001_public_storage),
    ("IAC-BICEP-002", _rule_iac_bicep_002_open_mgmt_ports),
    ("IAC-BICEP-003", _rule_iac_bicep_003_broad_role),
    ("IAC-BICEP-004", _rule_iac_bicep_004_no_encryption),
    ("IAC-BICEP-005", _rule_iac_bicep_005_no_diag),
    ("IAC-BICEP-006", _rule_iac_bicep_006_public_ip),
)


def all_rule_ids() -> tuple[str, ...]:
    return tuple(rid for rid, _ in _RULES)


def run_scan(
    repo_root: Path,
    *,
    include_globs: Iterable[str] = DEFAULT_INCLUDE_GLOBS,
    exclude_globs: Iterable[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> BicepScanOutcome:
    _ = timeout_seconds
    files = _walk_bicep_files(repo_root, include_globs, exclude_globs)
    resources: list[BicepResource] = []
    files_scanned: list[Path] = []
    parse_errors: list[dict[str, str]] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            parse_errors.append({"file": _normalize_target(repo_root, f), "error": str(exc)})
            continue
        files_scanned.append(f)
        resources.extend(_parse_resources(text, f))

    findings: list[BicepFinding] = []
    try:
        for _rid, fn in _RULES:
            findings.extend(fn(repo_root, resources))
    except Exception as exc:  # noqa: BLE001 - rule engine errors must not crash the scan
        return BicepScanOutcome(
            status="error",
            tool_version=_kit_version(),
            files_scanned=[_normalize_target(repo_root, f) for f in files_scanned],
            parse_errors=parse_errors,
            findings=[],
            scanned_at=_utc_iso(),
            diagnostics=f"rule engine raised {type(exc).__name__}: {exc}",
        )
    return BicepScanOutcome(
        status="ok",
        tool_version=_kit_version(),
        files_scanned=[_normalize_target(repo_root, f) for f in files_scanned],
        parse_errors=parse_errors,
        findings=findings,
        scanned_at=_utc_iso(),
    )


def render_evidence_payload(outcome: BicepScanOutcome, *, target: Path) -> dict[str, Any]:
    by_rule: dict[str, int] = {rid: 0 for rid in all_rule_ids()}
    by_severity: dict[str, int] = {}
    for f in outcome.findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": "oss-policy-kit-bicep-parser",
        "tool_version": outcome.tool_version,
        "status": outcome.status,
        "target": str(target.resolve()),
        "scanned_at": outcome.scanned_at,
        "attested_at": outcome.scanned_at,
        "attested_by": "oss-policy-kit scan-bicep",
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
