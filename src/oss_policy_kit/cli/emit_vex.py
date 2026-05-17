"""``oss-policy-kit emit-vex`` subcommand.

v0.2 surface (v5.9.0):

- Reads OSV-Scanner SARIF output (the same evidence ``SAST-OSV-068`` consumes).
- Optionally reads ``waivers/waivers.yaml`` and applies any waiver carrying a
  ``vulnerability_ids: [...]`` field to mark matching findings as
  ``not_affected`` with the waiver justification text.
- Findings without a matching waiver default to ``state: in_triage`` — the
  neutral CycloneDX state meaning "manufacturer is analyzing".
- ``--validate`` performs structural validation against the CycloneDX VEX 1.6
  required-field set (no external schema bundle needed).
- ``--include-references`` embeds OSV / GHSA advisory URLs when the SARIF
  exposes them via rule ``helpUri`` / ``help.text``.

This subcommand intentionally does **not**:

- Generate an SBOM (use Syft / Trivy / language-native tooling).
- Verify the manufacturer's analysis (the auditor does that).
- Mutate the OSV SARIF (read-only).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

# Canonical evidence path the SAST-OSV-068 adapter consumes.
_DEFAULT_OSV_SARIF = Path(".oss-policy-kit/evidence/sast/osv-scanner.sarif.json")
_DEFAULT_WAIVERS = Path("waivers/waivers.yaml")

_VEX_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# CycloneDX 1.6 allowed enum values for analysis.justification.
_CDX_JUSTIFICATIONS: frozenset[str] = frozenset(
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compensating_control",
        "inline_mitigations_already_exist",
    }
)


@dataclass(frozen=True, slots=True)
class _VulnWaiver:
    """Per-vulnerability waiver entry from waivers/waivers.yaml.

    Distinct from the kit's main ``WaiverRecord`` (which is keyed by
    ``control_id``). This shape is local to ``emit-vex`` so that extending the
    schema does not touch the evaluation engine.
    """

    justification_text: str
    owner: str
    status: str
    expires_at: date | None
    cdx_justification: str | None  # one of _CDX_JUSTIFICATIONS or None


def _extract_sarif_data(
    sarif_path: Path,
) -> tuple[list[str], dict[str, list[str]], str | None]:
    """Return (sorted unique vulnerability IDs, ID→advisory_url list, error_or_None).

    OSV-Scanner emits one rule per vulnerability (grouped by aliases) plus an
    optional ``helpUri`` per rule pointing to the OSV / GHSA / NVD advisory.
    We collect both per ID for ``--include-references``.
    """

    try:
        raw = sarif_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], {}, f"Could not read SARIF: {exc}"
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [], {}, f"Could not parse SARIF JSON: {exc}"
    if not isinstance(doc, dict) or "runs" not in doc:
        return [], {}, "SARIF missing top-level 'runs' array."
    ids: set[str] = set()
    refs: dict[str, set[str]] = {}
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return [], {}, "SARIF 'runs' is not an array."
    for run in runs:
        if not isinstance(run, dict):
            continue
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rid = rule.get("id")
                if not isinstance(rid, str) or not rid.strip():
                    continue
                rid = rid.strip()
                ids.add(rid)
                help_uri = rule.get("helpUri")
                if isinstance(help_uri, str) and help_uri.strip():
                    refs.setdefault(rid, set()).add(help_uri.strip())
                # OSV-Scanner also embeds related URLs inside rule.help.text;
                # we keep parsing conservative and skip free-text extraction.
        results = run.get("results") or []
        if isinstance(results, list):
            for r in results:
                if not isinstance(r, dict):
                    continue
                rid = r.get("ruleId")
                if isinstance(rid, str) and rid.strip():
                    ids.add(rid.strip())
    refs_sorted = {rid: sorted(s) for rid, s in refs.items()}
    return sorted(ids), refs_sorted, None


# Backwards-compatible shim retained for callers (and tests) that loaded
# `_extract_vuln_ids_from_sarif` from v0.1.
def _extract_vuln_ids_from_sarif(sarif_path: Path) -> tuple[list[str], str | None]:
    ids, _refs, err = _extract_sarif_data(sarif_path)
    return ids, err


def _load_vuln_waivers(path: Path) -> tuple[dict[str, _VulnWaiver], list[str]]:
    """Return (vulnerability_id → waiver, warnings).

    Reads ``waivers/waivers.yaml`` (or the supplied path) and collects only
    entries that carry a ``vulnerability_ids: [...]`` field. Entries that key
    on ``control_id`` alone are ignored — they steer the evaluation gate, not
    the VEX document.
    """

    warnings: list[str] = []
    if not path.is_file():
        return {}, warnings
    try:
        raw = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not read waivers file {path}: {exc}")
        return {}, warnings
    if not isinstance(raw, dict):
        warnings.append(f"Waivers file {path} is not a YAML mapping; ignoring.")
        return {}, warnings
    entries = raw.get("waivers")
    if not isinstance(entries, list):
        return {}, warnings
    today = datetime.now(UTC).date()
    out: dict[str, _VulnWaiver] = {}
    for idx, item in enumerate(entries):
        if not isinstance(item, dict):
            continue
        vuln_ids = item.get("vulnerability_ids")
        if not isinstance(vuln_ids, list) or not vuln_ids:
            continue  # control-id-only waiver — not our concern here
        justification = str(item.get("justification", "")).strip()
        if not justification:
            warnings.append(f"Waiver entry {idx} ignored: empty justification.")
            continue
        owner = str(item.get("owner", "")).strip()
        if not owner:
            warnings.append(f"Waiver entry {idx} ignored: empty owner.")
            continue
        status = str(item.get("status", "approved")).strip() or "approved"
        expires_at_raw = item.get("expires_at")
        expires_at: date | None = None
        if isinstance(expires_at_raw, str) and expires_at_raw.strip():
            try:
                expires_at = date.fromisoformat(expires_at_raw.strip()[:10])
            except ValueError:
                warnings.append(f"Waiver entry {idx} has unparseable expires_at={expires_at_raw!r}; ignored.")
                continue
        elif isinstance(expires_at_raw, date) and not isinstance(expires_at_raw, datetime):
            expires_at = expires_at_raw
        if expires_at is not None and expires_at < today:
            warnings.append(f"Waiver entry {idx} ignored: expired at {expires_at.isoformat()}.")
            continue
        cdx_just = item.get("vex_justification")
        if isinstance(cdx_just, str):
            cdx_just = cdx_just.strip()
            if cdx_just not in _CDX_JUSTIFICATIONS:
                warnings.append(
                    f"Waiver entry {idx} has vex_justification={cdx_just!r} "
                    f"not in CycloneDX enum; field will be omitted."
                )
                cdx_just = None
        else:
            cdx_just = None
        record = _VulnWaiver(
            justification_text=justification,
            owner=owner,
            status=status,
            expires_at=expires_at,
            cdx_justification=cdx_just,
        )
        for v in vuln_ids:
            if not isinstance(v, str) or not v.strip():
                continue
            out[v.strip()] = record
    return out, warnings


def _build_vex_document(
    vuln_ids: list[str],
    source_path: Path,
    *,
    waivers: dict[str, _VulnWaiver] | None = None,
    references: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Construct a CycloneDX VEX 1.6 document with per-finding analysis.

    - Without a matching waiver: ``analysis.state = in_triage`` (default).
    - With a matching waiver: ``analysis.state = not_affected``, justification
      mapped to the CycloneDX enum when provided, free-text justification
      always copied to ``analysis.detail``.
    - With ``references`` mapping: advisory URLs (OSV record, GHSA page,
      etc.) are embedded as ``advisories[].url`` per CycloneDX VEX 1.6 shape.
    """

    waivers = waivers or {}
    references = references or {}
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    vulns: list[dict[str, Any]] = []
    for vid in vuln_ids:
        entry: dict[str, Any] = {"id": vid}
        urls = references.get(vid, [])
        if urls:
            entry["advisories"] = [{"url": u} for u in urls]
        w = waivers.get(vid)
        if w is None:
            entry["analysis"] = {
                "state": "in_triage",
                "detail": (
                    f"Imported from {source_path.as_posix()} by oss-policy-kit "
                    "emit-vex. Manufacturer analysis pending; fill in state, "
                    "justification, and response per CycloneDX VEX 1.6 vocabulary."
                ),
            }
        else:
            analysis: dict[str, Any] = {
                "state": "not_affected",
                "detail": w.justification_text,
            }
            if w.cdx_justification is not None:
                analysis["justification"] = w.cdx_justification
            entry["analysis"] = analysis
        vulns.append(entry)
    return {
        "bomFormat": _BOM_FORMAT,
        "specVersion": _VEX_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "oss-policy-kit",
                    "name": "oss-policy-kit emit-vex",
                    "version": _emit_vex_tool_version(),
                }
            ],
        },
        "vulnerabilities": vulns,
    }


# CycloneDX VEX 1.6 structural validation errors that --validate surfaces.
_CDX_ALLOWED_STATES: frozenset[str] = frozenset(
    {"resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive", "not_affected"}
)


def _validate_vex_structure(doc: dict[str, Any]) -> list[str]:
    """Return a list of structural-validation error messages (empty on success).

    Lightweight CycloneDX VEX 1.6 contract check — does NOT replace
    schema validation against the official CycloneDX JSON Schema, but
    catches the common errors (missing required fields, unknown enum
    values) without bundling the full schema.
    """

    errs: list[str] = []
    if doc.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be 'CycloneDX'")
    if doc.get("specVersion") != "1.6":
        errs.append(f"specVersion must be '1.6'; got {doc.get('specVersion')!r}")
    if doc.get("version") != 1:
        errs.append(f"version must be 1; got {doc.get('version')!r}")
    vulns = doc.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        errs.append("vulnerabilities[] must be an array")
        return errs
    for i, v in enumerate(vulns):
        if not isinstance(v, dict):
            errs.append(f"vulnerabilities[{i}] must be an object")
            continue
        if not isinstance(v.get("id"), str) or not v["id"].strip():
            errs.append(f"vulnerabilities[{i}].id missing or empty")
        analysis = v.get("analysis")
        if not isinstance(analysis, dict):
            errs.append(f"vulnerabilities[{i}].analysis missing")
            continue
        state = analysis.get("state")
        if state not in _CDX_ALLOWED_STATES:
            errs.append(f"vulnerabilities[{i}].analysis.state={state!r} not in {sorted(_CDX_ALLOWED_STATES)}")
        justification = analysis.get("justification")
        if justification is not None and justification not in _CDX_JUSTIFICATIONS:
            errs.append(
                f"vulnerabilities[{i}].analysis.justification={justification!r} not in {sorted(_CDX_JUSTIFICATIONS)}"
            )
    return errs


def _emit_vex_tool_version() -> str:
    """Return the kit's version string for embedding in the VEX metadata."""

    try:
        from oss_policy_kit import __version__ as v  # noqa: PLC0415

        return str(v)
    except ImportError:  # pragma: no cover - defensive
        return "unknown"


@app.command("emit-vex")
def emit_vex_cmd(
    osv_sarif: Path = typer.Option(
        _DEFAULT_OSV_SARIF,
        "--osv-sarif",
        help=(
            "Path to OSV-Scanner SARIF output. Defaults to "
            ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json (the path "
            "SAST-OSV-068 consumes)."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the CycloneDX VEX document. Omit for stdout.",
    ),
    waivers: Path = typer.Option(
        _DEFAULT_WAIVERS,
        "--waivers",
        help=(
            "Path to waivers/waivers.yaml. Entries carrying a "
            "vulnerability_ids: [...] field auto-populate analysis.state=not_affected "
            "for matching findings. Control-keyed waivers are ignored by emit-vex."
        ),
    ),
    validate_output: bool = typer.Option(
        False,
        "--validate/--no-validate",
        help=(
            "Structural validation against the CycloneDX VEX 1.6 required-field "
            "set. Lightweight — does not bundle the full CycloneDX JSON Schema. "
            "Errors exit 2."
        ),
    ),
    include_references: bool = typer.Option(
        False,
        "--include-references/--no-include-references",
        help=("Embed advisory URLs from OSV-Scanner SARIF rule helpUri into vulnerabilities[].advisories[]."),
    ),
) -> None:
    """Emit a CycloneDX VEX 1.6 document from OSV-Scanner SARIF.

    Findings without a matching waiver are emitted with ``analysis.state:
    in_triage``. Findings matched by a waiver carrying ``vulnerability_ids:
    [...]`` get ``state: not_affected`` plus the waiver's justification text
    (and the CycloneDX ``analysis.justification`` enum value when the waiver
    supplies ``vex_justification``).
    """

    try:
        if not osv_sarif.is_file():
            raise InvalidInputError(
                f"OSV-Scanner SARIF not found at {osv_sarif}. Run "
                "`osv-scanner --format sarif --recursive . > "
                f"{osv_sarif.as_posix()}` first."
            )
        vuln_ids, refs, err = _extract_sarif_data(osv_sarif)
        if err is not None:
            raise InvalidInputError(err)
        vuln_waivers, waiver_warnings = _load_vuln_waivers(waivers)
        for w in waiver_warnings:
            stderr_console().print(f"[yellow]Waiver warning:[/yellow] {w}")
        doc = _build_vex_document(
            vuln_ids,
            osv_sarif,
            waivers=vuln_waivers if vuln_waivers else None,
            references=refs if include_references else None,
        )
        if validate_output:
            errors = _validate_vex_structure(doc)
            if errors:
                raise InvalidInputError("CycloneDX VEX 1.6 structural validation failed:\n  - " + "\n  - ".join(errors))
        payload = json.dumps(doc, indent=2, sort_keys=False) + "\n"
        if output is None:
            write_stdout_text(payload)
        else:
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(payload, encoding="utf-8")
            except OSError as exc:
                raise InvalidInputError(f"Cannot write to --output '{output}': {exc}") from exc
            applied = sum(1 for vid in vuln_ids if vid in vuln_waivers)
            stderr_console().print(
                f"[green]Wrote CycloneDX VEX 1.6 document[/green]: "
                f"{output} ({len(vuln_ids)} vulnerability ID(s), "
                f"{applied} marked not_affected via waivers)."
            )
            # Report waiver IDs that did NOT match any SARIF finding so the
            # user can spot typos, stale waivers, or alias mismatches
            # (e.g. waiver lists CVE-2024-XYZ but SARIF carries GHSA-aaa).
            sarif_ids = set(vuln_ids)
            unmatched_waivers = [vid for vid in vuln_waivers if vid not in sarif_ids]
            if unmatched_waivers:
                preview = ", ".join(sorted(unmatched_waivers)[:10])
                more = f" (+{len(unmatched_waivers) - 10} more)" if len(unmatched_waivers) > 10 else ""
                stderr_console().print(
                    f"[yellow]Warning:[/yellow] {len(unmatched_waivers)} waiver "
                    f"vulnerability_id(s) did not match any SARIF finding: "
                    f"{preview}{more}. Check for typos or alias mismatches "
                    f"(CVE vs GHSA vs OSV vs RUSTSEC)."
                )
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
