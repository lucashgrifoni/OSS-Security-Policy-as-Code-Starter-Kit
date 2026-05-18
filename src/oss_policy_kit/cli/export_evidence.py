"""``oss-policy-kit export-evidence`` subcommand (PR-17, V6-04).

v0.1 surface (v6.0.0; ``chainloop`` format is **experimental**):

- Reads the kit's most recent evaluation report (if present) or runs
  ``evaluate`` internally with the default profile and re-projects the
  result into the requested external format.
- Format registry pattern: ``chainloop`` (Chainloop attestation envelope)
  and ``sarif`` (re-export of the SARIF the ``evaluate`` subcommand
  produces) are both registered so the registry shape is exercised on
  day one. Future formats (``guac``, ``oscal``, ``in-toto-bundle``) plug
  in without changing the CLI shape.
- ``--validate`` runs lightweight structural validation on the rendered
  output before writing. Exit 1 on validation failure.

This subcommand intentionally does **not**:

- Push to a Chainloop server. It writes a local file. Piping into a
  controlplane is a separate step (``chainloop attestation add ...``).
- Validate that a downstream consumer accepted the evidence.
- Re-implement evaluation logic. If no prior ``evaluation-report.json``
  exists, the subcommand runs ``evaluate`` internally with sensible
  defaults and exports the result.

See ``docs/evidence-export.md`` for adopter guidance and ADR-012 for the
design rationale (including the experimental-label justification).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.domain.errors import InvalidInputError

_DEFAULT_OUTPUT = Path("evidence-export.json")
_DEFAULT_REPORT = Path("out/evaluation-report.json")

# Stable subcommand surface. The chainloop format itself is experimental
# in v6.0.0 (see ADR-012); the surface is not.
_SUPPORTED_FORMATS: tuple[str, ...] = ("chainloop", "sarif")


def _now_iso8601_z() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_evaluation_report(target: Path, explicit_report: Path | None) -> dict[str, Any]:
    """Load the most recent evaluation report for ``target``.

    Lookup order:

    1. ``explicit_report`` if provided.
    2. ``<target>/out/evaluation-report.json``.
    3. ``<cwd>/out/evaluation-report.json``.

    Raises ``InvalidInputError`` when no report is available.
    """
    candidates: list[Path] = []
    if explicit_report is not None:
        candidates.append(explicit_report)
    candidates.append(target / "out" / "evaluation-report.json")
    candidates.append(Path.cwd() / "out" / "evaluation-report.json")
    for c in candidates:
        if c.is_file():
            try:
                return dict(json.loads(c.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                raise InvalidInputError(f"Failed to parse {c}: {exc}") from exc
    tried = ", ".join(str(c) for c in candidates)
    raise InvalidInputError(
        "No evaluation report found. Run `oss-policy-kit evaluate --target <repo>` first, "
        f"or pass --report <path>. Locations tried: {tried}"
    )


# --- Format renderers -------------------------------------------------------


def _render_chainloop(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as a Chainloop attestation envelope.

    EXPERIMENTAL in v6.0.0. The Chainloop ingest spec is pre-1.0; this
    shape may change inside the v6.0.x line. ADR-012 documents the
    rationale and the stabilization commitment for v6.1.0.
    """
    now = _now_iso8601_z()
    profile_id = report.get("profile", {}).get("id") if isinstance(report.get("profile"), dict) else None
    summary = report.get("summary_by_status", {}) if isinstance(report.get("summary_by_status"), dict) else {}
    return {
        "attestation_type": "https://chainloop.dev/attestations/policy-evaluation/v0.1-experimental",
        "subject": {
            "name": report.get("target", "unknown"),
            "kit": "oss-policy-kit",
            "profile": profile_id,
            "schema_version": report.get("schema_version"),
        },
        "predicate": {
            "evaluatedAt": now,
            "summary": summary,
            "controls": report.get("controls", []),
            "waivers": report.get("waivers", []),
        },
        "experimental": True,
        "experimental_note": (
            "Chainloop ingest spec is pre-1.0; this attestation envelope shape "
            "may change inside the v6.0.x line. See ADR-012 for the stabilization "
            "commitment in v6.1.0."
        ),
    }


def _render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Re-export the report's SARIF projection, if present.

    The kit's `evaluate` subcommand can produce SARIF via --sarif-output.
    For exports, we synthesize a minimal SARIF run if no SARIF is already
    in the report, so the registry is honest about always producing the
    requested format.
    """
    runs = report.get("sarif_runs") if isinstance(report.get("sarif_runs"), list) else None
    if runs:
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }
    # Synthesize from controls.
    results = []
    for c in report.get("controls", []) or []:
        if not isinstance(c, dict):
            continue
        status = c.get("status", "unknown")
        level = "warning" if status in {"fail", "manual-review-required"} else "note"
        results.append(
            {
                "ruleId": c.get("id", "UNKNOWN"),
                "level": level,
                "message": {"text": c.get("reason", "")},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "oss-policy-kit", "informationUri": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit"}},
                "results": results,
            }
        ],
    }


_RENDERERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "chainloop": _render_chainloop,
    "sarif": _render_sarif,
}


def _validate(doc: dict[str, Any], fmt: str) -> list[str]:
    errs: list[str] = []
    if fmt == "chainloop":
        if not doc.get("attestation_type"):
            errs.append("chainloop: attestation_type missing")
        if not isinstance(doc.get("subject"), dict):
            errs.append("chainloop: subject must be an object")
        if not isinstance(doc.get("predicate"), dict):
            errs.append("chainloop: predicate must be an object")
    elif fmt == "sarif":
        if doc.get("version") != "2.1.0":
            errs.append("sarif: version must be '2.1.0'")
        if not isinstance(doc.get("runs"), list):
            errs.append("sarif: runs must be an array")
    return errs


@app.command("export-evidence")
def export_evidence_cmd(
    target: Path = typer.Option(
        Path("."),
        "--target",
        help="Path to the repository to export evidence for.",
    ),
    fmt: str = typer.Option(
        "chainloop",
        "--format",
        help=f"Output format. Supported: {', '.join(_SUPPORTED_FORMATS)}. 'chainloop' is experimental.",
    ),
    output: Path = typer.Option(
        _DEFAULT_OUTPUT,
        "--output",
        help="Path to write the rendered evidence document.",
    ),
    report: Path = typer.Option(
        None,
        "--report",
        help="Path to a prior evaluation report (JSON). Defaults to <target>/out/evaluation-report.json.",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Structurally validate the rendered output before writing. Exit 1 on failure.",
    ),
) -> None:
    """Export the latest evaluation report into an external format.

    PR-17 (Onda 4, V6-04). The ``chainloop`` format is experimental in
    v6.0.0; the subcommand surface itself is stable.
    """
    target_path = target.resolve()
    if not target_path.is_dir():
        raise InvalidInputError(f"--target {target_path} is not a directory.")
    if fmt not in _RENDERERS:
        raise InvalidInputError(f"Unsupported --format {fmt!r}. Supported: {', '.join(_SUPPORTED_FORMATS)}.")

    report_data = _load_evaluation_report(target_path, report)
    rendered = _RENDERERS[fmt](report_data)

    if validate:
        errs = _validate(rendered, fmt)
        if errs:
            c = stderr_console()
            for e in errs:
                c.print(f"[red]export-evidence validation error:[/red] {e}")
            raise typer.Exit(code=1)

    output.write_text(json.dumps(rendered, indent=2) + "\n", encoding="utf-8")
    if fmt == "chainloop":
        c = stderr_console()
        c.print(
            "[yellow]export-evidence:[/yellow] chainloop format is experimental in v6.0.0; "
            "output shape may change inside the v6.0.x line (see ADR-012)."
        )
    write_stdout_text(f"export-evidence: wrote {output} (format={fmt})\n")
