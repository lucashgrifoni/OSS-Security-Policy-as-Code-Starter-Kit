"""Semgrep adapter: run the scanner and normalize findings to evidence.

Design constraints:

- Semgrep is **not** a hard dependency. The adapter detects whether the
  binary is on PATH and degrades gracefully (returns a structured
  ``not_available`` outcome) so users without Semgrep still get a valid
  evidence file describing the gap, not a crash.
- The subprocess invocation passes ``--json`` and uses
  ``shutil.which("semgrep")`` so we never run untrusted strings through
  a shell. ``shell=False`` is enforced by always passing a list.
- The adapter is **safe by default**: it pins the rule registry to
  ``--config auto`` (which is what most users expect from "run semgrep")
  and accepts an explicit override only via a typed parameter, never via
  free-form CLI input passthrough.
- Output schema is versioned (``oss-policy-kit/evidence/sast-semgrep/v1``)
  so downstream evaluators can rely on a stable shape independently of
  Semgrep's own JSON layout, which evolves between versions.

Why an adapter (and not a plugin):

- Semgrep is the most common SAST entry point in OSS pipelines. Hard-
  wiring an adapter (with a stable evidence contract) lets the bundled
  catalog ship a real SAST control without forcing every user to write a
  plugin. The plugin entry-point system stays available for tools the
  maintainers do not want to ship in core.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: Schema version for the normalized evidence file written to disk.
EVIDENCE_SCHEMA_VERSION = "oss-policy-kit/evidence/sast-semgrep/v1"

#: Stable evidence filename under ``.oss-policy-kit/evidence/``.
EVIDENCE_FILENAME = "sast-semgrep.json"

#: Default ruleset. ``auto`` resolves to Semgrep's curated registry pack
#: for the languages it detects in the target. Users who need stricter
#: control can pass ``rulesets=("p/owasp-top-ten",)`` or similar.
DEFAULT_RULESETS: tuple[str, ...] = ("auto",)

#: Hard upper bound on the wall-clock time we let Semgrep run before we
#: kill it. Defensive default: avoids an unresponsive scan stalling CI.
DEFAULT_TIMEOUT_SECONDS = 600


@dataclass(slots=True)
class SemgrepFinding:
    """One normalized finding ready to embed in the evidence JSON."""

    rule_id: str
    severity: str
    message: str
    file: str
    line_start: int
    line_end: int
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SemgrepRunOutcome:
    """Structured outcome of a single Semgrep run.

    Attributes:
        status: One of ``ok`` (Semgrep ran), ``not_available`` (binary not
            on PATH), ``error`` (Semgrep ran but failed), ``timeout``
            (killed by the wall-clock timer).
        version: Semgrep version string when it ran, otherwise ``None``.
        rulesets: Rulesets the adapter passed to Semgrep.
        findings: Normalized findings (empty when ``status != "ok"``).
        raw_stderr: Truncated stderr captured for diagnostics. Never
            contains secrets because we never inject them into argv.
        scanned_at: ISO 8601 UTC timestamp; useful for downstream evidence.
    """

    status: str
    version: str | None
    rulesets: list[str]
    findings: list[SemgrepFinding] = field(default_factory=list)
    raw_stderr: str = ""
    scanned_at: str = ""


def is_available() -> bool:
    """Return whether ``semgrep`` is on PATH."""

    return shutil.which("semgrep") is not None


def _semgrep_version() -> str | None:
    """Return the installed Semgrep version, or ``None`` if missing/broken."""

    binary = shutil.which("semgrep")
    if binary is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - argv is a fixed list of strings
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            shell=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return proc.stdout.strip() or None


def _now_iso_utc() -> str:
    """Current UTC time in ISO 8601 with a ``Z`` suffix."""

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_finding(raw: dict[str, Any]) -> SemgrepFinding | None:
    """Convert one Semgrep JSON record into a :class:`SemgrepFinding`.

    Returns ``None`` when the record is missing required fields rather
    than crashing the whole run; downstream code can rely on the list
    only containing well-formed entries.
    """

    rule_id = raw.get("check_id") or raw.get("rule_id")
    path = raw.get("path")
    if not isinstance(rule_id, str) or not isinstance(path, str):
        return None

    extra = raw.get("extra", {}) or {}
    severity = str(extra.get("severity", "INFO")).upper()
    message = str(extra.get("message", "")).strip()

    metadata = extra.get("metadata", {}) or {}
    cwe_raw = metadata.get("cwe", [])
    if isinstance(cwe_raw, str):
        cwe = [cwe_raw]
    elif isinstance(cwe_raw, list):
        cwe = [str(c) for c in cwe_raw if isinstance(c, str)]
    else:
        cwe = []
    owasp_raw = metadata.get("owasp", [])
    if isinstance(owasp_raw, str):
        owasp = [owasp_raw]
    elif isinstance(owasp_raw, list):
        owasp = [str(o) for o in owasp_raw if isinstance(o, str)]
    else:
        owasp = []

    start = raw.get("start", {}) or {}
    end = raw.get("end", {}) or {}
    return SemgrepFinding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        file=path,
        line_start=int(start.get("line", 0) or 0),
        line_end=int(end.get("line", 0) or 0),
        cwe=cwe,
        owasp=owasp,
    )


def _parse_semgrep_findings(stdout: str) -> list[SemgrepFinding] | None:
    """Parse Semgrep JSON stdout into findings; return None when the JSON is unparseable."""

    if not stdout.strip():
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    findings: list[SemgrepFinding] = []
    for entry in payload.get("results", []) or []:
        if isinstance(entry, dict):
            normalized = _normalize_finding(entry)
            if normalized is not None:
                findings.append(normalized)
    return findings


def run_semgrep(
    target: Path,
    *,
    rulesets: tuple[str, ...] = DEFAULT_RULESETS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> SemgrepRunOutcome:
    """Execute Semgrep against ``target`` and normalize the output.

    The function never raises for "expected" failures (missing binary,
    non-zero exit, timeout): those are encoded into ``status``. Unexpected
    OS errors are still allowed to propagate so the CLI layer can convert
    them to exit code 3.

    Args:
        target: Repository root to scan. Must be an existing directory.
        rulesets: Tuple of ``--config`` arguments passed to Semgrep.
            Defaults to ``("auto",)``.
        timeout_seconds: Wall-clock timeout for the scan.

    Returns:
        A :class:`SemgrepRunOutcome` describing the run.
    """

    if not target.is_dir():
        raise ValueError(f"Semgrep target is not a directory: {target}")

    binary = shutil.which("semgrep")
    if binary is None:
        return SemgrepRunOutcome(
            status="not_available",
            version=None,
            rulesets=list(rulesets),
            scanned_at=_now_iso_utc(),
            raw_stderr="semgrep binary not found on PATH",
        )

    argv: list[str] = [binary, "--json", "--quiet", "--error", "--metrics=off"]
    for rs in rulesets:
        argv.extend(["--config", rs])
    argv.append(str(target))

    # ``env=os.environ.copy()`` keeps the user's PATH and pip cache while
    # making it explicit that we do not pass any custom env, which is
    # easier to audit than relying on subprocess defaults.
    env = os.environ.copy()

    try:
        proc = subprocess.run(  # noqa: S603 - argv is a fixed list of strings
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return SemgrepRunOutcome(
            status="timeout",
            version=_semgrep_version(),
            rulesets=list(rulesets),
            scanned_at=_now_iso_utc(),
            raw_stderr=(exc.stderr or "")[:2000] if isinstance(exc.stderr, str) else "",
        )

    stderr_excerpt = (proc.stderr or "")[:2000]
    if proc.returncode not in {0, 1}:
        # Semgrep uses exit 1 to report findings (still a valid run). Any
        # other non-zero code means the scanner itself failed (e.g. bad
        # ruleset). Capture stderr so users have something to grep.
        return SemgrepRunOutcome(
            status="error",
            version=_semgrep_version(),
            rulesets=list(rulesets),
            scanned_at=_now_iso_utc(),
            raw_stderr=stderr_excerpt,
        )

    findings = _parse_semgrep_findings(proc.stdout)
    if findings is None:
        return SemgrepRunOutcome(
            status="error",
            version=_semgrep_version(),
            rulesets=list(rulesets),
            scanned_at=_now_iso_utc(),
            raw_stderr="Semgrep JSON output could not be parsed.",
        )

    return SemgrepRunOutcome(
        status="ok",
        version=_semgrep_version(),
        rulesets=list(rulesets),
        findings=findings,
        scanned_at=_now_iso_utc(),
        raw_stderr=stderr_excerpt,
    )


def render_evidence_payload(
    outcome: SemgrepRunOutcome,
    *,
    target: Path,
) -> dict[str, Any]:
    """Build the evidence JSON dict from a run outcome.

    The resulting dict is the on-disk shape consumed by the
    ``SAST-SEMGREP-064`` evaluator. Keys are sorted alphabetically by
    :func:`json.dumps(..., sort_keys=True)` later, so order here is for
    human readability only.
    """

    counts_by_severity: dict[str, int] = {}
    for f in outcome.findings:
        counts_by_severity[f.severity] = counts_by_severity.get(f.severity, 0) + 1

    # GOV-EVIDFRESH-054 expects every evidence file to carry usable freshness
    # metadata (`attested_at` or `collected_at`) plus an attestation hint
    # (`attested_by`). We emit both so the file behaves like other bundled
    # evidence artifacts even when Semgrep itself was unavailable.
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": "semgrep",
        "tool_version": outcome.version,
        "status": outcome.status,
        "rulesets": list(outcome.rulesets),
        "target": str(target.resolve()),
        "scanned_at": outcome.scanned_at,
        "attested_at": outcome.scanned_at,
        "attested_by": "oss-policy-kit scan-sast",
        "findings_total": len(outcome.findings),
        "findings_by_severity": counts_by_severity,
        "findings": [asdict(f) for f in outcome.findings],
        "diagnostics": {
            "raw_stderr_excerpt": outcome.raw_stderr,
        },
    }


def write_evidence(
    payload: dict[str, Any],
    *,
    repo_root: Path,
    filename: str = EVIDENCE_FILENAME,
) -> Path:
    """Write *payload* to ``.oss-policy-kit/evidence/<filename>``.

    Returns the absolute path written. The directory is created on demand.
    """

    target_dir = repo_root / ".oss-policy-kit" / "evidence"
    target_dir.mkdir(parents=True, exist_ok=True)
    out = target_dir / filename
    out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return out.resolve()
