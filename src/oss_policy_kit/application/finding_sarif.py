"""Normalize the external SARIF drops into the ADR-030 finding model (A-S3).

Reads the four user-dropped SARIF files under ``.oss-policy-kit/evidence/sast/``
(zizmor, poutine, osv-scanner, gitleaks) and projects each SARIF result into a
:class:`NormalizedFinding` — KEEPING per-result physicalLocation and message
(the control evaluators' generic adapter only tallies level counts and discards
them) plus the structured EPSS/KEV/CVSS enrichment properties the osv-scanner
SARIF may carry.

Reuses the hardened SARIF primitives from the evaluators layer (the
``MAX_SARIF_BYTES`` cap and the nesting-depth guard) instead of growing another
set that could drift — the uncapped duplicate loaders were a confirmed v9.0.x
defect class. Only the *decoding* differs: this layer reads ``utf-8-sig``
because the drops are user-supplied files and most Windows tools write UTF-8
with a BOM; a BOM used to make json.loads reject the whole document, so every
finding in the drop disappeared while the ``--fail-on-severity`` gate stayed
green.

Attribution follows the document, not the filename: when ``tool.driver.name``
positively identifies a *different* known scanner (a Trivy report saved as
``gitleaks.sarif.json``), the findings carry that scanner's name and the
:class:`SourceRecord` is demoted to ``error`` with no version, so nothing in the
artifact asserts that the slot's scanner ran.

Severity (x-severity-map/v1): the generic SARIF table maps result levels
``error/warning/note/none`` → ``high/medium/info/unknown`` with the SARIF-spec
fallback chain (result.level → rule defaultConfiguration.level → warning).
zizmor's richer ``properties.security_severity_level`` vocabulary maps
Critical..Informational → critical..info. ``PER_TOOL_SEVERITY_OVERRIDES`` is a
documented, deliberately EMPTY slot: the kit's own gate posture never rewrites
a source tool's severity (scope-gate demand D4) — gitleaks therefore maps via
the generic table (warning → medium).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, NamedTuple

from oss_policy_kit.application.evaluators._shared import (
    _MAX_SARIF_JSON_DEPTH,
    _max_json_nesting_depth,
    _sarif_rule_levels,
)
from oss_policy_kit.application.input_limits import MAX_SARIF_BYTES, oversize_reason
from oss_policy_kit.domain.findings import (
    FindingLocation,
    FindingSource,
    NormalizedFinding,
    SeverityView,
    SourceRecord,
)

#: Registry of the four external SARIF sources: (filename, tool label).
#: Adding a source (e.g. a Trivy/Grype drop in v10.1) is a data-registration
#: change here plus, at most, a PER_TOOL_SEVERITY_OVERRIDES row — never a
#: schema change (binding design requirement from the v10 plan).
SARIF_SOURCES: tuple[tuple[str, str], ...] = (
    ("zizmor.sarif.json", "zizmor"),
    ("poutine.sarif.json", "poutine"),
    ("osv-scanner.sarif.json", "osv-scanner"),
    ("gitleaks.sarif.json", "gitleaks"),
)

_SARIF_DIR = Path(".oss-policy-kit") / "evidence" / "sast"

# Generic SARIF result-level table (x-severity-map/v1).
_SARIF_LEVEL_PAIRS: tuple[tuple[str, str], ...] = (
    ("error", "high"),
    ("warning", "medium"),
    ("note", "info"),
    ("none", "unknown"),
)
_SARIF_LEVEL: dict[str, str] = dict(_SARIF_LEVEL_PAIRS)

# zizmor's own vocabulary via result.properties.security_severity_level.
_ZIZMOR_SEVERITY_PAIRS: tuple[tuple[str, str], ...] = (
    ("CRITICAL", "critical"),
    ("HIGH", "high"),
    ("MEDIUM", "medium"),
    ("LOW", "low"),
    ("INFORMATIONAL", "info"),
    ("UNKNOWN", "unknown"),
)
_ZIZMOR_SEVERITY: dict[str, str] = dict(_ZIZMOR_SEVERITY_PAIRS)

#: Documented per-tool override slot — EMPTY by design in x-severity-map/v1.
#: The kit never rewrites a source tool's severity to match its own gate
#: posture (D4); a row here requires a map-version bump and a contract note.
PER_TOOL_SEVERITY_OVERRIDES: dict[str, dict[str, str]] = {}

_VULN_ID_PREFIXES = ("CVE-", "GHSA-", "PYSEC-", "OSV-", "RUSTSEC-", "GO-")

#: Scanner identities the kit can recognize in ``tool.driver.name``, keyed by the
#: name reduced to alphanumerics. A drop whose driver names one of these but NOT
#: the tool its filename implies is a proven mis-file, so the artifact must not
#: credit the filename's scanner. A generic or vendor-custom driver name (an
#: in-house wrapper, a bare "tool") proves nothing and is left with its slot.
_DRIVER_IDENTITY_PAIRS: tuple[tuple[str, str], ...] = (
    ("zizmor", "zizmor"),
    ("poutine", "poutine"),
    ("osvscanner", "osv-scanner"),
    ("osv", "osv-scanner"),
    ("gitleaks", "gitleaks"),
    # Other common SARIF producers, so their output landing in a registry slot
    # is caught instead of silently re-badged as the slot's scanner.
    ("trivy", "trivy"),
    ("grype", "grype"),
    ("semgrep", "semgrep"),
    ("snyk", "snyk"),
    ("snykcode", "snyk"),
    ("snykopensource", "snyk"),
    ("checkov", "checkov"),
    ("kics", "kics"),
    ("tfsec", "tfsec"),
    ("codeql", "codeql"),
    ("bandit", "bandit"),
    ("gosec", "gosec"),
    ("hadolint", "hadolint"),
    ("trufflehog", "trufflehog"),
    ("checkmarx", "checkmarx"),
)
_DRIVER_IDENTITY: dict[str, str] = dict(_DRIVER_IDENTITY_PAIRS)

#: A driver name is echoed into every finding of the drop; cap it so a hostile
#: or corrupt document cannot bloat the artifact through that field.
_MAX_DRIVER_NAME_CHARS = 64
#: Bounds on target-controlled location text entering `extensions.partial_scan_warnings`.
_MAX_EXTRA_LOCATIONS_NAMED = 10
_MAX_LOCATION_URI_CHARS = 200

#: SARIF result kinds that are NOT failures. ``kind`` defaults to "fail" when
#: absent (SARIF 2.1.0 §3.27.9), and "review"/"open" mean the tool has not
#: decided — dropping those would hide real work, so only these two are skipped.
_NON_FINDING_KINDS = frozenset({"pass", "notapplicable"})


def _load_runs(path: Path) -> tuple[list[Any] | None, str | None]:
    """Read + validate a user-dropped SARIF file, returning ``(runs, None)`` or ``(None, error)``.

    Decodes as ``utf-8-sig`` so the BOM that most Windows tools write does not
    turn a whole drop into unparseable JSON. The size cap is applied by the
    caller and the nesting-depth guard is the shared evaluator one, so neither
    hardening step can drift from the evaluate path. Every failure is returned,
    never raised: a corrupt drop is recorded as unread, it is not an exit 3.
    """

    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return None, f"Could not read SARIF file: {exc}"
    except UnicodeDecodeError as exc:
        return None, f"Could not decode SARIF file as UTF-8: {exc}"
    if _max_json_nesting_depth(raw) > _MAX_SARIF_JSON_DEPTH:
        return None, "Could not parse SARIF JSON: document is too deeply nested."
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Could not parse SARIF JSON: {exc}"
    except RecursionError as exc:  # pragma: no cover - the depth guard above refuses first
        # Unreachable while `too_deep_reason` runs before `json.loads`, and kept because
        # it is the only thing standing between a deeply nested document and an exit-3
        # crash if that ordering is ever changed.
        return None, f"Could not parse SARIF JSON: document is too deeply nested ({exc})"
    if not isinstance(doc, dict):
        return None, "SARIF file missing top-level 'runs' array."
    # str() before endswith: a non-string "$schema" is malformed input, not a crash.
    if "runs" not in doc and not str(doc.get("$schema", "")).endswith("sarif-schema-2.1.0.json"):
        return None, "SARIF file missing top-level 'runs' array."
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return None, "SARIF 'runs' is not an array."
    return runs, None


def normalize_sarif_level(level: str) -> str:
    """Map a SARIF result level to the normalized vocabulary (else ``unknown``)."""

    return _SARIF_LEVEL.get(level.strip().lower(), "unknown")


def _safe_float(raw: Any, *, lo: float | None = None, hi: float | None = None) -> float | None:
    """Parse a numeric SARIF property to float, dropping anything that would poison the artifact.

    Returns ``None`` for non-numeric input, for non-finite values (``NaN``/``inf``
    would serialize as invalid JSON ``NaN``/``Infinity`` in findings/1.0 and the
    ``--format json`` view), and for values outside ``[lo, hi]`` when bounds are
    given. Mirrors the enrichment clamp in
    ``finding_correlation._effective_signals`` so a garbage EPSS/CVSS cannot warp
    ranking or break the artifact.
    """

    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value):
        return None
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        return None
    return value


def _resolved_level(result: dict[str, Any], rule_levels: dict[str, str]) -> str:
    """SARIF-spec fallback chain: result.level -> rule default level -> warning."""

    level = result.get("level")
    if isinstance(level, str) and level.strip():
        return level.strip().lower()
    rid = result.get("ruleId")
    if isinstance(rid, str) and rid in rule_levels:
        return rule_levels[rid].strip().lower()
    return "warning"


def _location(result: dict[str, Any]) -> FindingLocation:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return FindingLocation()
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict):
        return FindingLocation()
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    raw_region = physical.get("region")
    region: dict[str, Any] = raw_region if isinstance(raw_region, dict) else {}
    start = region.get("startLine")
    end = region.get("endLine")
    return FindingLocation(
        file=str(uri) if isinstance(uri, str) and uri else None,
        line_start=start if isinstance(start, int) and start > 0 else None,
        line_end=end if isinstance(end, int) and end > 0 else None,
    )


def _extra_location_uris(result: dict[str, Any]) -> list[str]:
    """The files named by ``locations[1:]`` -- the ones a single FindingLocation cannot hold.

    SARIF 2.1.0 §3.27.12 makes ``result.locations`` the set of places the result was detected,
    so entries after the first are affected files, not decoration. Bounded the same way
    ``_foreign_driver`` bounds a driver name: this is target-controlled text on its way into a
    published artifact.
    """

    locations = result.get("locations")
    if not isinstance(locations, list) or len(locations) < 2:
        return []
    uris: list[str] = []
    # Same pairing as the caller, and for the same reason: `cleaned not in uris` rescanned a
    # growing list per location, so one result naming a monorepo cost O(locations^2) a second
    # time. This one dominated -- 8.7s of the 19.16s measured, in its own frame.
    seen: set[str] = set()
    for entry in locations[1:]:
        if not isinstance(entry, dict):
            continue
        physical = entry.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        uri = artifact.get("uri") if isinstance(artifact, dict) else None
        if not isinstance(uri, str):
            continue
        # Strip C0 controls before the string can reach a Markdown cell or a terminal.
        cleaned = "".join(ch for ch in uri.strip() if ch.isprintable())[:_MAX_LOCATION_URI_CHARS]
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            uris.append(cleaned)
    return uris


def sarif_partial_location_warnings(repo_root: Path) -> list[str]:
    """Name the affected files that the findings artifact cannot represent, per SARIF drop.

    ``_location`` keeps ``locations[0]`` and a finding holds exactly one file, so a result
    naming three files is published as one finding naming one of them. Measured through the
    CLI: the other two appear in no field of the artifact, and the command exits 0.

    This is the same loss ``finding_normalization.kit_evidence_partial_scan_warnings``
    already reports for kit evidence, and its docstring carries the full argument -- a closed
    ``sources_read[].status`` enum cannot hold the fact, ``extensions`` is the contract's
    sanctioned place for it, and ``--fail-on-severity`` gates pipelines on a count that is
    quietly incomplete without it.

    Deliberately does NOT change ``findings_total`` or the primary location. Whether a
    multi-location result should instead become one finding per location is a semantic
    question about the published contract, recorded as a product decision rather than
    settled here.
    """

    warnings: list[str] = []
    for filename, _tool in SARIF_SOURCES:
        dropped = _dropped_locations_in_drop(repo_root / _SARIF_DIR / filename, filename)
        if not dropped:
            continue
        shown = dropped[:_MAX_EXTRA_LOCATIONS_NAMED]
        listed = ", ".join(shown)
        if len(dropped) > len(shown):
            listed += f", and {len(dropped) - len(shown)} more"
        warnings.append(
            f"{filename}: results in this drop name further affected file(s) that a finding "
            f"cannot carry, so they are absent from findings[] and from findings_total: {listed}."
        )
    return warnings


def _dropped_locations_in_drop(path: Path, filename: str) -> list[str]:
    """Every extra location one SARIF drop names, in document order, deduplicated.

    Silent on anything it cannot read. A drop that is missing, oversize or unparseable is
    already reported through ``sources_read`` by :func:`normalize_sarif_sources`; saying it
    twice, in a field about a different problem, would be noise. Returning ``[]`` here never
    claims the drop was fine.
    """

    if not path.is_file():
        return []
    if oversize_reason(path, MAX_SARIF_BYTES, label=filename) is not None:
        return []
    runs, err = _load_runs(path)
    if err is not None or runs is None:
        return []
    dropped: list[str] = []
    # Membership in a set, order in the list. `uri not in dropped` rescanned a growing list for
    # every location, so one rule reported across a monorepo cost O(locations^2): 50,000 distinct
    # files in a 3.84 MiB drop took 19.16s, and the drop is well inside the 20 MiB cap, so nothing
    # refused it. Order is kept because the warning names the first ten and counts the rest -- a
    # set alone would make which ten an adopter sees depend on hashing.
    seen: set[str] = set()
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict) or _is_non_finding(result):
                continue
            for uri in _extra_location_uris(result):
                if uri not in seen:
                    seen.add(uri)
                    dropped.append(uri)
    return dropped


def _vulnerability_ids(rule: str, props: dict[str, Any]) -> tuple[str, ...]:
    """Collect verbatim vulnerability ids (no alias resolution in findings/1.0)."""

    seen: list[str] = []
    for candidate in (rule, props.get("cve"), props.get("id")):
        if not isinstance(candidate, str):
            continue
        token = candidate.strip()
        if token.upper().startswith(_VULN_ID_PREFIXES) and token not in seen:
            seen.append(token)
    return tuple(seen)


def _normalize_result(
    tool: str, rel_path: str, result: dict[str, Any], rule_levels: dict[str, str]
) -> NormalizedFinding:
    rule = str(result.get("ruleId") or "")
    message_obj = result.get("message")
    message = str(message_obj.get("text") or "") if isinstance(message_obj, dict) else ""
    raw_props = result.get("properties")
    props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else {}

    level = _resolved_level(result, rule_levels)
    zizmor_severity = props.get("security_severity_level")
    if tool == "zizmor" and isinstance(zizmor_severity, str) and zizmor_severity.strip():
        severity_original = zizmor_severity.strip()
        normalized = _ZIZMOR_SEVERITY.get(severity_original.upper(), normalize_sarif_level(level))
    else:
        severity_original = level
        normalized = normalize_sarif_level(level)

    kev_flag = props.get("kev")
    kev_str = kev_flag.strip().lower() if isinstance(kev_flag, str) else ""
    kev: bool | None = None
    if "kev" in props:
        kev = kev_flag in (True, 1) or kev_str in {"true", "yes", "1"}

    native_id = None
    for key in ("cve", "id"):
        value = props.get(key)
        if isinstance(value, str) and value.strip():
            native_id = value.strip()
            break

    return NormalizedFinding(
        id="",
        sources=(
            FindingSource(
                tool=tool,
                source_path=rel_path,
                rule=rule,
                severity_original=severity_original,
                message=message,
                native_id=native_id,
            ),
        ),
        rule=rule,
        message=message,
        severity=SeverityView(normalized=normalized, by_source=((tool, severity_original),)),
        location=_location(result),
        vulnerability_ids=_vulnerability_ids(rule, props),
        # EPSS is a probability in [0.0, 1.0]; CVSS base scores fall in [0.0, 10.0].
        # Bounds + the finite guard keep a garbage source value from warping ranking
        # or writing invalid JSON (Infinity/NaN) into the artifact.
        epss=_safe_float(props.get("epss_score", props.get("epss")), lo=0.0, hi=1.0),
        kev=kev,
        cvss=_safe_float(props.get("cvss_score", props.get("security-severity")), lo=0.0, hi=10.0),
    )


def _driver(run: dict[str, Any]) -> dict[str, Any]:
    """Return the run's ``tool.driver`` object, or an empty dict for any other shape."""

    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    return driver if isinstance(driver, dict) else {}


def _driver_version(driver: dict[str, Any]) -> str | None:
    """Return the driver's semanticVersion/version if present, else None."""

    version = driver.get("semanticVersion") or driver.get("version")
    return version.strip() if isinstance(version, str) and version.strip() else None


def _foreign_driver(driver: dict[str, Any], expected_tool: str) -> str | None:
    """Return ``tool.driver.name`` when the run positively identifies another scanner.

    ``None`` means "no proof of a mis-file": either the driver agrees with the
    slot, or its name is one the kit cannot resolve to a scanner (an in-house
    wrapper), in which case the filename convention stays authoritative.
    """

    name = driver.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    identity = _DRIVER_IDENTITY.get("".join(ch for ch in name.lower() if ch.isalnum()))
    if identity is None or identity == expected_tool:
        return None
    return name.strip()[:_MAX_DRIVER_NAME_CHARS]


def _is_non_finding(result: dict[str, Any]) -> bool:
    """True for results the SARIF spec marks as passing or not applicable.

    Such results carry no failure — counting them turned a clean scan into a
    FAIL and exit 1. Absent ``kind`` means "fail" per the spec, so the default
    stays a finding.
    """

    kind = result.get("kind")
    return isinstance(kind, str) and kind.strip().lower() in _NON_FINDING_KINDS


class _Projection(NamedTuple):
    """One drop's findings plus the honesty flags its SourceRecord must carry."""

    findings: list[NormalizedFinding]
    tool_version: str | None
    container_invalid: bool
    foreign_driver: str | None


def _normalize_results(
    results: list[Any],
    attributed_to: str,
    rel: str,
    rule_levels: dict[str, str],
) -> list[NormalizedFinding]:
    """Normalize one run's ``results`` array, dropping entries that are not findings.

    A non-dict entry is skipped rather than raised on: a single malformed result in an
    otherwise-readable drop should not cost the caller the whole file.
    """

    return [
        _normalize_result(attributed_to, rel, result, rule_levels)
        for result in results
        if isinstance(result, dict) and not _is_non_finding(result)
    ]


def _project_runs(runs: list[Any], tool: str, rel: str) -> _Projection:
    """Project every run's results into findings.

    ``container_invalid`` is True when any run carries a ``results`` key that is
    present but not a list (the results CONTAINER itself is malformed) — the
    caller demotes the record to ``error`` so a corrupt drop is distinguishable
    from a genuinely-empty one. A run with no ``results`` key, or with
    ``results: []``, stays honestly ``ok``. ``foreign_driver`` carries the name of
    the scanner that actually produced the drop when it is not the one the
    filename implies; its findings are attributed to it, never to the slot.
    """

    findings: list[NormalizedFinding] = []
    tool_version: str | None = None
    container_invalid = False
    foreign_driver: str | None = None
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = _driver(run)
        if tool_version is None:
            tool_version = _driver_version(driver)
        if foreign_driver is None:
            foreign_driver = _foreign_driver(driver, tool)
        results = run.get("results")
        if not isinstance(results, list):
            if "results" in run:
                container_invalid = True
            continue
        # The shared helper walks tool.driver.rules unguarded; only hand it a run
        # whose driver really is an object, so a malformed one degrades instead
        # of raising through correlate-findings as an exit 3.
        rule_levels = _sarif_rule_levels(run) if driver else {}
        findings.extend(_normalize_results(results, foreign_driver or tool, rel, rule_levels))
    return _Projection(findings, tool_version, container_invalid, foreign_driver)


def normalize_sarif_sources(repo_root: Path) -> tuple[list[NormalizedFinding], list[SourceRecord]]:
    """Project the four external SARIF drops under *repo_root* into findings.

    Deterministic (registry order, in-document result order). Missing, oversize,
    and unreadable files contribute an honest :class:`SourceRecord` and no
    findings — never a failure.
    """

    findings: list[NormalizedFinding] = []
    records: list[SourceRecord] = []
    for filename, tool in SARIF_SOURCES:
        rel = (_SARIF_DIR / filename).as_posix()
        path = repo_root / _SARIF_DIR / filename
        if not path.is_file():
            records.append(SourceRecord(path=rel, kind="external-sarif", tool=tool, status="missing"))
            continue
        if oversize_reason(path, MAX_SARIF_BYTES, label=filename) is not None:
            records.append(SourceRecord(path=rel, kind="external-sarif", tool=tool, status="oversize"))
            continue
        runs, err = _load_runs(path)
        if err is not None or runs is None:
            records.append(SourceRecord(path=rel, kind="external-sarif", tool=tool, status="unreadable"))
            continue
        projection = _project_runs(runs, tool, rel)
        findings.extend(projection.findings)
        status = "error" if (projection.container_invalid or projection.foreign_driver) else "ok"
        records.append(
            SourceRecord(
                path=rel,
                kind="external-sarif",
                tool=tool,
                status=status,
                # A foreign document's version would read as "<slot tool> <version>":
                # never state a version for a scanner that did not produce this drop.
                tool_version=None if projection.foreign_driver else projection.tool_version,
            )
        )
    return findings, records


__all__ = [
    "PER_TOOL_SEVERITY_OVERRIDES",
    "SARIF_SOURCES",
    "normalize_sarif_level",
    "normalize_sarif_sources",
    "sarif_partial_location_warnings",
]
