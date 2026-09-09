"""Heuristics for suggesting bundled profiles from repository layout."""

from __future__ import annotations

import importlib.resources as ir
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# --- Which evidence filenames the kit itself writes and reads ----------------
#
# The invariant this section exists to hold: every filename `scaffold-evidence`
# writes, `collect-evidence` writes, `scan-*` writes, or an evaluator reads must
# be RECOGNIZED here. When it is not, `recommend-profile` tells the adopter the
# file "will be ignored by evaluate" and offers to remove it -- destructive
# advice about evidence the kit produced itself. v10.0.6 fixed exactly one such
# filename by appending a string (sast-semgrep.json) and left two more broken
# (github-actions-policy.json, github-release-immutability.json), which is why
# the set is now DERIVED instead of hand-listed.
#
# Source of truth: one `evidence-<name>.schema.json` ships per bundled evidence
# document, and every writer/reader of `<name>.json` validates against it. A new
# evidence document therefore becomes recognized the moment its schema is added,
# with no second list to remember.
_EVIDENCE_SCHEMA_PACKAGE = "oss_policy_kit.data.schema"
_EVIDENCE_SCHEMA_PREFIX = "evidence-"
_EVIDENCE_SCHEMA_SUFFIX = ".schema.json"


#: The note `recommend-profile` emits when nothing in the clone points at a platform and the
#: GitHub baseline is therefore the fallback. Named rather than inlined because `init` has to
#: recognise it: with `--platform gitlab` the chosen profile is `gitlab-level-1`, and printing
#: "defaulting to a conservative GitHub baseline profile" underneath told the reader their gate
#: was running a profile it was not. Matching a re-typed copy of the sentence would have gone
#: stale the first time the wording changed.
FEW_SIGNALS_FALLBACK_NOTE = (
    "Few strong platform signals were detected; defaulting to a conservative GitHub baseline profile."
)


def schema_backed_evidence_filenames() -> frozenset[str]:
    """Return ``{"<name>.json", ...}`` for every bundled ``evidence-<name>.schema.json``."""

    try:
        entries = list(ir.files(_EVIDENCE_SCHEMA_PACKAGE).iterdir())
    except (OSError, ModuleNotFoundError, TypeError, ValueError):
        # An unusual packaging layout must degrade to the static floor below,
        # never to "every evidence file the kit wrote is unrecognized".
        return frozenset()
    return frozenset(
        f"{e.name[len(_EVIDENCE_SCHEMA_PREFIX) : -len(_EVIDENCE_SCHEMA_SUFFIX)]}.json"
        for e in entries
        if e.name.startswith(_EVIDENCE_SCHEMA_PREFIX) and e.name.endswith(_EVIDENCE_SCHEMA_SUFFIX)
    )


#: Evidence documents an evaluator reads that ship NO bundled JSON Schema: third-party
#: formats the kit ingests as-is, or documents checked structurally. Filenames that do
#: have a schema must never be added here -- they are discovered automatically.
UNSCHEMAED_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "scorecard.json",  # OpenSSF Scorecard result (OSPS conformance fallback)
        "scorecard-osps.json",  # `scorecard --format=osps` conformance output
        "llm-release-integrity.json",  # LLM-218A-PS-001
        "mcp-tool-descriptions.json",  # MCP-TOOL-HASH-001
    }
)

#: Last-resort floor for the case where the bundled schema directory cannot be
#: enumerated. Every entry here is also schema-backed, so on a normal install this
#: set is fully redundant with the derivation above; it only keeps a broken
#: packaging layout from regressing to destructive "remove them" advice.
_EVIDENCE_FILENAME_FLOOR: frozenset[str] = frozenset(
    {
        "branch-protection.json",
        "github-rulesets.json",
        "github-environment-protection.json",
        "github-secret-scanning.json",
        "github-provenance-artifact.json",
        "github-actions-policy.json",
        "github-release-immutability.json",
        "org-mfa-posture.json",
        "runner-groups.json",
        "gitlab-mr-rules.json",
        "azure-branch-policies.json",
        "azure-pipeline-governance.json",
        "azure-sbom-artifact.json",
        "azure-provenance-artifact.json",
        "aws-codebuild-project.json",
        "aws-codepipeline.json",
        "aws-sbom-artifact.json",
        "aws-provenance-artifact.json",
        "audit-log-streaming.json",
        "disclosure-policy.json",
        "k8s-baseline.json",
        "release-archival-policy.json",
        "iac-terraform.json",
        "iac-bicep.json",
        "iac-cfn.json",
        "iac-pulumi.json",
        "sast-semgrep.json",
    }
)

#: A recognized filename is routed to a platform bucket by its prefix; that is the
#: same naming rule the collectors and scaffold templates already follow.
_PLATFORM_FILENAME_PREFIXES: tuple[tuple[str, str], ...] = (
    ("github", "github-"),
    ("gitlab", "gitlab-"),
    ("azure", "azure-"),
    ("aws", "aws-"),
)

#: Recognized filenames with no platform prefix that still belong to a platform
#: bucket. branch-protection.json and org-mfa-posture.json are platform-agnostic
#: (the GitLab collector emits them too) and stay under GitHub to preserve the
#: historical partition behavior.
_GITHUB_BUCKET_EXTRA: frozenset[str] = frozenset(
    {
        "branch-protection.json",
        "org-mfa-posture.json",
        "runner-groups.json",
    }
)


def _evidence_bucket(name: str) -> str:
    """Return the platform bucket (``github``/``gitlab``/``azure``/``aws``/``generic``)."""

    if name in _GITHUB_BUCKET_EXTRA:
        return "github"
    for platform, prefix in _PLATFORM_FILENAME_PREFIXES:
        if name.startswith(prefix):
            return platform
    return "generic"


def recognized_evidence_filenames() -> frozenset[str]:
    """Every evidence filename the kit writes or reads under ``.oss-policy-kit/evidence/``."""

    return schema_backed_evidence_filenames() | _EVIDENCE_FILENAME_FLOOR | UNSCHEMAED_EVIDENCE_FILENAMES


def _evidence_bucket_names(platform: str) -> frozenset[str]:
    return frozenset(n for n in recognized_evidence_filenames() if _evidence_bucket(n) == platform)


GITHUB_EVIDENCE_FILENAMES: frozenset[str] = _evidence_bucket_names("github")
GITLAB_EVIDENCE_FILENAMES: frozenset[str] = _evidence_bucket_names("gitlab")
AZURE_EVIDENCE_FILENAMES: frozenset[str] = _evidence_bucket_names("azure")
AWS_EVIDENCE_FILENAMES: frozenset[str] = _evidence_bucket_names("aws")
#: Platform-agnostic evidence consumed by controls that apply everywhere
#: (governance, IaC, K8s, SAST, AI). Recognized, but not a platform signal.
GENERIC_EVIDENCE_FILENAMES: frozenset[str] = _evidence_bucket_names("generic")


# M-003 (v6.0.0, ADR-008): schema_version becomes an absolute URL.
# The legacy shorthand is accepted by internal consumers for one minor
# (v6.0.x) so adopters that string-match the value have time to migrate.
PROFILE_RECOMMENDATION_V2_SCHEMA_URL = "https://schemas.lucashgrifoni.io/oss-policy-kit/recommend-profile/v2.json"
PROFILE_RECOMMENDATION_V2_LEGACY_SHORTHAND = "oss-policy-kit/profile-recommendation/v2"


@dataclass(slots=True)
class ProfileRecommendation:
    """Structured profile hints for CLI and automation."""

    schema_version: str = PROFILE_RECOMMENDATION_V2_SCHEMA_URL
    signals_detected: list[dict[str, str]] = field(default_factory=list)
    suggestions: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        """Serialize for JSON stdout (includes schema_version and nested structures)."""

        return asdict(self)


def _workflow_yaml_paths(repo_root: Path) -> list[Path]:
    root = repo_root.resolve()
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    paths: list[Path] = []
    for p in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        try:
            resolved = p.resolve()
        except OSError:
            continue
        if not resolved.is_file():
            continue
        if not resolved.is_relative_to(root):
            # Guard against symlink escapes that would leak signals from outside --target.
            continue
        paths.append(resolved)
    return paths


def _gitlab_ci_paths(repo_root: Path) -> list[Path]:
    """Return GitLab CI definition paths (root ``.gitlab-ci.yml`` or under ``.gitlab/``)."""

    seen: set[Path] = set()
    paths: list[Path] = []
    for parent in (repo_root, repo_root / ".gitlab"):
        for name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
            p = parent / name
            if p.is_file() and p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def _azure_pipeline_paths(repo_root: Path) -> list[Path]:
    patterns = [
        "azure-pipelines*.yml",
        "azure-pipelines*.yaml",
        "pipelines/azure/*.yml",
        "pipelines/azure/*.yaml",
        ".azure-pipelines/*.yml",
        ".azure-pipelines/*.yaml",
    ]
    seen: set[Path] = set()
    paths: list[Path] = []
    for pattern in patterns:
        for p in sorted(repo_root.glob(pattern)):
            # The six globs above are mutually exclusive, so the duplicate arm is not
            # reachable today; the guard is what keeps that true if one is widened.
            if p not in seen:  # pragma: no branch
                seen.add(p)
                paths.append(p)
    return paths


def _evidence_json_paths(repo_root: Path) -> list[Path]:
    ev = repo_root / ".oss-policy-kit" / "evidence"
    if not ev.is_dir():
        return []
    return sorted(p for p in ev.glob("*.json") if p.is_file())


def _partition_evidence_json(
    ev_json: list[Path],
) -> tuple[list[Path], list[Path], list[Path], list[Path], list[Path]]:
    """Partition discovered evidence JSON paths into (github, gitlab, azure, aws, unrecognized).

    Generic / cross-platform bundled filenames (disclosure-policy.json,
    audit-log-streaming.json, release-archival-policy.json, iac-*.json,
    k8s-baseline.json) are RECOGNIZED as bundled and therefore do NOT land
    in the unrecognized bucket — they are consumed by controls that aren't
    tied to a specific CI platform.
    """
    github: list[Path] = []
    gitlab: list[Path] = []
    azure: list[Path] = []
    aws: list[Path] = []
    other: list[Path] = []
    for p in ev_json:
        name = p.name
        if name in GITHUB_EVIDENCE_FILENAMES:
            github.append(p)
        elif name in GITLAB_EVIDENCE_FILENAMES:
            gitlab.append(p)
        elif name in AZURE_EVIDENCE_FILENAMES:
            azure.append(p)
        elif name in AWS_EVIDENCE_FILENAMES:
            aws.append(p)
        elif name in GENERIC_EVIDENCE_FILENAMES:
            # Bundled & cross-platform; skip the unrecognized signal entirely.
            continue
        else:
            other.append(p)
    return github, gitlab, azure, aws, other


def _append_signal(signals: list[dict[str, str]], sig_id: str, detail: str) -> None:
    signals.append({"id": sig_id, "detail": detail})


_CONTAINER_SIGNAL_ID = "container_docker"


def _detect_container_stack(repo_root: Path, found: list[dict[str, str]]) -> bool:
    """Append a container signal when a Dockerfile/compose is present; return prefer-L2 flag."""

    if (
        (repo_root / "Dockerfile").is_file()
        or (repo_root / "docker-compose.yml").is_file()
        or (repo_root / "docker-compose.yaml").is_file()
    ):
        _append_signal(
            found,
            _CONTAINER_SIGNAL_ID,
            "Container workload detected via Dockerfile or docker-compose.",
        )
        return True
    return False


# How strongly a marker file says "this repository *is* this stack". A manifest that
# declares the project outranks one that is as often a sidecar: a bare package.json
# belongs to a docs site or a tooling folder at least as often as to the project
# itself, which is how a Python repository used to be reported as "your Node.js
# project". A committed lockfile is what proves the tree is really installed as Node.
_STACK_WEIGHT_DECLARES_PROJECT = 3
_STACK_WEIGHT_MAY_BE_SIDECAR = 2

#: Stack display labels, named once. Repeating them meant a typo in any single copy
#: would split one stack into two the ranking treats as unrelated, with nothing failing.
_LABEL_PYTHON = "Python"
_LABEL_NODE = "Node.js"
_LABEL_GO = "Go"
_LABEL_JAVA_MAVEN = "Java/Maven"
_LABEL_JAVA_GRADLE = "Java/Kotlin (Gradle)"
_LABEL_RUST = "Rust"
_LABEL_DOTNET = "C#/.NET"

# Stable display order for stacks tied on weight, so the rationale is deterministic.
_STACK_LABEL_ORDER: tuple[str, ...] = (
    _LABEL_PYTHON,
    _LABEL_NODE,
    _LABEL_GO,
    _LABEL_JAVA_MAVEN,
    _LABEL_JAVA_GRADLE,
    _LABEL_RUST,
    _LABEL_DOTNET,
)

_NODE_LOCKFILE_NOTE = "Add package-lock.json or yarn.lock to enable reproducible builds."

#: Signal id -> the stack label it identifies. Consumers that must pick ONE stack
#: (``init`` writes ``detected.primary_stack``) read the FIRST such signal out of
#: ``signals_detected``, so this mapping plus :func:`_stack_evidence_order` is what
#: makes "first" and "strongest" the same thing.
_STACK_SIGNAL_LABELS: dict[str, str] = {
    "node_js": _LABEL_NODE,
    "python_pyproject": _LABEL_PYTHON,
    "python_requirements": _LABEL_PYTHON,
    "python_setup": _LABEL_PYTHON,
    "go_module": _LABEL_GO,
    "java_maven": _LABEL_JAVA_MAVEN,
    "java_gradle": _LABEL_JAVA_GRADLE,
    "rust_cargo": _LABEL_RUST,
    "dotnet_csproj": _LABEL_DOTNET,
}

#: Signals that qualify a stack without identifying it; they trail their own stack.
_STACK_QUALIFIER_SIGNALS: dict[str, str] = {"node_lockfile": _LABEL_NODE}

#: Public: signal id -> human label, for consumers that need to *name* the detected stack
#: rather than rank it. Composed from the two definitions above so there is one place to edit.
#:
#: `_STACK_SIGNAL_LABELS` deliberately excludes the container signal, which `_rank_stack_signals`
#: handles separately as packaging rather than a language. A caller that only wants a label still
#: needs it, and `init_planner` used to carry its own copy of this dict to get one -- which had
#: already drifted: it knew `container_docker` while this module knew `node_lockfile`, so the two
#: answers disagreed depending on which one you asked.
STACK_LABEL_BY_SIGNAL_ID: dict[str, str] = {
    **_STACK_SIGNAL_LABELS,
    _CONTAINER_SIGNAL_ID: "Container (Docker)",
}


def _detect_node_stack(
    repo_root: Path, found: list[dict[str, str]], weights: dict[str, int] | None = None
) -> str | None:
    """Append Node.js signals; return the stack label or None. Records its weight in *weights*."""

    if not (repo_root / "package.json").is_file():
        return None
    has_lockfile = any((repo_root / name).is_file() for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"))
    _append_signal(
        found,
        "node_js",
        (
            "Node.js project detected via package.json"
            if has_lockfile
            else "package.json found without a lockfile (may be a tooling or docs sidecar rather than the project)"
        ),
    )
    if has_lockfile:
        _append_signal(found, "node_lockfile", "Node lockfile present (reproducible installs).")
    if weights is not None:
        weights[_LABEL_NODE] = _STACK_WEIGHT_DECLARES_PROJECT if has_lockfile else _STACK_WEIGHT_MAY_BE_SIDECAR
    return _LABEL_NODE


def _append_pyproject_tooling_notes(pyproject: Path, notes: list[str]) -> None:
    """Note the quality tooling declared in *pyproject*, if it can be read at all.

    An unreadable file yields no notes rather than an error: the stack was already
    identified by the file's existence, and the notes are advisory.
    """

    try:
        body = pyproject.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    lowered = body.lower()
    if "[tool.ruff]" in body or "[tool.ruff." in body or "ruff>" in lowered:
        notes.append("Ruff is configured under pyproject.toml - align CI quality gates with the same rules.")
    if "[tool.mypy]" in body or "python -m mypy" in lowered:
        notes.append("Mypy is referenced - keep static type checks in CI for stronger supply-chain posture.")


def _detect_python_stack(
    repo_root: Path,
    found: list[dict[str, str]],
    notes: list[str],
    weights: dict[str, int] | None = None,
) -> str | None:
    """Append Python signals/notes; return the stack label or None. Records its weight in *weights*."""

    if (repo_root / "pyproject.toml").is_file():
        _append_signal(found, "python_pyproject", "Python project detected via pyproject.toml")
        if weights is not None:
            weights[_LABEL_PYTHON] = _STACK_WEIGHT_DECLARES_PROJECT
        _append_pyproject_tooling_notes(repo_root / "pyproject.toml", notes)
        return _LABEL_PYTHON
    if (repo_root / "requirements.txt").is_file():
        _append_signal(found, "python_requirements", "Python project detected via requirements.txt")
        if weights is not None:
            # Pinned dependencies alone; the file is often vendored beside another stack.
            weights[_LABEL_PYTHON] = _STACK_WEIGHT_MAY_BE_SIDECAR
        return _LABEL_PYTHON
    if (repo_root / "setup.py").is_file() or (repo_root / "setup.cfg").is_file():
        _append_signal(found, "python_setup", "Python project detected via setup.py/setup.cfg")
        if weights is not None:
            weights[_LABEL_PYTHON] = _STACK_WEIGHT_DECLARES_PROJECT
        return _LABEL_PYTHON
    return None


# (marker filenames, primary label, signal id, signal detail) for single-file stacks.
_SIMPLE_STACK_MARKERS: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
    (("go.mod",), _LABEL_GO, "go_module", "Go module detected via go.mod"),
    (("pom.xml",), _LABEL_JAVA_MAVEN, "java_maven", "Java/Maven project detected via pom.xml"),
    (
        ("build.gradle", "build.gradle.kts"),
        _LABEL_JAVA_GRADLE,
        "java_gradle",
        "Java/Kotlin project detected via build.gradle",
    ),
    (("Cargo.toml",), _LABEL_RUST, "rust_cargo", "Rust project detected via Cargo.toml"),
)


def _detect_simple_stacks(
    repo_root: Path,
    found: list[dict[str, str]],
    primary: str | None,
    weights: dict[str, int] | None = None,
) -> str | None:
    """Append signals for single-file language markers; return the first primary label seen."""

    for markers, label, sig_id, detail in _SIMPLE_STACK_MARKERS:
        if any((repo_root / m).is_file() for m in markers):
            primary = primary or label
            _append_signal(found, sig_id, detail)
            if weights is not None:
                weights[label] = _STACK_WEIGHT_DECLARES_PROJECT
    if list(repo_root.glob("*.csproj")) or list(repo_root.glob("*.sln")):
        primary = primary or _LABEL_DOTNET
        _append_signal(found, "dotnet_csproj", "C#/.NET project detected via .csproj or .sln")
        if weights is not None:
            weights[_LABEL_DOTNET] = _STACK_WEIGHT_DECLARES_PROJECT
    return primary


def _rank_stack_labels(weights: dict[str, int]) -> list[str]:
    """Every detected stack, strongest evidence first, ties in stable display order."""

    def sort_key(label: str) -> tuple[int, int, str]:
        order = _STACK_LABEL_ORDER.index(label) if label in _STACK_LABEL_ORDER else len(_STACK_LABEL_ORDER)
        return (-weights[label], order, label)

    return sorted(weights, key=sort_key)


def _primary_stacks(weights: dict[str, int]) -> list[str]:
    """Return every stack tied for the strongest signal, in a stable display order."""

    ranked = _rank_stack_labels(weights)
    if not ranked:
        return []
    strongest = weights[ranked[0]]
    return [label for label in ranked if weights[label] == strongest]


def _stack_evidence_order(found: list[dict[str, str]], weights: dict[str, int]) -> list[dict[str, str]]:
    """Re-emit stack signals strongest-evidence-first, keeping every other signal in place.

    ``signals_detected`` is the only ranking a consumer sees, and a consumer that
    must name ONE stack takes the first entry that maps to one. Detection order
    used to decide that: the Node detector ran first, so a Python repository with
    a sidecar ``package.json`` was announced as a Node.js project even though the
    weighting had already ranked Python above it.
    """

    rank = {label: position for position, label in enumerate(_rank_stack_labels(weights))}
    unranked = len(rank)

    def sort_key(item: tuple[int, dict[str, str]]) -> tuple[int, int, int, int]:
        index, signal = item
        sid = signal["id"]
        if sid == _CONTAINER_SIGNAL_ID:
            # Packaging, not language: keeps its historical lead position.
            return (0, 0, 0, index)
        label = _STACK_SIGNAL_LABELS.get(sid)
        if label is not None:
            return (1, rank.get(label, unranked), 0, index)
        qualified = _STACK_QUALIFIER_SIGNALS.get(sid)
        if qualified is not None:
            return (1, rank.get(qualified, unranked), 1, index)
        return (2, 0, 0, index)

    return [signal for _index, signal in sorted(enumerate(found), key=sort_key)]


def _multi_stack_note(ranked: list[str]) -> list[str]:
    """Note naming every detected stack in rank order (empty for 0/1 stack)."""

    if len(ranked) <= 1:
        return []
    return [
        (
            f"Multiple language stacks detected (ranked by evidence strength: {', '.join(ranked)}). "
            "A single primary stack is recorded for convenience; it does not mean the other "
            "stacks were ignored."
        )
    ]


def _collect_tech_stack_signals(
    repo_root: Path,
) -> tuple[list[dict[str, str]], list[str], bool, str | None]:
    """Detect common language/runtime markers; returns signals, notes, Dockerfile->L2 flag, primary stack label."""

    found: list[dict[str, str]] = []
    notes: list[str] = []
    weights: dict[str, int] = {}
    prefer_l2 = _detect_container_stack(repo_root, found)
    _detect_node_stack(repo_root, found, weights)
    # Every detector runs: first-match-wins used to short-circuit the rest, so a repo
    # with both markers lost the weaker-listed stack from signals_detected entirely.
    _detect_python_stack(repo_root, found, notes, weights)
    _detect_simple_stacks(repo_root, found, None, weights)

    found = _stack_evidence_order(found, weights)
    primary_stacks = _primary_stacks(weights)
    signal_ids = {s["id"] for s in found}
    if _LABEL_NODE in primary_stacks and "node_lockfile" not in signal_ids:
        # Only advise a lockfile when Node is what the repository actually is; on a
        # sidecar package.json this reads as advice for somebody else's project.
        notes.append(_NODE_LOCKFILE_NOTE)
    notes.extend(_multi_stack_note(_rank_stack_labels(weights)))
    return found, notes, prefer_l2, " / ".join(primary_stacks) or None


def _platform_order(
    *,
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[str]:
    """Return github, gitlab, azure, aws ordered with the most strongly indicated platform first."""

    def weight(name: str) -> int:
        if name == "github":
            return 100 * len(github_ev) + 40 * bool(wf_paths)
        if name == "gitlab":
            return 100 * len(gitlab_ev) + 40 * bool(gl_paths)
        if name == "azure":
            return 100 * len(azure_ev) + 40 * bool(az_paths)
        return 100 * len(aws_ev) + 40 * bool(buildspec)

    present = [p for p in ("github", "gitlab", "azure", "aws") if weight(p) > 0]
    return sorted(present, key=lambda n: (-weight(n), n))


def _collect_signals(
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
    other_ev: list[Path],
) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    if wf_paths:
        _append_signal(
            signals,
            "github_actions_workflows",
            f"Found {len(wf_paths)} workflow file(s) under .github/workflows/.",
        )
    if gl_paths:
        _append_signal(
            signals,
            "gitlab_ci_yaml",
            f"Found {len(gl_paths)} GitLab CI file(s) (.gitlab-ci.yml at root or under .gitlab/).",
        )
    if az_paths:
        _append_signal(
            signals,
            "azure_pipelines_yaml",
            f"Found {len(az_paths)} Azure Pipelines file(s) in supported paths.",
        )
    if buildspec:
        _append_signal(signals, "aws_codebuild_buildspec", "Found buildspec.yml / buildspec.yaml at root.")

    if ev_dir.is_dir() and not ev_json:
        _append_signal(
            signals,
            "evidence_dir_empty",
            ".oss-policy-kit/evidence/ exists but no *.json files yet.",
        )

    if github_ev:
        names = ", ".join(sorted(p.name for p in github_ev))
        _append_signal(
            signals,
            "github_evidence_json_files",
            f"Found {len(github_ev)} GitHub-shaped evidence JSON file(s): {names}",
        )
    if azure_ev:
        names = ", ".join(sorted(p.name for p in azure_ev))
        _append_signal(
            signals,
            "azure_evidence_json_files",
            f"Found {len(azure_ev)} Azure-shaped evidence JSON file(s): {names}",
        )
    if gitlab_ev:
        names = ", ".join(sorted(p.name for p in gitlab_ev))
        _append_signal(
            signals,
            "gitlab_evidence_json_files",
            f"Found {len(gitlab_ev)} GitLab-shaped evidence JSON file(s): {names}",
        )
    if aws_ev:
        names = ", ".join(sorted(p.name for p in aws_ev))
        _append_signal(
            signals,
            "aws_evidence_json_files",
            f"Found {len(aws_ev)} AWS-shaped evidence JSON file(s): {names}",
        )
    if other_ev:
        names = ", ".join(sorted(p.name for p in other_ev[:5]))
        extra = "" if len(other_ev) <= 5 else f" (+{len(other_ev) - 5} more)"
        _append_signal(
            signals,
            "evidence_json_unrecognized_filenames",
            (
                f"Unrecognized JSON under .oss-policy-kit/evidence/ — these files do not "
                f"match any bundled schema and will be ignored by `evaluate`: {names}{extra}. "
                f"Rename to a bundled template (see `scaffold-evidence --help`) or remove them."
            ),
        )
    return signals


def _append_gh_release_hardening(
    out: list[tuple[int, str, str, list[str]]],
    *,
    can_rh2: bool,
    can_rh1: bool,
) -> None:
    """Append the GitHub release-hardening-2/-1 suggestion when its signals are present."""

    if can_rh2:
        out.append(
            (
                300,
                "github-release-hardening-2",
                (
                    "GitHub Actions workflows AND GitHub-shaped release evidence JSON are both "
                    "present; evaluate declared release posture with github-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                ["github_actions_workflows", "github_evidence_json_files"],
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "github-release-hardening-1",
                (
                    "Evidence directory is empty but GitHub workflows exist; "
                    "add GitHub evidence JSON, then use release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "github_actions_workflows"],
            )
        )


def _suggestions_github(
    *,
    wf_paths: list[Path],
    github_ev: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """GitHub-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # release-hardening-2 requires BOTH a CI signal AND release-shaped evidence
    # (M-005): a single intentionally-unsafe workflow alone is not justification
    # to recommend a release-track profile.
    can_rh2 = bool(wf_paths) and bool(github_ev)
    can_rh1 = empty_evidence_dir and bool(wf_paths) and not github_ev
    if wf_paths and not github_ev:
        out.append(
            (
                320,
                "github-level-1",
                (
                    "GitHub workflows are visible but release evidence is not present yet; "
                    "start with github-level-1 and escalate after evidence maturity."
                ),
                ["github_actions_workflows"],
            )
        )
    _append_gh_release_hardening(out, can_rh2=can_rh2, can_rh1=can_rh1)
    if wf_paths and github_ev:
        tier = "github-level-2" if len(wf_paths) >= 2 else "github-level-1"
        out.append(
            (
                200,
                tier,
                (
                    "GitHub Actions workflows are visible in the clone; pick a GitHub ladder profile "
                    "that matches your desired strictness."
                ),
                ["github_actions_workflows"],
            )
        )
    # MELHORIA-001 / F-001: evidence files for GitHub exist but NO CI signal
    # in the clone (and no other platform's CI either). Surface a weak
    # suggestion + explicit rationale. If another platform (Azure / AWS) has
    # CI signals, suppress this fallback — the adopter is clearly on that
    # platform, and a GitHub recommendation would be misleading.
    no_other_ci = not az_paths and not buildspec
    if github_ev and not wf_paths and no_other_ci:
        # Suggest the starter ladder (github-level-1), not release-hardening:
        # the adopter clearly lacks CI altogether, so release-track guidance
        # would be misleading. The rationale explains that the evidence is
        # currently unused. Keeps consistency with M-005 (no release-hardening
        # without CI signal).
        out.append(
            (
                150,
                "github-level-1",
                (
                    "GitHub-shaped evidence JSON files were found but no .github/workflows/ "
                    "files exist in this clone. The evidence is currently unused — start "
                    "from github-level-1 and add a workflow first (or confirm you are "
                    "pointing --target at the correct repository root), then re-run "
                    "recommend-profile to graduate to a release-hardening profile."
                ),
                ["github_evidence_json_files"],
            )
        )
    return out


def _suggestions_gitlab(
    *,
    gl_paths: list[Path],
    gitlab_ev: list[Path],
    wf_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """GitLab-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # BOTH a CI signal AND release-shaped evidence required for release-hardening-2 (M-005).
    can_rh2 = bool(gl_paths) and bool(gitlab_ev)
    can_rh1 = empty_evidence_dir and bool(gl_paths) and not gitlab_ev
    if can_rh2:
        out.append(
            (
                300,
                "gitlab-release-hardening-2",
                (
                    "GitLab CI pipelines AND GitLab-shaped release evidence JSON are both present; "
                    "evaluate declared release posture with gitlab-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                ["gitlab_ci_yaml", "gitlab_evidence_json_files"],
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "gitlab-release-hardening-1",
                (
                    "Evidence directory is empty but GitLab CI pipelines exist; "
                    "add GitLab evidence JSON, then use gitlab-release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "gitlab_ci_yaml"],
            )
        )
    if gl_paths:
        tier = "gitlab-level-2" if len(gl_paths) >= 2 else "gitlab-level-1"
        out.append(
            (
                200,
                tier,
                "GitLab CI pipelines are present; evaluate clone-visible GitLab CI governance.",
                ["gitlab_ci_yaml"],
            )
        )
    # GitLab evidence without GitLab CI (and no other platform's CI): surface a weak fallback.
    no_other_ci = not wf_paths and not az_paths and not buildspec
    if gitlab_ev and not gl_paths and no_other_ci:
        out.append(
            (
                150,
                "gitlab-level-1",
                (
                    "GitLab-shaped evidence JSON files were found but no .gitlab-ci.yml exists in this "
                    "clone. The evidence is currently unused — start from gitlab-level-1 and add a "
                    "pipeline first (or confirm you are pointing --target at the correct repository "
                    "root), then re-run recommend-profile to graduate to a release-hardening profile."
                ),
                ["gitlab_evidence_json_files"],
            )
        )
    return out


def _suggestions_azure(
    *,
    az_paths: list[Path],
    azure_ev: list[Path],
    wf_paths: list[Path],
    buildspec: bool,
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """Azure-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # See github branch above: BOTH signals required for release-hardening-2 (M-005).
    can_rh2 = bool(az_paths) and bool(azure_ev)
    can_rh1 = empty_evidence_dir and bool(az_paths) and not azure_ev
    if can_rh2:
        out.append(
            (
                300,
                "azure-release-hardening-2",
                (
                    "Azure Pipelines YAML AND Azure-shaped release evidence JSON are both "
                    "present; evaluate declared release posture with azure-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                ["azure_pipelines_yaml", "azure_evidence_json_files"],
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "azure-release-hardening-1",
                (
                    "Evidence directory is empty but Azure Pipelines YAML exists; "
                    "add Azure evidence JSON, then use azure-release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "azure_pipelines_yaml"],
            )
        )
    if az_paths:
        out.append(
            (
                200,
                "azure-level-1",
                "Azure Pipelines definitions are present; evaluate clone-visible Azure CI governance.",
                ["azure_pipelines_yaml"],
            )
        )
    # MELHORIA-001 / F-001: Azure evidence without Azure Pipelines (and
    # no other platform's CI), see the GitHub branch above.
    no_other_ci = not wf_paths and not buildspec
    if azure_ev and not az_paths and no_other_ci:
        out.append(
            (
                150,
                "azure-level-1",
                (
                    "Azure-shaped evidence JSON files were found but no Azure Pipelines YAML "
                    "exists in this clone. The evidence is currently unused — start from "
                    "azure-level-1 and add a pipeline first (or confirm you are pointing "
                    "--target at the correct repository root), then re-run recommend-profile "
                    "to graduate to a release-hardening profile."
                ),
                ["azure_evidence_json_files"],
            )
        )
    return out


def _suggestions_aws(
    *,
    buildspec: bool,
    aws_ev: list[Path],
    wf_paths: list[Path],
    az_paths: list[Path],
    empty_evidence_dir: bool,
) -> list[tuple[int, str, str, list[str]]]:
    """AWS-platform profile suggestions (see _suggestions_for_platform)."""

    out: list[tuple[int, str, str, list[str]]] = []
    # See github branch above: BOTH signals required for release-hardening-2 (M-005).
    can_rh2 = bool(buildspec) and bool(aws_ev)
    can_rh1 = empty_evidence_dir and bool(buildspec) and not aws_ev
    if can_rh2:
        out.append(
            (
                300,
                "aws-release-hardening-2",
                (
                    "A buildspec AND AWS-shaped release evidence JSON are both present; "
                    "evaluate declared release posture with aws-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                ["aws_codebuild_buildspec", "aws_evidence_json_files"],
            )
        )
    elif can_rh1:
        out.append(
            (
                290,
                "aws-release-hardening-1",
                (
                    "Evidence directory is empty but buildspec.yml exists; "
                    "add AWS evidence JSON, then use aws-release-hardening-1 as a starting ladder."
                ),
                ["evidence_dir_empty", "aws_codebuild_buildspec"],
            )
        )
    if buildspec:
        out.append(
            (
                200,
                "aws-level-1",
                "A CodeBuild buildspec is present; evaluate clone-visible AWS CI signals.",
                ["aws_codebuild_buildspec"],
            )
        )
    # MELHORIA-001 / F-001: AWS evidence without buildspec (and no other
    # platform's CI), see the GitHub branch above.
    no_other_ci = not wf_paths and not az_paths
    if aws_ev and not buildspec and no_other_ci:
        out.append(
            (
                150,
                "aws-level-1",
                (
                    "AWS-shaped evidence JSON files were found but no buildspec.yml / "
                    "buildspec.yaml exists in this clone. The evidence is currently unused — "
                    "start from aws-level-1 and add a buildspec first (or confirm you are "
                    "pointing --target at the correct repository root), then re-run "
                    "recommend-profile to graduate to a release-hardening profile."
                ),
                ["aws_evidence_json_files"],
            )
        )
    return out


def _suggestions_for_platform(
    platform: str,
    *,
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[tuple[int, str, str, list[str]]]:
    """Return (priority, profile_id, rationale, based_on) for one platform, in user-facing order."""

    empty_evidence_dir = ev_dir.is_dir() and not ev_json
    if platform == "github":
        return _suggestions_github(
            wf_paths=wf_paths,
            github_ev=github_ev,
            az_paths=az_paths,
            buildspec=buildspec,
            empty_evidence_dir=empty_evidence_dir,
        )
    if platform == "gitlab":
        return _suggestions_gitlab(
            gl_paths=gl_paths,
            gitlab_ev=gitlab_ev,
            wf_paths=wf_paths,
            az_paths=az_paths,
            buildspec=buildspec,
            empty_evidence_dir=empty_evidence_dir,
        )
    if platform == "azure":
        return _suggestions_azure(
            az_paths=az_paths,
            azure_ev=azure_ev,
            wf_paths=wf_paths,
            buildspec=buildspec,
            empty_evidence_dir=empty_evidence_dir,
        )
    return _suggestions_aws(
        buildspec=buildspec,
        aws_ev=aws_ev,
        wf_paths=wf_paths,
        az_paths=az_paths,
        empty_evidence_dir=empty_evidence_dir,
    )


def _merge_platform_suggestions(
    order: list[str],
    *,
    wf_paths: list[Path],
    gl_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
    gitlab_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[dict[str, Any]]:
    """Collect, rank, and de-duplicate per-platform suggestions (top 3)."""

    merged: list[tuple[int, int, str, str, list[str]]] = []
    for order_idx, plat in enumerate(order):
        for prio, pid, rationale, based_on in _suggestions_for_platform(
            plat,
            wf_paths=wf_paths,
            gl_paths=gl_paths,
            az_paths=az_paths,
            buildspec=buildspec,
            ev_dir=ev_dir,
            ev_json=ev_json,
            github_ev=github_ev,
            gitlab_ev=gitlab_ev,
            azure_ev=azure_ev,
            aws_ev=aws_ev,
        ):
            merged.append((prio, order_idx, pid, rationale, based_on))

    merged.sort(key=lambda t: (-t[0], t[1]))
    suggestions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _prio, _order_idx, pid, rationale, based_on in merged:
        if pid in seen or len(suggestions) >= 3:
            continue
        suggestions.append({"profile_id": pid, "rationale": rationale, "based_on": list(dict.fromkeys(based_on))})
        seen.add(pid)
    return suggestions


def _multi_platform_notes(order: list[str]) -> list[str]:
    """Notes explaining ranked multi-platform CI detection (empty for 0/1 platform)."""

    if len(order) <= 1:
        return []
    primary = order[0]
    pretty = {
        "github": "GitHub Actions",
        "gitlab": "GitLab CI",
        "azure": "Azure Pipelines",
        "aws": "AWS CodeBuild",
    }.get(primary, primary)
    tail = ", ".join(
        {"github": "GitHub", "gitlab": "GitLab", "azure": "Azure", "aws": "AWS"}.get(p, p) for p in order[1:]
    )
    return [
        (
            f"Multiple CI platforms detected in this clone (primary ranked: {pretty}; also: {tail}). "
            "Profile suggestions prioritize the strongest platform signals first."
        ),
        (
            "Pass --platform github | gitlab | azure | aws (on `init`) or --profile <id> (on `evaluate`) "
            "to override and fix the platform family yourself."
        ),
    ]


def _no_platform_fallback(
    *,
    other_ev: list[Path],
    wf_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    github_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
    ev_dir: Path,
    ev_json: list[Path],
    prefer_l2_container: bool,
    tech_ids: set[str],
    tech_primary: str | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Suggestions + notes when no CI platform was detected at all."""

    notes: list[str] = []
    suggestions: list[dict[str, Any]] = []
    if other_ev and not (wf_paths or az_paths or buildspec or github_ev or azure_ev or aws_ev):
        notes.append(
            "Evidence JSON uses non-bundled filenames; add platform-specific template names "
            "(or CI signals) so release-hardening suggestions can align to GitHub, Azure, or AWS."
        )
    if ev_dir.is_dir() and not ev_json and not (wf_paths or az_paths or buildspec):
        notes.append(
            "An empty .oss-policy-kit/evidence/ directory was found without CI signals; "
            "run scaffold-evidence for the correct platform or remove the folder if unused."
        )
    if prefer_l2_container or "container_docker" in tech_ids:
        notes.append(
            "Container workloads benefit from stricter workflow and supply-chain controls "
            "(image provenance, pinned actions, SBOM signals) - github-level-2 is a stronger starting point."
        )
        suggestions.append(
            {
                "profile_id": "github-level-2",
                "rationale": (
                    "Container signals detected (Dockerfile / compose). github-level-2 is recommended "
                    "as a baseline because it emphasizes CI workflow hardening and supply-chain adjacent "
                    "checks relevant to container build and publish paths."
                ),
                "based_on": (["container_docker"] if "container_docker" in tech_ids else sorted(tech_ids)),
            }
        )
    elif tech_ids:
        stack = tech_primary or "application"
        suggestions.append(
            {
                "profile_id": "github-level-1",
                "rationale": (
                    f"github-level-1 is recommended as a starting baseline for your {stack} project; "
                    "it covers SAST, dependency audit, and governance signals relevant to typical CI pipelines."
                ),
                "based_on": sorted(tech_ids),
            }
        )
    else:
        notes.append(FEW_SIGNALS_FALLBACK_NOTE)
        suggestions.append(
            {
                "profile_id": "github-level-1",
                "rationale": (
                    "No GitHub/Azure/AWS CI or bundled-shaped evidence JSON detected; "
                    "github-level-1 is the safest default ladder."
                ),
                "based_on": [],
            }
        )
    return suggestions, notes


def build_profile_recommendation(repo_root: Path) -> ProfileRecommendation:
    """Inspect *repo_root* and return up to three profile suggestions with rationale."""

    wf_paths = _workflow_yaml_paths(repo_root)
    gl_paths = _gitlab_ci_paths(repo_root)
    az_paths = _azure_pipeline_paths(repo_root)
    buildspec = (repo_root / "buildspec.yml").is_file() or (repo_root / "buildspec.yaml").is_file()
    ev_dir = repo_root / ".oss-policy-kit" / "evidence"
    ev_json = _evidence_json_paths(repo_root)
    github_ev, gitlab_ev, azure_ev, aws_ev, other_ev = _partition_evidence_json(ev_json)

    signals = _collect_signals(
        wf_paths, gl_paths, az_paths, buildspec, ev_dir, ev_json, github_ev, gitlab_ev, azure_ev, aws_ev, other_ev
    )

    tech_signals, tech_notes, prefer_l2_container, tech_primary = _collect_tech_stack_signals(repo_root)
    signals.extend(tech_signals)

    order = _platform_order(
        wf_paths=wf_paths,
        gl_paths=gl_paths,
        az_paths=az_paths,
        buildspec=buildspec,
        github_ev=github_ev,
        gitlab_ev=gitlab_ev,
        azure_ev=azure_ev,
        aws_ev=aws_ev,
    )

    suggestions = _merge_platform_suggestions(
        order,
        wf_paths=wf_paths,
        gl_paths=gl_paths,
        az_paths=az_paths,
        buildspec=buildspec,
        ev_dir=ev_dir,
        ev_json=ev_json,
        github_ev=github_ev,
        gitlab_ev=gitlab_ev,
        azure_ev=azure_ev,
        aws_ev=aws_ev,
    )

    notes = _multi_platform_notes(order)
    tech_ids = {s["id"] for s in tech_signals}
    if tech_notes:
        notes.extend(tech_notes)

    if not order:
        fb_suggestions, fb_notes = _no_platform_fallback(
            other_ev=other_ev,
            wf_paths=wf_paths,
            az_paths=az_paths,
            buildspec=buildspec,
            github_ev=github_ev,
            azure_ev=azure_ev,
            aws_ev=aws_ev,
            ev_dir=ev_dir,
            ev_json=ev_json,
            prefer_l2_container=prefer_l2_container,
            tech_ids=tech_ids,
            tech_primary=tech_primary,
        )
        suggestions.extend(fb_suggestions)
        notes.extend(fb_notes)

    return ProfileRecommendation(signals_detected=signals, suggestions=suggestions, notes=notes)


def recommend_profiles(repo_root: Path) -> list[tuple[str, str]]:
    """Backward-compatible (profile_id, rationale) pairs, up to three entries."""

    rec = build_profile_recommendation(repo_root)
    return [(s["profile_id"], str(s["rationale"])) for s in rec.suggestions]
