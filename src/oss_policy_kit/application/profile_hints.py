"""Heuristics for suggesting bundled profiles from repository layout."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

GITHUB_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "branch-protection.json",
        "github-rulesets.json",
        "github-environment-protection.json",
        "github-secret-scanning.json",
    }
)
AZURE_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "azure-branch-policies.json",
        "azure-pipeline-governance.json",
        "azure-sbom-artifact.json",
        "azure-provenance-artifact.json",
    }
)
AWS_EVIDENCE_FILENAMES: frozenset[str] = frozenset(
    {
        "aws-codebuild-project.json",
        "aws-codepipeline.json",
        "aws-codecommit-review-posture.json",
        "aws-sbom-artifact.json",
        "aws-provenance-artifact.json",
    }
)


@dataclass(slots=True)
class ProfileRecommendation:
    """Structured profile hints for CLI and automation."""

    schema_version: str = "oss-policy-kit/profile-recommendation/v2"
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
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def _evidence_json_paths(repo_root: Path) -> list[Path]:
    ev = repo_root / ".oss-policy-kit" / "evidence"
    if not ev.is_dir():
        return []
    return sorted(p for p in ev.glob("*.json") if p.is_file())


def _partition_evidence_json(ev_json: list[Path]) -> tuple[list[Path], list[Path], list[Path], list[Path]]:
    github: list[Path] = []
    azure: list[Path] = []
    aws: list[Path] = []
    other: list[Path] = []
    for p in ev_json:
        name = p.name
        if name in GITHUB_EVIDENCE_FILENAMES:
            github.append(p)
        elif name in AZURE_EVIDENCE_FILENAMES:
            azure.append(p)
        elif name in AWS_EVIDENCE_FILENAMES:
            aws.append(p)
        else:
            other.append(p)
    return github, azure, aws, other


def _append_signal(signals: list[dict[str, str]], sig_id: str, detail: str) -> None:
    signals.append({"id": sig_id, "detail": detail})


def _collect_tech_stack_signals(
    repo_root: Path,
) -> tuple[list[dict[str, str]], list[str], bool, str | None]:
    """Detect common language/runtime markers; returns signals, notes, Dockerfile->L2 flag, primary stack label."""

    found: list[dict[str, str]] = []
    notes: list[str] = []
    prefer_l2 = False
    primary: str | None = None

    if (
        (repo_root / "Dockerfile").is_file()
        or (repo_root / "docker-compose.yml").is_file()
        or (repo_root / "docker-compose.yaml").is_file()
    ):
        prefer_l2 = True
        _append_signal(
            found,
            "container_docker",
            "Container workload detected via Dockerfile or docker-compose.",
        )

    if (repo_root / "package.json").is_file():
        primary = primary or "Node.js"
        _append_signal(found, "node_js", "Node.js project detected via package.json")
        if any((repo_root / name).is_file() for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
            _append_signal(found, "node_lockfile", "Node lockfile present (reproducible installs).")
        else:
            notes.append("Add package-lock.json or yarn.lock to enable reproducible builds.")

    if (repo_root / "pyproject.toml").is_file():
        primary = primary or "Python"
        _append_signal(found, "python_pyproject", "Python project detected via pyproject.toml")
        try:
            body = (repo_root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        bl = body.lower()
        if "[tool.ruff]" in body or "[tool.ruff." in body or "ruff>" in bl:
            notes.append("Ruff is configured under pyproject.toml - align CI quality gates with the same rules.")
        if "[tool.mypy]" in body or "python -m mypy" in bl:
            notes.append("Mypy is referenced - keep static type checks in CI for stronger supply-chain posture.")
    elif (repo_root / "requirements.txt").is_file():
        primary = primary or "Python"
        _append_signal(found, "python_requirements", "Python project detected via requirements.txt")
    elif (repo_root / "setup.py").is_file() or (repo_root / "setup.cfg").is_file():
        primary = primary or "Python"
        _append_signal(found, "python_setup", "Python project detected via setup.py/setup.cfg")

    if (repo_root / "go.mod").is_file():
        primary = primary or "Go"
        _append_signal(found, "go_module", "Go module detected via go.mod")

    if (repo_root / "pom.xml").is_file():
        primary = primary or "Java/Maven"
        _append_signal(found, "java_maven", "Java/Maven project detected via pom.xml")

    if (repo_root / "build.gradle").is_file() or (repo_root / "build.gradle.kts").is_file():
        primary = primary or "Java/Kotlin (Gradle)"
        _append_signal(found, "java_gradle", "Java/Kotlin project detected via build.gradle")

    if (repo_root / "Cargo.toml").is_file():
        primary = primary or "Rust"
        _append_signal(found, "rust_cargo", "Rust project detected via Cargo.toml")

    if list(repo_root.glob("*.csproj")) or list(repo_root.glob("*.sln")):
        primary = primary or "C#/.NET"
        _append_signal(found, "dotnet_csproj", "C#/.NET project detected via .csproj or .sln")

    return found, notes, prefer_l2, primary


def _platform_order(
    *,
    wf_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    github_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[str]:
    """Return github, azure, aws ordered with the most strongly indicated platform first."""

    def weight(name: str) -> int:
        if name == "github":
            return 100 * len(github_ev) + 40 * bool(wf_paths)
        if name == "azure":
            return 100 * len(azure_ev) + 40 * bool(az_paths)
        return 100 * len(aws_ev) + 40 * bool(buildspec)

    present = [p for p in ("github", "azure", "aws") if weight(p) > 0]
    return sorted(present, key=lambda n: (-weight(n), n))


def _collect_signals(
    wf_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
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
            "evidence_json_non_bundled_filenames",
            f"JSON under evidence/ with names outside bundled templates: {names}{extra}",
        )
    return signals


def _suggestions_for_platform(
    platform: str,
    *,
    wf_paths: list[Path],
    az_paths: list[Path],
    buildspec: bool,
    ev_dir: Path,
    ev_json: list[Path],
    github_ev: list[Path],
    azure_ev: list[Path],
    aws_ev: list[Path],
) -> list[tuple[int, str, str, list[str]]]:
    """Return (priority, profile_id, rationale, based_on) for one platform, in user-facing order."""

    out: list[tuple[int, str, str, list[str]]] = []
    empty_evidence_dir = ev_dir.is_dir() and not ev_json

    if platform == "github":
        can_rh2 = bool(wf_paths or github_ev)
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
        if can_rh2:
            gh_keys = ("github_actions_workflows", "github_evidence_json_files")
            bo = [x for x in gh_keys if _bo_hit(x, wf_paths, github_ev)]
            if not bo:
                bo = ["github_actions_workflows"] if wf_paths else ["github_evidence_json_files"]
            out.append(
                (
                    300,
                    "github-release-hardening-2",
                    (
                        "GitHub Actions and/or GitHub-shaped evidence JSON is present; "
                        "evaluate declared release posture with github-release-hardening-2 "
                        "(verify evidence JSONs are filled, not templates)."
                    ),
                    _normalize_based_on(bo, wf_paths, github_ev),
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
        return out

    if platform == "azure":
        can_rh2 = bool(azure_ev or az_paths)
        can_rh1 = empty_evidence_dir and bool(az_paths) and not azure_ev
        if can_rh2:
            az_keys = ("azure_pipelines_yaml", "azure_evidence_json_files")
            bo = [x for x in az_keys if _bo_hit_az(x, az_paths, azure_ev)]
            if not bo:
                bo = ["azure_pipelines_yaml"] if az_paths else ["azure_evidence_json_files"]
            out.append(
                (
                    300,
                    "azure-release-hardening-2",
                    (
                        "Azure Pipelines and/or Azure-shaped evidence JSON is present; "
                        "evaluate declared release posture with azure-release-hardening-2 "
                        "(verify evidence JSONs are filled, not templates)."
                    ),
                    _normalize_based_on_az(bo, az_paths, azure_ev),
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
        return out

    # aws
    can_rh2 = bool(buildspec or aws_ev)
    can_rh1 = empty_evidence_dir and bool(buildspec) and not aws_ev
    if can_rh2:
        aws_keys = ("aws_codebuild_buildspec", "aws_evidence_json_files")
        bo = [x for x in aws_keys if _bo_hit_aws(x, buildspec, aws_ev)]
        if not bo:
            bo = ["aws_codebuild_buildspec"] if buildspec else ["aws_evidence_json_files"]
        out.append(
            (
                300,
                "aws-release-hardening-2",
                (
                    "A buildspec and/or AWS-shaped evidence JSON is present; "
                    "evaluate declared release posture with aws-release-hardening-2 "
                    "(verify evidence JSONs are filled, not templates)."
                ),
                _normalize_based_on_aws(bo, buildspec, aws_ev),
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
    return out


def _bo_hit(name: str, wf_paths: list[Path], github_ev: list[Path]) -> bool:
    if name == "github_actions_workflows":
        return bool(wf_paths)
    if name == "github_evidence_json_files":
        return bool(github_ev)
    return False


def _normalize_based_on(bo: list[str], wf_paths: list[Path], github_ev: list[Path]) -> list[str]:
    out = list(bo)
    if "github_actions_workflows" not in out and wf_paths:
        out.insert(0, "github_actions_workflows")
    if "github_evidence_json_files" not in out and github_ev:
        out.append("github_evidence_json_files")
    return out


def _bo_hit_az(name: str, az_paths: list[Path], azure_ev: list[Path]) -> bool:
    if name == "azure_pipelines_yaml":
        return bool(az_paths)
    if name == "azure_evidence_json_files":
        return bool(azure_ev)
    return False


def _normalize_based_on_az(bo: list[str], az_paths: list[Path], azure_ev: list[Path]) -> list[str]:
    out = list(bo)
    if "azure_pipelines_yaml" not in out and az_paths:
        out.insert(0, "azure_pipelines_yaml")
    if "azure_evidence_json_files" not in out and azure_ev:
        out.append("azure_evidence_json_files")
    return out


def _bo_hit_aws(name: str, buildspec: bool, aws_ev: list[Path]) -> bool:
    if name == "aws_codebuild_buildspec":
        return buildspec
    if name == "aws_evidence_json_files":
        return bool(aws_ev)
    return False


def _normalize_based_on_aws(bo: list[str], buildspec: bool, aws_ev: list[Path]) -> list[str]:
    out = list(bo)
    if "aws_codebuild_buildspec" not in out and buildspec:
        out.insert(0, "aws_codebuild_buildspec")
    if "aws_evidence_json_files" not in out and aws_ev:
        out.append("aws_evidence_json_files")
    return out


def build_profile_recommendation(repo_root: Path) -> ProfileRecommendation:
    """Inspect *repo_root* and return up to three profile suggestions with rationale."""

    wf_paths = _workflow_yaml_paths(repo_root)
    az_paths = _azure_pipeline_paths(repo_root)
    buildspec = (repo_root / "buildspec.yml").is_file() or (repo_root / "buildspec.yaml").is_file()
    ev_dir = repo_root / ".oss-policy-kit" / "evidence"
    ev_json = _evidence_json_paths(repo_root)
    github_ev, azure_ev, aws_ev, other_ev = _partition_evidence_json(ev_json)

    signals = _collect_signals(wf_paths, az_paths, buildspec, ev_dir, ev_json, github_ev, azure_ev, aws_ev, other_ev)

    tech_signals, tech_notes, prefer_l2_container, tech_primary = _collect_tech_stack_signals(repo_root)
    signals.extend(tech_signals)

    order = _platform_order(
        wf_paths=wf_paths,
        az_paths=az_paths,
        buildspec=buildspec,
        github_ev=github_ev,
        azure_ev=azure_ev,
        aws_ev=aws_ev,
    )

    merged: list[tuple[int, int, str, str, list[str]]] = []
    for order_idx, plat in enumerate(order):
        for prio, pid, rationale, based_on in _suggestions_for_platform(
            plat,
            wf_paths=wf_paths,
            az_paths=az_paths,
            buildspec=buildspec,
            ev_dir=ev_dir,
            ev_json=ev_json,
            github_ev=github_ev,
            azure_ev=azure_ev,
            aws_ev=aws_ev,
        ):
            merged.append((prio, order_idx, pid, rationale, based_on))

    merged.sort(key=lambda t: (-t[0], t[1]))
    suggestions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _prio, _order_idx, pid, rationale, based_on in merged:
        if pid in seen:
            continue
        if len(suggestions) >= 3:
            break
        suggestions.append({"profile_id": pid, "rationale": rationale, "based_on": list(dict.fromkeys(based_on))})
        seen.add(pid)

    notes: list[str] = []
    if len(order) > 1:
        primary = order[0]
        pretty = {"github": "GitHub Actions", "azure": "Azure Pipelines", "aws": "AWS CodeBuild"}.get(primary, primary)
        tail = ", ".join({"github": "GitHub", "azure": "Azure", "aws": "AWS"}.get(p, p) for p in order[1:])
        notes.append(
            f"Multiple CI platforms detected in this clone (primary ranked: {pretty}; also: {tail}). "
            "Profile suggestions prioritize the strongest platform signals first.",
        )
    tech_ids = {s["id"] for s in tech_signals}
    if tech_notes:
        notes.extend(tech_notes)

    if not order:
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
            notes.append(
                "Few strong platform signals were detected; defaulting to a conservative GitHub baseline profile."
            )
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

    return ProfileRecommendation(signals_detected=signals, suggestions=suggestions, notes=notes)


def recommend_profiles(repo_root: Path) -> list[tuple[str, str]]:
    """Backward-compatible (profile_id, rationale) pairs, up to three entries."""

    rec = build_profile_recommendation(repo_root)
    return [(s["profile_id"], str(s["rationale"])) for s in rec.suggestions]
