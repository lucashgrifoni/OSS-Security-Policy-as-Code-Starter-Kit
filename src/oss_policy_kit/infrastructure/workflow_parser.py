"""Parse GitHub Actions workflow YAML for static security signals."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from oss_policy_kit.infrastructure.yaml_io import load_yaml_file


@dataclass(slots=True)
class WorkflowAnalysis:
    """Aggregated signals from all workflows in a repository."""

    workflow_paths: list[Path] = field(default_factory=list)
    missing_top_level_permissions: list[Path] = field(default_factory=list)
    uses_pull_request_target: list[Path] = field(default_factory=list)
    mutable_action_refs: list[tuple[Path, str]] = field(default_factory=list)
    suspicious_permissions: list[tuple[Path, str]] = field(default_factory=list)
    #: Distinct CI security scanning / SAST signals found (CodeQL, Semgrep, Bandit, etc.).
    sast_ci_signals: list[str] = field(default_factory=list)
    has_codeql_or_security_scan: bool = False
    has_dependency_review: bool = False
    reusable_secrets_inherit_paths: list[Path] = field(default_factory=list)
    pr_self_hosted_runner_paths: list[Path] = field(default_factory=list)
    broad_job_permissions: list[tuple[Path, str]] = field(default_factory=list)
    release_workflow_paths: list[Path] = field(default_factory=list)
    release_workflows_missing_concurrency: list[Path] = field(default_factory=list)
    cloud_deploy_workflow_paths: list[Path] = field(default_factory=list)
    cloud_deploy_with_oidc_paths: list[Path] = field(default_factory=list)
    has_artifact_attestation: bool = False
    #: Workflows that appear to enable GitHub merge queue / merge_group triggers.
    merge_queue_signal_paths: list[Path] = field(default_factory=list)
    #: Reusable workflow calls (``uses: .../.github/workflows/...@ref``) where *ref* is not a full commit SHA.
    reusable_workflow_mutable_ref_paths: list[Path] = field(default_factory=list)
    #: Workflows that call reusable workflows under ``.github/workflows`` (any pin).
    reusable_workflow_call_paths: list[Path] = field(default_factory=list)
    #: (workflow path, job id, human-readable detail) — least-privilege gaps (CI-LEAST-009 signal).
    implicit_permission_risks: list[tuple[Path, str, str]] = field(default_factory=list)
    parse_errors: list[tuple[Path, str]] = field(default_factory=list)


_MUTABLE_REF = re.compile(
    r"uses:\s*([^\s#]+)",
    re.MULTILINE,
)


_REUSABLE_WORKFLOW_USES = re.compile(
    r"^\s*uses:\s*([^\s#]+)",
    re.MULTILINE | re.IGNORECASE,
)


def _reusable_workflow_pin_is_full_sha(ref: str) -> bool:
    """Return True when a reusable workflow ``uses`` pin looks like a full 40-char commit SHA."""

    r = ref.strip().strip("'\"")
    if ".github/workflows" not in r.lower():
        return True
    if "@" not in r:
        return False
    _prefix, pin = r.rsplit("@", 1)
    return bool(re.fullmatch(r"[0-9a-f]{40}", pin.strip().lower()))


def _scan_reusable_workflow_pins(
    content: str,
    path: Path,
    *,
    mutable_out: list[Path],
    call_out: list[Path],
) -> None:
    for m in _REUSABLE_WORKFLOW_USES.finditer(content):
        ref = m.group(1).strip()
        if not ref or ref.startswith("${{"):
            continue
        if ".github/workflows" not in ref.lower():
            continue
        if path not in call_out:
            call_out.append(path)
        if not _reusable_workflow_pin_is_full_sha(ref) and path not in mutable_out:
            mutable_out.append(path)


def _is_immutable_action_ref(ref: str) -> bool:
    r = ref.strip().strip("'\"")
    if r.startswith("${{") or r.startswith("./") or r.startswith("docker://"):
        return True
    if "@" not in r:
        return True
    _repo, pin = r.rsplit("@", 1)
    pin_l = pin.lower()
    if re.fullmatch(r"[0-9a-f]{40}", pin_l):
        return True
    if re.fullmatch(r"v\d+(?:\.\d+)*", pin_l):
        return False
    if pin_l in {"main", "master", "latest", "dev", "develop", "release"}:
        return False
    return bool(re.fullmatch(r"[0-9a-f]{7,39}", pin_l))


def _scan_uses_for_mutable(content: str, path: Path, out: list[tuple[Path, str]]) -> None:
    for m in _MUTABLE_REF.finditer(content):
        ref = m.group(1).strip()
        if not ref or ref.startswith("${{"):
            continue
        if not _is_immutable_action_ref(ref):
            out.append((path, ref))


def _content_has_token(text: str, token: str) -> bool:
    return token in text


def _contains_pr_event(data: dict[str, Any], raw: str) -> bool:
    """Best-effort detection for pull-request-triggered workflows."""

    on_block = data.get("on")
    if isinstance(on_block, str):
        return on_block in {"pull_request", "pull_request_target"}
    if isinstance(on_block, list):
        return any(item in {"pull_request", "pull_request_target"} for item in on_block)
    if isinstance(on_block, dict):
        return "pull_request" in on_block or "pull_request_target" in on_block
    return "pull_request" in raw or "pull_request_target" in raw


def _is_self_hosted_runs_on(value: Any) -> bool:
    if isinstance(value, str):
        return "self-hosted" in value.lower()
    if isinstance(value, list):
        return any(isinstance(x, str) and "self-hosted" in x.lower() for x in value)
    return False


def _detect_release_workflow(data: dict[str, Any], raw: str) -> bool:
    lower = raw.lower()
    if any(tok in lower for tok in ("release", "deploy", "publish", "package")):
        return True
    on_block = data.get("on")
    if isinstance(on_block, dict) and ("release" in on_block or "workflow_dispatch" in on_block):
        return True
    return "tags:" in lower


def _workflow_body_for_sast_heuristics(raw: str) -> str:
    """Remove single-line `run: echo ...` steps to avoid satisfying SAST checks with decoy strings."""

    kept: list[str] = []
    for line in raw.splitlines():
        if re.search(r"^\s*-\s+run:\s*echo\b", line, re.IGNORECASE):
            continue
        if re.search(r"^\s+run:\s*echo\b", line, re.IGNORECASE):
            continue
        kept.append(line)
    return "\n".join(kept)


def _collect_sast_ci_signals(raw: str) -> set[str]:  # noqa: C901
    """Detect plausible CI SAST / code scanning for SEC-CODEQL-010 (not mere tool-name mentions)."""

    body = _workflow_body_for_sast_heuristics(raw)
    lower = body.lower()
    full_lower = raw.lower()
    found: set[str] = set()

    codeql_action = re.search(r"github/codeql-action/\w+", full_lower, re.IGNORECASE)
    codeql_cli = re.search(r"\bcodeql\s+database\b", lower) or re.search(r"\bcodeql\s+analyze\b", lower)
    if codeql_action or codeql_cli:
        found.add("codeql")

    semgrep_uses = re.search(
        r"uses:\s*[^\n#]*(returntocorp/semgrep|semgrep/semgrep|semgrep-action)", full_lower, re.IGNORECASE
    )
    semgrep_cli = re.search(r"\bsemgrep\s+(scan|ci)\b", lower) or re.search(r"\bsemgrep\s+[^\n]*--config\b", lower)
    if semgrep_uses or semgrep_cli:
        found.add("semgrep")

    bandit_cli = re.search(r"\bpython\s+-m\s+bandit\b", lower) or re.search(r"\bbandit\s+-r\b", lower)
    bandit_uses = re.search(r"uses:\s*[^\n#]*bandit", full_lower, re.IGNORECASE)
    if bandit_cli or bandit_uses:
        found.add("bandit")

    if re.search(r"\bsnyk\s+code\s+test\b", lower) or "snyk-code" in lower:
        found.add("snyk-code")

    sonar_uses = re.search(
        r"uses:\s*[^\n#]*sonarsource/sonarcloud-github-action", full_lower, re.IGNORECASE
    ) or re.search(r"uses:\s*[^\n#]*sonarqube", full_lower, re.IGNORECASE)
    if sonar_uses or re.search(r"\bsonar-scanner\b", lower):
        found.add("sonar")

    if re.search(r"uses:\s*[^\n#]*brakeman", full_lower, re.IGNORECASE) or re.search(r"\bbrakeman\s+(\.|--)", lower):
        found.add("brakeman")

    if re.search(r"uses:\s*[^\n#]*horusec", full_lower, re.IGNORECASE) or re.search(r"\bhorusec\s+cli\b", lower):
        found.add("horusec")

    if re.search(r"checkmarx/ast-github-action", full_lower, re.IGNORECASE) or re.search(r"\bcx\s+scan\b", lower):
        found.add("checkmarx")

    if re.search(r"uses:\s*[^\n#]*shiftleft/scan", full_lower, re.IGNORECASE):
        found.add("shiftleft-scan")

    if (
        re.search(r"\btrivy\s+(fs|config|filesystem)\b", lower)
        or "scan-type: 'fs'" in lower
        or 'scan-type: "fs"' in lower
    ):
        found.add("trivy-fs-config")
    if "aquasecurity/trivy-action" in full_lower and (
        "fs" in full_lower or "config" in full_lower or "misconfig" in full_lower
    ):
        found.add("trivy-fs-config")

    if re.search(r"\bflake8-bugbear\b", lower) or re.search(r"flake8.*bugbear", lower):
        found.add("flake8-bugbear")
    if re.search(r"\bgosec\b", lower):
        found.add("gosec")
    if re.search(r"\bspotbugs\b", lower):
        found.add("spotbugs")
    if re.search(r"\bveracode\b", lower):
        found.add("veracode")
    if re.search(r"\bsonarqube\b", lower) or re.search(r"\bsonarcloud\b", lower):
        found.add("sonarqube")
    if re.search(r"\bbearer\s+(scan|cli)\b", lower) or re.search(r"uses:\s*[^\n#]*\bbearer\b", full_lower, re.I):
        found.add("bearer")

    return found


def _flatten_run_text(step: dict[str, Any]) -> str:
    r = step.get("run")
    if isinstance(r, str):
        return r
    if isinstance(r, dict):
        return "\n".join(str(v) for v in r.values() if isinstance(v, (str, int, float)))
    return ""


def _checkout_uses_non_default_token(step: dict[str, Any]) -> bool:
    uses = str(step.get("uses", "")).lower()
    if "actions/checkout" not in uses:
        return False
    w = step.get("with")
    if not isinstance(w, dict) or "token" not in w:
        return False
    tok = str(w.get("token", "")).lower().replace(" ", "")
    if not tok:
        return False
    return "secrets.github_token" not in tok and "${{github.token}}" not in tok


_SENSITIVE_FOR_LEAST_PRIV: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bdocker\s+push\b", re.I), "docker push"),
    (re.compile(r"\bgh\s+release\b", re.I), "gh release"),
    (re.compile(r"\baws\s+(\S+\s+){0,6}deploy\b", re.I), "aws deploy"),
    (re.compile(r"\baz\s+deployment\b", re.I), "az deployment"),
    (re.compile(r"\bkubectl\s+apply\b", re.I), "kubectl apply"),
    (re.compile(r"\bhelm\s+upgrade\b", re.I), "helm upgrade"),
    (re.compile(r"\bgcloud\s+(\S+\s+){0,6}deploy\b", re.I), "gcloud deploy"),
    (re.compile(r"\btwine\s+upload\b", re.I), "twine upload"),
    (re.compile(r"\bnpm\s+publish\b", re.I), "npm publish"),
    (re.compile(r"\bcargo\s+publish\b", re.I), "cargo publish"),
    (re.compile(r"\bpypi\b.*\bupload\b|\bpublish.*pypi\b", re.I), "pypi publish"),
)


def _step_sensitive_for_least_privilege(step: dict[str, Any]) -> bool:
    blob = (str(step.get("uses", "")) + "\n" + _flatten_run_text(step)).lower()
    if "upload-release-asset" in blob:
        return True
    return any(rx.search(blob) for rx, _ in _SENSITIVE_FOR_LEAST_PRIV)


def _collect_implicit_permission_risks(  # noqa: C901
    data: dict[str, Any],
    path: Path,
    out: list[tuple[Path, str, str]],
) -> None:
    """Detect jobs that combine sensitive operations or PAT checkout without explicit ``permissions``."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return
    workflow_has_top = "permissions" in data
    seen: set[tuple[str, str]] = set()
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_has_perm = "permissions" in job
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            if _checkout_uses_non_default_token(step) and not job_has_perm:
                key = (str(job_name), f"{idx}-checkout-token")
                if key not in seen:
                    seen.add(key)
                    out.append(
                        (
                            path,
                            str(job_name),
                            f"step {idx}: actions/checkout uses a non-default `token` but the job has no "
                            f"explicit `permissions` mapping.",
                        )
                    )
            if _step_sensitive_for_least_privilege(step) and not job_has_perm:
                key = (str(job_name), f"{idx}-sensitive")
                if key not in seen:
                    seen.add(key)
                    out.append(
                        (
                            path,
                            str(job_name),
                            f"step {idx}: sensitive deploy/publish pattern without explicit job-level `permissions`.",
                        )
                    )
        if not workflow_has_top and not job_has_perm:
            blob = "\n".join(
                str(cast(dict[str, Any], s).get("uses", "")) + "\n" + _flatten_run_text(cast(dict[str, Any], s))
                for s in steps
                if isinstance(s, dict)
            ).lower()
            for rx, label in _SENSITIVE_FOR_LEAST_PRIV:
                if rx.search(blob):
                    key = (str(job_name), "no-top-level-perms")
                    if key not in seen:
                        seen.add(key)
                        out.append(
                            (
                                path,
                                str(job_name),
                                f"workflow omits top-level `permissions` while job {job_name!r} references "
                                f"{label} (or similar) — add explicit least-privilege permissions.",
                            )
                        )
                    break


def _workflow_has_oidc_posture(raw: str, data: dict[str, Any]) -> bool:
    if "id-token: write" in raw.lower():
        return True
    perms = data.get("permissions")
    if isinstance(perms, dict) and str(perms.get("id-token", "")).lower() == "write":
        return True
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            jperms = job.get("permissions")
            if isinstance(jperms, dict) and str(jperms.get("id-token", "")).lower() == "write":
                return True
            # Provider-specific OIDC action patterns (structural step scan)
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                raw_with = step.get("with")
                with_block: dict[str, Any] = raw_with if isinstance(raw_with, dict) else {}
                if uses.startswith("aws-actions/configure-aws-credentials") and "role-to-assume" in with_block:
                    return True
                if uses.startswith("google-github-actions/auth") and "workload_identity_provider" in with_block:
                    return True
                # azure/login with client-id (not creds) indicates OIDC federation
                if uses.startswith("azure/login") and "client-id" in with_block and "creds" not in with_block:
                    return True
    return False


def analyze_workflows(repo_root: Path) -> WorkflowAnalysis:  # noqa: C901
    """Scan `.github/workflows` for static patterns."""

    result = WorkflowAnalysis()
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return result

    signal_acc: set[str] = set()
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        result.workflow_paths.append(path)
        raw = path.read_text(encoding="utf-8", errors="replace")

        if _content_has_token(raw, "pull_request_target"):
            result.uses_pull_request_target.append(path)

        signal_acc.update(_collect_sast_ci_signals(raw))
        if re.search(r"dependency-review-action", raw, re.IGNORECASE) or re.search(
            r"advanced-security\/dependency-review-action", raw, re.IGNORECASE
        ):
            result.has_dependency_review = True
        if re.search(
            r"actions/attest-build-provenance|actions/attest\b|slsa|provenance|attestation"
            r"|slsa-framework/slsa-github-generator|sigstore/cosign-installer|cosign\s+sign",
            raw,
            re.IGNORECASE,
        ):
            result.has_artifact_attestation = True

        if (
            re.search(
                r"(?m)(^\s*merge_group:\s*$|merge-queue|github\s+merge\s+queue)",
                raw,
                re.IGNORECASE,
            )
            and path not in result.merge_queue_signal_paths
        ):
            result.merge_queue_signal_paths.append(path)
        _scan_reusable_workflow_pins(
            raw,
            path,
            mutable_out=result.reusable_workflow_mutable_ref_paths,
            call_out=result.reusable_workflow_call_paths,
        )

        try:
            data: Any = load_yaml_file(path)
        except Exception as exc:  # noqa: BLE001 - surface parse error without crashing engine
            result.parse_errors.append((path, str(exc)))
            _scan_uses_for_mutable(raw, path, result.mutable_action_refs)
            continue

        if not isinstance(data, dict):
            result.parse_errors.append((path, "workflow root must be a mapping"))
            _scan_uses_for_mutable(raw, path, result.mutable_action_refs)
            continue

        if "permissions" not in data:
            result.missing_top_level_permissions.append(path)

        perms = data.get("permissions")
        if perms == "write-all" or perms == "read-all":
            result.suspicious_permissions.append((path, str(perms)))
        elif isinstance(perms, dict) and perms.get("contents") == "write":
            result.suspicious_permissions.append((path, "contents: write at workflow level"))

        _scan_uses_for_mutable(raw, path, result.mutable_action_refs)

        jobs = data.get("jobs")
        if isinstance(jobs, dict):
            if _contains_pr_event(data, raw):
                for job in jobs.values():
                    if isinstance(job, dict) and _is_self_hosted_runs_on(job.get("runs-on")):
                        result.pr_self_hosted_runner_paths.append(path)
                        break

            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                if (
                    isinstance(job.get("uses"), str)
                    and job.get("secrets") == "inherit"
                    and path not in result.reusable_secrets_inherit_paths
                ):
                    result.reusable_secrets_inherit_paths.append(path)
                jperms = job.get("permissions")
                if jperms == "write-all":
                    result.broad_job_permissions.append((path, f"{job_name}: write-all"))
                elif isinstance(jperms, dict):
                    for scope in ("contents", "actions", "packages", "deployments"):
                        if str(jperms.get(scope, "")).lower() == "write":
                            result.broad_job_permissions.append((path, f"{job_name}: {scope}=write"))
                            break

            _collect_implicit_permission_risks(data, path, result.implicit_permission_risks)

        if _detect_release_workflow(data, raw):
            result.release_workflow_paths.append(path)
            if "concurrency" not in data:
                result.release_workflows_missing_concurrency.append(path)

        if re.search(
            r"aws-actions/configure-aws-credentials|azure/login|google-github-actions/auth|gcloud auth|kubectl|helm",
            raw,
            re.IGNORECASE,
        ):
            result.cloud_deploy_workflow_paths.append(path)
            if _workflow_has_oidc_posture(raw, data):
                result.cloud_deploy_with_oidc_paths.append(path)

    result.sast_ci_signals = sorted(signal_acc)
    result.has_codeql_or_security_scan = bool(signal_acc)

    return result
