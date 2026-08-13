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
    if r.startswith(("${{", "./", "docker://")):
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


def _on_block(data: dict[str, Any]) -> Any:
    """Return a workflow's trigger block, under whichever key YAML parked it.

    ``on`` is a YAML 1.1 boolean. An unquoted ``on:`` in a GitHub Actions workflow --
    which is how every workflow in the wild is written -- parses to the key ``True``,
    not to the string ``"on"``. So ``data.get("on")`` returns ``None`` for real files
    and only ever worked on hand-built dicts in tests.

    Both callers had a raw-text fallback that quietly absorbed this, which is why it
    went unnoticed: the parsed branch never ran, the substring branch always did, and
    the substring branch cannot tell a trigger from a comment.
    """

    block = data.get("on")
    # ``data`` is typed ``dict[str, Any]`` because every other key in a workflow is a
    # string; the boolean key is real at runtime regardless of the annotation.
    return cast(dict[Any, Any], data).get(True) if block is None else block


def _contains_pr_event(data: dict[str, Any]) -> bool:
    """True when the workflow is triggered by a pull request."""

    on_block = _on_block(data)
    if isinstance(on_block, str):
        return on_block in {"pull_request", "pull_request_target"}
    if isinstance(on_block, list):
        return any(item in {"pull_request", "pull_request_target"} for item in on_block)
    if isinstance(on_block, dict):
        return "pull_request" in on_block or "pull_request_target" in on_block
    return False


def _is_self_hosted_runs_on(value: Any) -> bool:
    if isinstance(value, str):
        return "self-hosted" in value.lower()
    if isinstance(value, list):
        return any(isinstance(x, str) and "self-hosted" in x.lower() for x in value)
    return False


#: Actions whose presence means the workflow ships something outward.
_RELEASE_ACTION_RE = re.compile(
    r"(?:^|/)(?:"
    r"gh-action-pypi-publish|action-gh-release|create-release|release-action|release-drafter"
    r"|goreleaser-action|release-please-action|release-please|semantic-release"
    r"|deploy-pages|github-pages-deploy-action|action-electron-builder"
    r"|build-push-action|ghcr-push"
    r")\b"
)

#: ``run:`` commands that publish or deploy. Anchored on the verb at the START, so prose
#: that merely mentions a release does not match.
#:
#: Deliberately NOT anchored at the end. The first version closed with ``)\b`` and wrote the
#: JVM alternatives as ``\bpublish\b``, which requires a word boundary after the verb -- and a
#: following capital letter never provides one. That silently dropped
#: ``./gradlew publishToSonatype``, ``publishToMavenCentral`` and ``sbt publishSigned``, which
#: is how essentially every JVM project publishes to Maven Central. Those workflows answered
#: "No release or deploy workflow detected", and the substring detector this replaced had
#: caught them, so it was a regression rather than a pre-existing gap.
#:
#: The cost of dropping the trailing boundary is that ``cargo publisher`` would match. That is
#: not a shape anyone writes, and missing a real release workflow is the worse failure.
_RELEASE_RUN_RE = re.compile(
    r"\b(?:"
    r"twine\s+upload"
    r"|(?:npm|yarn|pnpm)\s+publish"
    r"|(?:poetry|flit|uv|hatch|maturin)\s+publish"
    r"|cargo\s+publish"
    r"|gem\s+push"
    r"|(?:dotnet\s+)?nuget\s+push"
    r"|helm\s+push"
    r"|(?:docker|podman|buildah)\s+push"
    r"|docker\s+buildx\s+(?:build|bake)[^\n]*--push"
    r"|skopeo\s+copy"
    r"|gh\s+release\s+(?:create|upload)"
    r"|goreleaser\s+release"
    r"|mvn\b[^\n]*\bdeploy"
    r"|gradle\w*\b[^\n]*\bpublish"
    r"|sbt\b[^\n]*\bpublish"
    r"|kubectl\s+(?:apply|rollout|set\s+image)"
    r"|helm\s+upgrade"
    r"|terraform\s+apply"
    r"|pulumi\s+up"
    r"|(?:serverless|sls|cdk)\s+deploy"
    r"|aws\s+s3\s+sync"
    r")"
)

#: Workflow / job names and job ids that declare release intent. Matched only on the
#: ``name:`` fields and job keys the author chose -- declared intent, not free text.
_RELEASE_NAME_RE = re.compile(r"\b(?:release|deploy|publish|package)\w*\b", re.IGNORECASE)


def _release_trigger(on_block: Any) -> bool:
    """True when the workflow's triggers alone mark it as a release workflow.

    ``workflow_dispatch`` is deliberately absent. A manually-dispatched workflow is a
    manually-dispatched workflow; treating it as a release made every repo with a manual
    utility job answer for release concurrency.
    """

    if isinstance(on_block, str):
        return on_block == "release"
    if isinstance(on_block, list):
        return "release" in on_block
    if not isinstance(on_block, dict):
        return False
    if "release" in on_block:
        return True
    push = on_block.get("push")
    return isinstance(push, dict) and bool(push.get("tags") or push.get("tags-ignore"))


def _job_publishes(job: Any) -> bool:
    """True when any step in *job* runs a publishing action or command."""

    if not isinstance(job, dict):
        return False
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            continue
        uses = step.get("uses")
        if isinstance(uses, str) and _RELEASE_ACTION_RE.search(uses.split("@", 1)[0].lower()):
            return True
        run = step.get("run")
        if isinstance(run, str) and _RELEASE_RUN_RE.search(run.lower()):
            return True
    return False


def _releasing_job_ids(jobs: dict[str, Any]) -> set[str]:
    """Job ids that actually ship something, by name or by what their steps run."""

    return {
        str(job_id)
        for job_id, job in jobs.items()
        if _RELEASE_NAME_RE.search(str(job_id))
        or (isinstance(job, dict) and _RELEASE_NAME_RE.search(str(job.get("name", ""))))
        or _job_publishes(job)
    }


def _declares_concurrency(data: dict[str, Any]) -> bool:
    """True when concurrency protects the publishing, at the workflow level or on the job.

    GH-REL-021 reports a workflow as not declaring concurrency "at the workflow or job
    level", but the check only ever looked at the top level. Job-level ``concurrency:`` is
    valid GitHub Actions and is the natural way to write it when one job of several
    publishes, so a workflow that did exactly what the remediation asks was failed and told
    it had not.

    Widening it to *any* job was too much, and adversarial review caught it before release:
    a workflow with a ``concurrency`` group on a ``docs`` job and a bare ``publish`` job
    running ``twine upload`` reported PASS, which is precisely the double-publish this
    control exists to prevent. The group has to be where the publishing happens.

    Every releasing job must carry one -- ``any`` would let a two-publisher workflow pass on
    the strength of protecting one of them. When no job looks like the releasing job, the
    signal came from the trigger alone and there is nothing to attribute a job-level group
    to, so only a workflow-level declaration counts.
    """

    if "concurrency" in data:
        return True
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return False
    releasing = _releasing_job_ids(jobs)
    if not releasing:
        return False
    return all(isinstance(jobs[job_id], dict) and "concurrency" in jobs[job_id] for job_id in releasing)


def _detect_release_workflow(data: dict[str, Any]) -> bool:
    """True when this workflow releases, deploys, or publishes something.

    Read from the parsed structure, never from the workflow text. The previous version
    lowercased the whole file and returned True on the bare substring ``release``,
    ``deploy``, ``publish``, or ``package`` -- which meant a comment decided the answer.
    Every workflow template this kit ships carries the line

        # Actions are pinned to immutable commit SHAs (release tag in the trailing ...

    so all three were classified as release workflows and failed GH-REL-021 for missing
    ``concurrency:``. An adopter running ``init --with-workflow`` and then ``evaluate``
    got a FAIL, produced by the kit, about a workflow the kit wrote, for a control that
    did not apply to it. Deleting the comment made the finding disappear, which is the
    signature of a detector reading the wrong thing.

    Stripping comments before the scan would fix these three files and leave the design
    intact: any prose in a ``name:`` or an ``echo`` would still decide it. Reading the
    structure removes the whole class -- comments cannot reach these fields at all.

    A workflow counts when its triggers say release (``on: release``, or a tag-filtered
    push), when a job id or name declares it, or when a step actually runs a publishing
    action or command.
    """

    if _release_trigger(_on_block(data)):
        return True
    if _RELEASE_NAME_RE.search(str(data.get("name", ""))):
        return True
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return False
    # Same helper the concurrency check uses, so "is this a release workflow" and "which job
    # is the release" can never answer from different rules.
    return bool(_releasing_job_ids(jobs))


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


# SAST/code-scanning detectors. Each entry is (signal_name, ((pattern, use_full_text), ...)).
# ``use_full_text`` searches the whole raw workflow (``uses:`` refs); otherwise the
# SAST-heuristic body (CLI invocations). All texts are pre-lowercased, so patterns are
# lowercase and need no IGNORECASE. ``uses:[^\n#]*`` (not ``uses:\s*[^\n#]*``) avoids the
# ambiguous adjacent quantifiers that trip ReDoS detection — ``[^\n#]*`` already covers
# leading whitespace.
_SAST_SIGNAL_RULES: tuple[tuple[str, tuple[tuple[re.Pattern[str], bool], ...]], ...] = (
    (
        "codeql",
        (
            (re.compile(r"github/codeql-action/\w+"), True),
            (re.compile(r"\bcodeql\s+database\b"), False),
            (re.compile(r"\bcodeql\s+analyze\b"), False),
        ),
    ),
    (
        "semgrep",
        (
            (re.compile(r"uses:[^\n#]*(returntocorp/semgrep|semgrep/semgrep|semgrep-action)"), True),
            (re.compile(r"\bsemgrep\s+(scan|ci)\b"), False),
            (re.compile(r"\bsemgrep\s[^\n]*--config\b"), False),
        ),
    ),
    (
        "bandit",
        (
            (re.compile(r"\bpython\s+-m\s+bandit\b"), False),
            (re.compile(r"\bbandit\s+-r\b"), False),
            (re.compile(r"uses:[^\n#]*bandit"), True),
        ),
    ),
    ("snyk-code", ((re.compile(r"\bsnyk\s+code\s+test\b"), False), (re.compile(r"snyk-code"), False))),
    (
        "sonar",
        (
            (re.compile(r"uses:[^\n#]*sonarsource/sonarcloud-github-action"), True),
            (re.compile(r"uses:[^\n#]*sonarqube"), True),
            (re.compile(r"\bsonar-scanner\b"), False),
        ),
    ),
    ("brakeman", ((re.compile(r"uses:[^\n#]*brakeman"), True), (re.compile(r"\bbrakeman\s+(\.|--)"), False))),
    ("horusec", ((re.compile(r"uses:[^\n#]*horusec"), True), (re.compile(r"\bhorusec\s+cli\b"), False))),
    ("checkmarx", ((re.compile(r"checkmarx/ast-github-action"), True), (re.compile(r"\bcx\s+scan\b"), False))),
    ("shiftleft-scan", ((re.compile(r"uses:[^\n#]*shiftleft/scan"), True),)),
    ("flake8-bugbear", ((re.compile(r"\bflake8-bugbear\b"), False), (re.compile(r"flake8.*bugbear"), False))),
    ("gosec", ((re.compile(r"\bgosec\b"), False),)),
    ("spotbugs", ((re.compile(r"\bspotbugs\b"), False),)),
    ("veracode", ((re.compile(r"\bveracode\b"), False),)),
    ("sonarqube", ((re.compile(r"\bsonarqube\b"), False), (re.compile(r"\bsonarcloud\b"), False))),
    ("bearer", ((re.compile(r"\bbearer\s+(scan|cli)\b"), False), (re.compile(r"uses:[^\n#]*\bbearer\b"), True))),
)


def _trivy_fs_config_signals(lower: str, full_lower: str) -> bool:
    """True when a Trivy filesystem/config scan is referenced (CLI or aquasecurity/trivy-action)."""

    if (
        re.search(r"\btrivy\s+(fs|config|filesystem)\b", lower)
        or "scan-type: 'fs'" in lower
        or 'scan-type: "fs"' in lower
    ):
        return True
    return "aquasecurity/trivy-action" in full_lower and (
        "fs" in full_lower or "config" in full_lower or "misconfig" in full_lower
    )


def _collect_sast_ci_signals(raw: str) -> set[str]:
    """Detect plausible CI SAST / code scanning for SEC-CODEQL-010 (not mere tool-name mentions)."""

    lower = _workflow_body_for_sast_heuristics(raw).lower()
    full_lower = raw.lower()
    found: set[str] = set()
    for signal, patterns in _SAST_SIGNAL_RULES:
        for pattern, use_full in patterns:
            if pattern.search(full_lower if use_full else lower):
                found.add(signal)
                break
    if _trivy_fs_config_signals(lower, full_lower):
        found.add("trivy-fs-config")
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


def _add_perm_risk(
    out: list[tuple[Path, str, str]],
    seen: set[tuple[str, str]],
    job_name: str,
    key_suffix: str,
    path: Path,
    message: str,
) -> None:
    """Append a (path, job, message) risk once per (job, key_suffix)."""

    key = (job_name, key_suffix)
    if key not in seen:
        seen.add(key)
        out.append((path, job_name, message))


def _collect_step_permission_risks(
    job_name: str,
    steps: list[Any],
    job_has_perm: bool,
    path: Path,
    seen: set[tuple[str, str]],
    out: list[tuple[Path, str, str]],
) -> None:
    for idx, step in enumerate(steps):
        if not isinstance(step, dict) or job_has_perm:
            continue
        if _checkout_uses_non_default_token(step):
            _add_perm_risk(
                out,
                seen,
                job_name,
                f"{idx}-checkout-token",
                path,
                f"step {idx}: actions/checkout uses a non-default `token` but the job has no "
                f"explicit `permissions` mapping.",
            )
        if _step_sensitive_for_least_privilege(step):
            _add_perm_risk(
                out,
                seen,
                job_name,
                f"{idx}-sensitive",
                path,
                f"step {idx}: sensitive deploy/publish pattern without explicit job-level `permissions`.",
            )


def _collect_no_top_perm_risk(
    job_name: str,
    steps: list[Any],
    path: Path,
    seen: set[tuple[str, str]],
    out: list[tuple[Path, str, str]],
) -> None:
    blob = "\n".join(
        str(cast(dict[str, Any], s).get("uses", "")) + "\n" + _flatten_run_text(cast(dict[str, Any], s))
        for s in steps
        if isinstance(s, dict)
    ).lower()
    for rx, label in _SENSITIVE_FOR_LEAST_PRIV:
        if rx.search(blob):
            _add_perm_risk(
                out,
                seen,
                job_name,
                "no-top-level-perms",
                path,
                f"workflow omits top-level `permissions` while job {job_name!r} references "
                f"{label} (or similar) — add explicit least-privilege permissions.",
            )
            break


def _collect_implicit_permission_risks(
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
        _collect_step_permission_risks(str(job_name), steps, job_has_perm, path, seen, out)
        if not workflow_has_top and not job_has_perm:
            _collect_no_top_perm_risk(str(job_name), steps, path, seen, out)


def _step_indicates_oidc(step: Any) -> bool:
    """True when a step uses a provider OIDC-federation action (AWS/GCP/Azure)."""

    if not isinstance(step, dict):
        return False
    uses = str(step.get("uses", ""))
    raw_with = step.get("with")
    with_block: dict[str, Any] = raw_with if isinstance(raw_with, dict) else {}
    if uses.startswith("aws-actions/configure-aws-credentials") and "role-to-assume" in with_block:
        return True
    if uses.startswith("google-github-actions/auth") and "workload_identity_provider" in with_block:
        return True
    # azure/login with client-id (not creds) indicates OIDC federation
    return uses.startswith("azure/login") and "client-id" in with_block and "creds" not in with_block


def _job_indicates_oidc(job: Any) -> bool:
    """True when a job declares ``id-token: write`` or contains an OIDC-federation step."""

    if not isinstance(job, dict):
        return False
    jperms = job.get("permissions")
    if isinstance(jperms, dict) and str(jperms.get("id-token", "")).lower() == "write":
        return True
    return any(_step_indicates_oidc(step) for step in job.get("steps") or [])


def _workflow_has_oidc_posture(raw: str, data: dict[str, Any]) -> bool:
    if "id-token: write" in raw.lower():
        return True
    perms = data.get("permissions")
    if isinstance(perms, dict) and str(perms.get("id-token", "")).lower() == "write":
        return True
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return False
    return any(_job_indicates_oidc(job) for job in jobs.values())


def _scan_workflow_raw(raw: str, path: Path, result: WorkflowAnalysis, signal_acc: set[str]) -> None:
    """Raw-text (pre-parse) signals: PR target, SAST, dependency-review, attestation, merge-queue, reusable pins."""

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
        re.search(r"(?m)(^\s*merge_group:\s*$|merge-queue|github\s+merge\s+queue)", raw, re.IGNORECASE)
        and path not in result.merge_queue_signal_paths
    ):
        result.merge_queue_signal_paths.append(path)
    _scan_reusable_workflow_pins(
        raw,
        path,
        mutable_out=result.reusable_workflow_mutable_ref_paths,
        call_out=result.reusable_workflow_call_paths,
    )


def _classify_top_level_permissions(data: dict[str, Any], path: Path, result: WorkflowAnalysis) -> None:
    if "permissions" not in data:
        result.missing_top_level_permissions.append(path)
    perms = data.get("permissions")
    if perms in ("write-all", "read-all"):
        result.suspicious_permissions.append((path, str(perms)))
    elif isinstance(perms, dict) and perms.get("contents") == "write":
        result.suspicious_permissions.append((path, "contents: write at workflow level"))


def _classify_job_permissions(job_name: str, job: dict[str, Any], path: Path, result: WorkflowAnalysis) -> None:
    jperms = job.get("permissions")
    if jperms == "write-all":
        result.broad_job_permissions.append((path, f"{job_name}: write-all"))
    elif isinstance(jperms, dict):
        for scope in ("contents", "actions", "packages", "deployments"):
            if str(jperms.get(scope, "")).lower() == "write":
                result.broad_job_permissions.append((path, f"{job_name}: {scope}=write"))
                break


def _scan_workflow_jobs(jobs: dict[str, Any], data: dict[str, Any], path: Path, result: WorkflowAnalysis) -> None:
    if _contains_pr_event(data):
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
        _classify_job_permissions(str(job_name), job, path, result)
    _collect_implicit_permission_risks(data, path, result.implicit_permission_risks)


def _scan_workflow_parsed(data: dict[str, Any], raw: str, path: Path, result: WorkflowAnalysis) -> None:
    """Parsed-dict signals: permissions, jobs, mutable refs, release + cloud-deploy posture."""

    _classify_top_level_permissions(data, path, result)
    _scan_uses_for_mutable(raw, path, result.mutable_action_refs)
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        _scan_workflow_jobs(jobs, data, path, result)
    if _detect_release_workflow(data):
        result.release_workflow_paths.append(path)
        if not _declares_concurrency(data):
            result.release_workflows_missing_concurrency.append(path)
    if re.search(
        r"aws-actions/configure-aws-credentials|azure/login|google-github-actions/auth|gcloud auth|kubectl|helm",
        raw,
        re.IGNORECASE,
    ):
        result.cloud_deploy_workflow_paths.append(path)
        if _workflow_has_oidc_posture(raw, data):
            result.cloud_deploy_with_oidc_paths.append(path)


def _analyze_one_workflow(path: Path, result: WorkflowAnalysis, signal_acc: set[str]) -> None:
    result.workflow_paths.append(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    _scan_workflow_raw(raw, path, result, signal_acc)
    try:
        data: Any = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001 - surface parse error without crashing engine
        result.parse_errors.append((path, str(exc)))
        _scan_uses_for_mutable(raw, path, result.mutable_action_refs)
        return
    if not isinstance(data, dict):
        result.parse_errors.append((path, "workflow root must be a mapping"))
        _scan_uses_for_mutable(raw, path, result.mutable_action_refs)
        return
    _scan_workflow_parsed(data, raw, path, result)


def analyze_workflows(repo_root: Path) -> WorkflowAnalysis:
    """Scan `.github/workflows` for static patterns."""

    result = WorkflowAnalysis()
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return result

    signal_acc: set[str] = set()
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        _analyze_one_workflow(path, result, signal_acc)

    result.sast_ci_signals = sorted(signal_acc)
    result.has_codeql_or_security_scan = bool(signal_acc)
    return result
