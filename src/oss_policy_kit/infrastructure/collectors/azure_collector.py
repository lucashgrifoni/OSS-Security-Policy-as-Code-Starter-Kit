"""Collect Azure DevOps evidence via the REST API."""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime
from typing import Any, NoReturn, cast

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors.base import CollectionResult, EvidenceCollector

logger = logging.getLogger(__name__)

# Well-known Azure DevOps policy type identifiers (REST returns ``type.id`` without displayName).
_POLICY_MINIMUM_REVIEWERS = "fa4e907d-c16f-4ac8-9af7-9a14fae485e1"
_POLICY_BUILD = "c6658a15-eed7-46e9-9015-8b68baeacbc3"
_POLICY_COMMENT_REQUIREMENTS = "40e92bfc-8e2c-425a-8d25-f4dad55efcdb"
_POLICY_RESET_REVIEWER_VOTES = "06c46c03-9e68-41af-9d0d-6410d4ee82f0"
_POLICY_BLOCK_LAST_PUSHER = "ad9f688a-9619-41ac-8c2b-21224097d594"
_POLICY_BYPASS = "d84a17f0-13d1-4966-8b58-3f17f74ebbac"


def _utc_iso_timestamp() -> str:
    """Return current UTC time as ISO-8601 with ``Z`` suffix (no micros)."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso_date_prefix(ts: str) -> str:
    return ts[:10] if len(ts) >= 10 else ts


def _parse_project_repo(repo_slug: str) -> tuple[str, str]:
    parts = repo_slug.strip().split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        msg = f"Invalid Azure repo slug {repo_slug!r}; expected 'ProjectName/repoName'."
        raise ValueError(msg)
    return parts[0], parts[1]


def _azure_headers(pat: str) -> dict[str, str]:
    """Build headers for Azure DevOps PAT (HTTP Basic with empty username)."""

    token = base64.b64encode(f":{pat}".encode()).decode("ascii")
    return {
        "Accept": "application/json",
        "Authorization": f"Basic {token}",
        "User-Agent": "oss-policy-kit-collect-evidence",
    }


def _enforce_rate_limit(response: Any) -> None:
    if response.status_code == 429:
        retry = response.headers.get("retry-after", "")
        hint = f" Retry-After: {retry}." if retry else ""
        raise RateLimitError("Azure DevOps API rate limit exceeded." + hint)


def _raise_permission(url: str, status: int) -> NoReturn:
    """Translate an Azure DevOps permission-like status into a typed collector error.

    Always raises; never returns. The ``NoReturn`` annotation documents control flow for callers.
    """

    raise CollectionPermissionError(
        f"Azure DevOps API returned HTTP {status} for {url}. "
        "Check AZURE_DEVOPS_TOKEN scopes (Code: Read, Build: Read, Project and Team: Read) "
        "and that the project/repo exists."
    )


def _policy_applies_to_repository(cfg: dict[str, Any], repo_id: str) -> bool:
    """Return True when the policy configuration scope targets *repo_id*."""

    settings = cfg.get("settings")
    if not isinstance(settings, dict):
        return False
    scope_obj = settings.get("scope")
    scopes: list[dict[str, Any]] = []
    if isinstance(scope_obj, list):
        scopes = [cast(dict[str, Any], s) for s in scope_obj if isinstance(s, dict)]
    elif isinstance(scope_obj, dict):
        scopes = [cast(dict[str, Any], scope_obj)]
    for sc in scopes:
        rid = sc.get("repositoryId")
        if rid is not None and str(rid).lower() == repo_id.lower():
            return True
    return False


def _infer_branch_posture(configs: list[dict[str, Any]], repo_id: str) -> dict[str, bool]:
    """Map policy configurations to schema ``posture`` booleans for *repo_id*."""

    posture = {
        "minimum_reviewers_enabled": False,
        "build_validation_enabled": False,
        "comment_resolution_required": False,
        "reset_votes_on_push": False,
        "block_last_pusher_approval": False,
        "bypass_policy_restricted": False,
    }
    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        if not _policy_applies_to_repository(cfg, repo_id):
            continue
        tid = str((cfg.get("type") or {}).get("id", "")).lower()
        settings = cast(dict[str, Any], cfg.get("settings") or {})
        if tid == _POLICY_MINIMUM_REVIEWERS.lower():
            posture["minimum_reviewers_enabled"] = int(settings.get("minimumApproverCount", 0) or 0) >= 1
        elif tid == _POLICY_BUILD.lower():
            posture["build_validation_enabled"] = True
        elif tid == _POLICY_COMMENT_REQUIREMENTS.lower():
            posture["comment_resolution_required"] = True
        elif tid == _POLICY_RESET_REVIEWER_VOTES.lower():
            posture["reset_votes_on_push"] = True
        elif tid == _POLICY_BLOCK_LAST_PUSHER.lower():
            posture["block_last_pusher_approval"] = True
        elif tid == _POLICY_BYPASS.lower():
            posture["bypass_policy_restricted"] = not bool(settings.get("allowBypass", True))
    return posture


def _service_endpoint_auth_kind(endpoint: dict[str, Any]) -> str:
    """Map Azure DevOps service endpoint ``authorization.scheme`` to evidence schema enum."""

    auth = cast(dict[str, Any], endpoint.get("authorization") or {})
    scheme = str(auth.get("scheme", "") or "").lower()
    if scheme == "workloadidentityfederation":
        return "workload_identity_federation"
    if scheme == "managedserviceidentity":
        return "managed_identity"
    if scheme in ("usernamepassword", "token"):
        return "secret"
    if scheme in ("certificate",):
        return "certificate"
    return "unknown"


def _azure_collection_block(collected_at: str, source_url: str) -> dict[str, Any]:
    return {
        "evidence_collection_method": "live",
        "collected_at": collected_at,
        "source_url": source_url,
        "mode": "api",
    }


def _check_configuration_looks_like_approval(cfg: dict[str, Any]) -> bool:
    t = cfg.get("type")
    if isinstance(t, dict):
        name = str(t.get("name", "")).lower()
        if "approval" in name:
            return True
    return False


def _environment_has_approval_check(client: Any, project: str, environment_id: str) -> bool | None:
    """Return whether an environment-scoped approval check exists, or ``None`` when the API is unusable."""

    for ver in ("7.2-preview.1", "7.1-preview.1"):
        url = (
            f"/{project}/_apis/check/configurations?resourceType=environment&resourceId={environment_id}"
            f"&api-version={ver}"
        )
        r = client.get(url)
        _enforce_rate_limit(r)
        if r.status_code in {401, 403}:
            return None
        if r.status_code == 404:
            continue
        if r.status_code != 200:
            return None
        body = cast(dict[str, Any], r.json())
        vals = body.get("value")
        if not isinstance(vals, list):
            return False
        return any(isinstance(item, dict) and _check_configuration_looks_like_approval(item) for item in vals)
    return None


def _azure_service_connection_posture(
    client: Any, project: str
) -> tuple[list[dict[str, str]], dict[str, bool], str, int]:
    """Return service_connections list, posture booleans, notes, and HTTP status for the endpoints API."""

    sc_url = f"/{project}/_apis/serviceendpoint/endpoints?api-version=7.1"
    r_sc = client.get(sc_url)
    _enforce_rate_limit(r_sc)
    if r_sc.status_code in {401, 403}:
        _raise_permission(f"{client.base_url}{sc_url}", r_sc.status_code)
    if r_sc.status_code not in (200,):
        return (
            [],
            {"service_connection_restricted": False, "federated_identity_preferred": False},
            f"Service connections API returned HTTP {r_sc.status_code}; governance flags left false.",
            int(r_sc.status_code),
        )

    body = cast(dict[str, Any], r_sc.json())
    raw_list = body.get("value")
    endpoints = cast(list[dict[str, Any]], raw_list) if isinstance(raw_list, list) else []
    connections: list[dict[str, str]] = []
    federated = False
    has_username_password = False
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        name = str(ep.get("name", "") or "unknown")
        akind = _service_endpoint_auth_kind(ep)
        connections.append({"name": name, "authentication": akind})
        if akind == "workload_identity_federation":
            federated = True
        if akind == "secret":
            has_username_password = True

    recognizable = any(c["authentication"] not in {"unknown", "secret"} for c in connections)
    restricted = bool(endpoints) and not has_username_password and recognizable
    if not endpoints:
        restricted = False

    return (
        connections,
        {
            "service_connection_restricted": restricted,
            "federated_identity_preferred": federated,
        },
        "serviceendpoint/endpoints: PAT/UsernamePassword endpoints mark service_connection_restricted false; "
        "WorkloadIdentityFederation sets federated_identity_preferred true.",
        200,
    )


def _default_branch_name(repo: dict[str, Any]) -> str:
    ref = str(repo.get("defaultBranch") or "refs/heads/main")
    if ref.startswith("refs/heads/"):
        return ref.removeprefix("refs/heads/")
    return ref.split("/")[-1] if "/" in ref else ref


class AzureDevOpsEvidenceCollector(EvidenceCollector):
    """Collect Azure DevOps evidence JSON files using ``httpx`` (sync)."""

    def __init__(self, *, organization: str, personal_access_token: str) -> None:
        self._org = organization.strip()
        self._pat = personal_access_token
        self._base = f"https://dev.azure.com/{self._org}"

    def collect_sbom_artifact(self, repo_slug: str) -> list[CollectionResult]:
        """Optional hook for **AZ-ARTSBOM-058** (no API payload emitted here).

        Azure DevOps REST (builds, releases, universal packages) does not expose a single portable JSON object
        aligned with ``evidence-azure-sbom-artifact.schema.json`` (digest-bound SBOM linked to a release artifact).
        Maintain ``azure-sbom-artifact.json`` manually or export it from your release pipeline.
        """

        logger.info(
            "collect_sbom_artifact(%r): skipped — digest-bound SBOM artifact evidence is manual/pipeline-only; "
            "see docs/evidence-pack.md.",
            repo_slug,
        )
        return []

    def collect_provenance_artifact(self, repo_slug: str) -> list[CollectionResult]:
        """Optional hook for **AZ-ARTPRV-059** (no API payload emitted here).

        In-toto/SLSA-style provenance bound to a specific artifact digest is not available as a first-class
        REST resource in the same shape as ``evidence-azure-provenance-artifact.schema.json``. Use manual evidence
        or your attestation store integration.
        """

        logger.info(
            "collect_provenance_artifact(%r): skipped — artifact provenance JSON is manual/pipeline-only; "
            "see docs/evidence-pack.md.",
            repo_slug,
        )
        return []

    def collect(self, repo_slug: str) -> list[CollectionResult]:  # noqa: C901
        """Collect branch-policy and pipeline-governance evidence for ``project/repoName``.

        **Environment (required):** ``AZURE_DEVOPS_ORG`` and ``AZURE_DEVOPS_TOKEN`` (or constructor args).

        **PAT scopes (least privilege, read-only):**

        * **Code (read)** — ``vso.code`` / ``Code (read)``: enumerate repositories and read policy configurations.
        * **Build (read)** — ``vso.build``: list YAML pipelines and build definitions where exposed by the API.
        * **Release (read)** — ``vso.release`` (optional): richer pipeline metadata when your org exposes it.
        * **Service connections (read)** — ``vso.serviceendpoint`` / ``Service Endpoints (read)``: federated vs PAT
          posture for **AZ-SCONN-056** / **AZ-WIFEV-057** governance payloads.

        Missing scopes: HTTP **403** is raised as
        :class:`~oss_policy_kit.domain.errors.CollectionPermissionError`; otherwise partial payloads use
        conservative ``false`` / empty lists in governance notes when endpoints are unreachable.

        **Optional (manual-only) hooks:** :meth:`collect_sbom_artifact` / :meth:`collect_provenance_artifact` are
        invoked at the end of a successful run; they do not add files today (see ``docs/evidence-pack.md``).
        """

        try:
            import httpx
        except ImportError as exc:
            msg = "Azure evidence collection requires httpx. Install with: pip install 'oss-policy-kit[azure]'"
            raise RuntimeError(msg) from exc

        project, repo_name = _parse_project_repo(repo_slug)
        collected_at = _utc_iso_timestamp()
        attested_date = _iso_date_prefix(collected_at)
        attested_by = "azure-devops-api-collection"
        results: list[CollectionResult] = []

        try:
            with httpx.Client(
                base_url=self._base,
                headers=_azure_headers(self._pat),
                timeout=60.0,
            ) as client:
                repos_url = f"/{project}/_apis/git/repositories?api-version=7.1"
                r_repos = client.get(repos_url)
                _enforce_rate_limit(r_repos)
                if r_repos.status_code in {401, 403, 404}:
                    _raise_permission(f"{self._base}{repos_url}", r_repos.status_code)
                if r_repos.status_code == 422:
                    logger.warning("Azure returned 422 for %s; aborting collection.", repos_url)
                    return []
                r_repos.raise_for_status()
                body = cast(dict[str, Any], r_repos.json())
                raw_list = body.get("value")
                repos = cast(list[dict[str, Any]], raw_list) if isinstance(raw_list, list) else []
                repo_obj: dict[str, Any] | None = None
                for r in repos:
                    if str(r.get("name", "")).lower() == repo_name.lower():
                        repo_obj = r
                        break
                if repo_obj is None:
                    raise ValueError(f"Repository {repo_name!r} not found in project {project!r}.")

                repo_id = str(repo_obj.get("id", ""))
                if not repo_id:
                    raise ValueError("Repository response missing id.")

                branch = _default_branch_name(repo_obj)

                pol_url = f"/{project}/_apis/policy/configurations?api-version=7.1"
                r_pol = client.get(pol_url)
                _enforce_rate_limit(r_pol)
                if r_pol.status_code in {401, 403}:
                    _raise_permission(f"{self._base}{pol_url}", r_pol.status_code)
                if r_pol.status_code == 404:
                    pol_cfgs: list[dict[str, Any]] = []
                elif r_pol.status_code == 422:
                    logger.warning("Azure returned 422 for %s; using empty policy list.", pol_url)
                    pol_cfgs = []
                else:
                    r_pol.raise_for_status()
                    pol_body = cast(dict[str, Any], r_pol.json())
                    vals = pol_body.get("value")
                    pol_cfgs = cast(list[dict[str, Any]], vals) if isinstance(vals, list) else []

                posture_bp = _infer_branch_posture(pol_cfgs, repo_id)
                bp_payload: dict[str, Any] = {
                    "schema_version": "azure-branch-policies/v1",
                    "attested_at": attested_date,
                    "attested_by": attested_by,
                    "project": project,
                    "repository": repo_name,
                    "branch": branch,
                    "posture": posture_bp,
                    "posture_support": {"policies_api_reachable": r_pol.status_code == 200},
                    "collection": _azure_collection_block(collected_at, f"{self._base}{pol_url}"),
                    "notes": "Derived from Azure DevOps policy configurations API.",
                }
                results.append(
                    CollectionResult(
                        evidence_key="azure-branch-policies",
                        data=bp_payload,
                        source_url=f"{self._base}{pol_url}",
                        collected_at=collected_at,
                    )
                )

                # Pipelines API is polled solely to confirm reachability; the body is not consumed
                # because governance posture is derived from environments, checks, and service endpoints.
                pipe_url = f"/{project}/_apis/pipelines?api-version=7.1"
                r_pipe = client.get(pipe_url)
                _enforce_rate_limit(r_pipe)
                if r_pipe.status_code in {401, 403}:
                    _raise_permission(f"{self._base}{pipe_url}", r_pipe.status_code)
                if r_pipe.status_code in {404, 422}:
                    if r_pipe.status_code == 422:
                        logger.warning("Azure returned 422 for %s; using empty pipelines list.", pipe_url)
                else:
                    r_pipe.raise_for_status()

                env_url = f"/{project}/_apis/distributedtask/environments?api-version=7.1"
                r_env = client.get(env_url)
                _enforce_rate_limit(r_env)
                env_list: list[dict[str, Any]] = []
                if r_env.status_code == 200:
                    eb = cast(dict[str, Any], r_env.json())
                    ev = eb.get("value")
                    if isinstance(ev, list):
                        env_list = [cast(dict[str, Any], x) for x in ev if isinstance(x, dict)]
                elif r_env.status_code in {401, 403, 404, 422}:
                    logger.warning(
                        "Environments API returned HTTP %s for %s; pipeline governance flags may be conservative.",
                        r_env.status_code,
                        env_url,
                    )

                env_count = len(env_list)
                approval_observable = True
                approval_found = False
                if r_env.status_code == 200 and env_list:
                    for env in env_list[:25]:
                        eid = env.get("id")
                        if eid is None:
                            continue
                        sub = _environment_has_approval_check(client, project, str(eid))
                        if sub is None:
                            approval_observable = False
                            break
                        if sub:
                            approval_found = True
                elif r_env.status_code != 200:
                    approval_observable = False

                connections, sc_flags, sc_note, sc_http = _azure_service_connection_posture(client, project)

                gov_posture = {
                    "approvals_required": approval_found,
                    "environment_checks_enabled": env_count > 0 and r_env.status_code == 200,
                    "service_connection_restricted": sc_flags["service_connection_restricted"],
                    "federated_identity_preferred": sc_flags["federated_identity_preferred"],
                }
                posture_support = {
                    "pipelines_api_reachable": r_pipe.status_code == 200,
                    "environments_api_reachable": r_env.status_code == 200,
                    "service_endpoints_api_verified": sc_http == 200,
                    "environment_approval_checks_observable": approval_observable,
                }
                gov_payload: dict[str, Any] = {
                    "schema_version": "azure-pipeline-governance/v1",
                    "attested_at": attested_date,
                    "attested_by": attested_by,
                    "project": project,
                    "posture": gov_posture,
                    "posture_support": posture_support,
                    "collection": _azure_collection_block(collected_at, f"{self._base}{pipe_url}"),
                    "notes": (
                        "Derived from pipelines, environments, check/configurations (approval checks), "
                        f"and serviceendpoint/endpoints APIs. {sc_note} "
                        "When posture_support flags are false, downstream evaluators should not treat "
                        "missing API data as proof of strong governance."
                    ),
                }
                if connections:
                    gov_payload["service_connections"] = connections
                results.append(
                    CollectionResult(
                        evidence_key="azure-pipeline-governance",
                        data=gov_payload,
                        source_url=f"{self._base}{pipe_url}",
                        collected_at=collected_at,
                    )
                )

        except (CollectionPermissionError, RateLimitError, ValueError, RuntimeError):
            raise
        except httpx.RequestError as exc:
            raise CollectionNetworkError(f"Azure DevOps network error: {exc}") from exc
        except Exception as exc:
            raise CollectionNetworkError(f"Azure DevOps evidence collection failed: {exc}") from exc

        results.extend(self.collect_sbom_artifact(repo_slug))
        results.extend(self.collect_provenance_artifact(repo_slug))
        return results
