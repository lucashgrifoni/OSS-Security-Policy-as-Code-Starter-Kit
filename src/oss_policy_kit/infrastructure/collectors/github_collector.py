"""Collect GitHub repository evidence via the public REST API."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, cast

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors.base import CollectionResult, EvidenceCollector

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


def _utc_iso_timestamp() -> str:
    """Return current UTC time as ISO-8601 with ``Z`` suffix (no micros)."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso_date_prefix(ts: str) -> str:
    """First 10 chars ``YYYY-MM-DD`` from an ISO timestamp."""

    return ts[:10] if len(ts) >= 10 else ts


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "oss-policy-kit-collect-evidence",
    }


def _status_block_enabled(block: object) -> bool:
    if not isinstance(block, dict):
        return False
    return str(block.get("status", "")).lower() == "enabled"


def _github_collection_block(collected_at: str, source_url: str) -> dict[str, str]:
    """Standard collection metadata for API-backed GitHub evidence files."""

    return {
        "evidence_collection_method": "live",
        "collected_at": collected_at,
        "source_url": source_url,
        "mode": "api",
    }


def _parse_owner_repo(repo_slug: str) -> tuple[str, str]:
    parts = repo_slug.strip().split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        msg = f"Invalid GitHub repo slug {repo_slug!r}; expected 'owner/repo'."
        raise ValueError(msg)
    return parts[0], parts[1]


def _enforce_rate_limit(response: Any) -> None:
    rem = response.headers.get("x-ratelimit-remaining")
    if response.status_code == 429 or rem == "0":
        retry = response.headers.get("retry-after", "")
        hint = f" Retry-After: {retry}." if retry else ""
        raise RateLimitError(
            "GitHub API rate limit exceeded. Wait and retry, or use a token with higher rate limits." + hint
        )


def _raise_permission(method: str, url: str, status: int) -> None:
    raise CollectionPermissionError(
        f"GitHub API returned HTTP {status} for {method} {url}. "
        "Ensure GITHUB_TOKEN is set with scopes that can read administration/security "
        "(for example ``repo`` on private repositories, or appropriate org permissions)."
    )


class GitHubEvidenceCollector(EvidenceCollector):
    """Collect GitHub evidence JSON files using ``httpx`` (sync)."""

    def __init__(self, token: str) -> None:
        self._token = token

    def collect(self, repo_slug: str) -> list[CollectionResult]:  # noqa: C901
        """Collect repository-scoped evidence JSON via the GitHub REST API.

        **Required:** ``GITHUB_TOKEN`` (or the token passed to the constructor) with enough access to read the
        repository and its security settings.

        **Typical scopes**

        * **Public repositories:** the default ``GITHUB_TOKEN`` in Actions often suffices for metadata; for
          **branch protection** and **rulesets**, the token still needs **administration: read** (or **repo** scope
          on classic PATs) because those endpoints are restricted.
        * **Private repositories:** classic PAT or GitHub App installation token with **repo** (full control of
          private repositories) or fine-grained permissions that include **Contents**, **Metadata**, and
          **Administration** read where applicable.

        **Organization MFA / org-wide posture (ORG-MFA-001):** not collected by this module. Proving org-level MFA
        requires the **Organization** API (for example ``GET /orgs/{org}`` with **admin:org** read on a classic PAT,
        or an organization-level fine-grained token). Treat **ORG-MFA-001** as manual or org-admin tooling unless
        you extend the collector with explicit org endpoints.

        **Graceful degradation:** HTTP **404** on optional endpoints yields empty or conservative payloads where
        the writer logs a warning; **403** raises :class:`~oss_policy_kit.domain.errors.CollectionPermissionError`
        so you can widen scopes deliberately.
        """

        try:
            import httpx
        except ImportError as exc:
            msg = "GitHub evidence collection requires httpx. Install with: pip install 'oss-policy-kit[github]'"
            raise RuntimeError(msg) from exc

        owner, repo = _parse_owner_repo(repo_slug)
        results: list[CollectionResult] = []
        collected_at = _utc_iso_timestamp()
        attested_date = _iso_date_prefix(collected_at)
        attested_by = "github-api-collection"

        try:
            with httpx.Client(base_url=GITHUB_API, headers=_github_headers(self._token), timeout=60.0) as client:
                repo_url = f"/repos/{owner}/{repo}"
                r_repo = client.get(repo_url)
                _enforce_rate_limit(r_repo)
                if r_repo.status_code in {403, 404}:
                    _raise_permission("GET", f"{GITHUB_API}{repo_url}", r_repo.status_code)
                if r_repo.status_code == 422:
                    logger.warning("GitHub returned 422 for %s; skipping repository metadata.", repo_url)
                    return []
                r_repo.raise_for_status()
                repo_json = cast(dict[str, Any], r_repo.json())
                default_branch = str(repo_json.get("default_branch") or "main")

                # 1) Branch protection
                bp_url = f"/repos/{owner}/{repo}/branches/{default_branch}/protection"
                r_bp = client.get(bp_url)
                _enforce_rate_limit(r_bp)
                if r_bp.status_code in {403, 404}:
                    if r_bp.status_code == 403:
                        _raise_permission("GET", f"{GITHUB_API}{bp_url}", r_bp.status_code)
                    bp_data: dict[str, Any] = {}
                elif r_bp.status_code == 422:
                    logger.warning("GitHub returned 422 for %s; skipping branch protection evidence.", bp_url)
                    bp_data = {}
                else:
                    r_bp.raise_for_status()
                    bp_data = cast(dict[str, Any], r_bp.json())
                bp_payload = _branch_protection_payload(
                    bp_data,
                    branch=default_branch,
                    repo_slug=f"{owner}/{repo}",
                    attested_at=attested_date,
                    attested_by=attested_by,
                    collected_at=collected_at,
                )
                results.append(
                    CollectionResult(
                        evidence_key="branch-protection",
                        data=bp_payload,
                        source_url=f"{GITHUB_API}{bp_url}",
                        collected_at=collected_at,
                    )
                )

                # 2) Rulesets
                rs_url = f"/repos/{owner}/{repo}/rulesets"
                r_rs = client.get(rs_url)
                _enforce_rate_limit(r_rs)
                if r_rs.status_code in {403, 404}:
                    if r_rs.status_code == 403:
                        _raise_permission("GET", f"{GITHUB_API}{rs_url}", r_rs.status_code)
                    rulesets: list[dict[str, Any]] = []
                elif r_rs.status_code == 422:
                    logger.warning("GitHub returned 422 for %s; skipping rulesets evidence.", rs_url)
                    rulesets = []
                else:
                    r_rs.raise_for_status()
                    body_rs = r_rs.json()
                    rulesets = cast(list[dict[str, Any]], body_rs) if isinstance(body_rs, list) else []
                rs_payload = _rulesets_payload(
                    rulesets,
                    repo_slug=f"{owner}/{repo}",
                    attested_at=attested_date,
                    attested_by=attested_by,
                    collected_at=collected_at,
                )
                results.append(
                    CollectionResult(
                        evidence_key="github-rulesets",
                        data=rs_payload,
                        source_url=f"{GITHUB_API}{rs_url}",
                        collected_at=collected_at,
                    )
                )

                # 3) Secret scanning posture (from repository object)
                ss_payload = _secret_scanning_payload(
                    repo_json,
                    repo_slug=f"{owner}/{repo}",
                    attested_at=attested_date,
                    attested_by=attested_by,
                    collected_at=collected_at,
                )
                results.append(
                    CollectionResult(
                        evidence_key="github-secret-scanning",
                        data=ss_payload,
                        source_url=f"{GITHUB_API}{repo_url}",
                        collected_at=collected_at,
                    )
                )

                # 4) Environments
                env_url = f"/repos/{owner}/{repo}/environments"
                r_env = client.get(env_url)
                _enforce_rate_limit(r_env)
                if r_env.status_code in {403, 404}:
                    if r_env.status_code == 403:
                        _raise_permission("GET", f"{GITHUB_API}{env_url}", r_env.status_code)
                    env_list: list[dict[str, Any]] = []
                elif r_env.status_code == 422:
                    logger.warning("GitHub returned 422 for %s; skipping environment protection evidence.", env_url)
                    env_list = []
                else:
                    r_env.raise_for_status()
                    body_env = cast(dict[str, Any], r_env.json())
                    raw_envs = body_env.get("environments")
                    env_list = cast(list[dict[str, Any]], raw_envs) if isinstance(raw_envs, list) else []
                env_payload = _environments_payload(
                    env_list,
                    attested_at=attested_date,
                    attested_by=attested_by,
                    repo_slug=f"{owner}/{repo}",
                    collected_at=collected_at,
                )
                if env_payload is not None:
                    results.append(
                        CollectionResult(
                            evidence_key="github-environment-protection",
                            data=env_payload,
                            source_url=f"{GITHUB_API}{env_url}",
                            collected_at=collected_at,
                        )
                    )
                else:
                    logger.warning("No GitHub environments returned for %s/%s; skipping environment file.", owner, repo)

        except CollectionPermissionError:
            raise
        except RateLimitError:
            raise
        except RuntimeError:
            raise
        except httpx.RequestError as exc:
            raise CollectionNetworkError(f"GitHub network error: {exc}") from exc
        except Exception as exc:
            raise CollectionNetworkError(f"GitHub evidence collection failed: {exc}") from exc

        return results


def _branch_protection_payload(
    data: dict[str, Any],
    *,
    branch: str,
    repo_slug: str,
    attested_at: str,
    attested_by: str,
    collected_at: str,
) -> dict[str, Any]:
    pr = data.get("required_pull_request_reviews")
    pr_dict = cast(dict[str, Any], pr) if isinstance(pr, dict) else None
    sc = data.get("required_status_checks")
    sc_dict = cast(dict[str, Any], sc) if isinstance(sc, dict) else None
    ea = data.get("enforce_admins")
    ea_dict = cast(dict[str, Any], ea) if isinstance(ea, dict) else None
    afp = data.get("allow_force_pushes")
    afp_dict = cast(dict[str, Any], afp) if isinstance(afp, dict) else None

    require_pr_reviews = pr_dict is not None
    dismiss_stale = bool(pr_dict.get("dismiss_stale_reviews")) if pr_dict else False
    require_checks = sc_dict is not None and bool(sc_dict.get("strict") or sc_dict.get("contexts"))
    enforce_admins = bool(ea_dict.get("enabled")) if ea_dict else False
    allow_force = bool(afp_dict.get("enabled")) if afp_dict else False
    restrict_force_push = not allow_force

    return {
        "schema_version": "branch-protection/v1",
        "attested_at": attested_at,
        "attested_by": attested_by,
        "branch": branch,
        "protections": {
            "require_pull_request_reviews": require_pr_reviews,
            "dismiss_stale_reviews": dismiss_stale,
            "require_status_checks": require_checks,
            "enforce_admins": enforce_admins,
            "restrict_force_push": restrict_force_push,
        },
        "collection": _github_collection_block(
            collected_at, f"{GITHUB_API}/repos/{repo_slug}/branches/{branch}/protection"
        ),
        "notes": f"Collected from GitHub API for {repo_slug}.",
    }


def _rulesets_payload(
    rulesets: list[dict[str, Any]],
    *,
    repo_slug: str,
    attested_at: str,
    attested_by: str,
    collected_at: str,
) -> dict[str, Any]:
    require_pr = False
    require_checks = False
    restrict_force = False
    code_owner = False
    for rs in rulesets:
        if str(rs.get("enforcement", "")).lower() == "disabled":
            continue
        for rule in cast(list[Any], rs.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            t = str(rule.get("type", "")).lower()
            if t == "pull_request":
                require_pr = True
                params = cast(dict[str, Any], rule.get("parameters") or {})
                if params.get("required_reviewers"):
                    code_owner = True
                if params.get("require_code_owner_review") is True:
                    code_owner = True
            if t == "required_status_checks":
                require_checks = True
            if t in {"non_fast_forward", "deletion", "update"}:
                restrict_force = True
    return {
        "schema_version": "github-rulesets/v1",
        "attested_at": attested_at,
        "attested_by": attested_by,
        "repository": repo_slug,
        "posture": {
            "require_pull_request": require_pr,
            "require_status_checks": require_checks,
            "restrict_force_push": restrict_force,
            "require_code_owner_review": code_owner,
        },
        "collection": _github_collection_block(collected_at, f"{GITHUB_API}/repos/{repo_slug}/rulesets"),
        "notes": "Derived from GitHub repository rulesets list API.",
    }


def _secret_scanning_payload(
    repo_json: dict[str, Any],
    *,
    repo_slug: str,
    attested_at: str,
    attested_by: str,
    collected_at: str,
) -> dict[str, Any]:
    sna = cast(dict[str, Any], repo_json.get("security_and_analysis") or {})
    posture = {
        "secret_scanning_enabled": _status_block_enabled(sna.get("secret_scanning")),
        "push_protection_enabled": _status_block_enabled(sna.get("secret_scanning_push_protection")),
        "validity_checks_enabled": _status_block_enabled(sna.get("secret_scanning_validity_checks")),
    }
    return {
        "schema_version": "github-secret-scanning/v1",
        "attested_at": attested_at,
        "attested_by": attested_by,
        "repository": repo_slug,
        "posture": posture,
        "collection": _github_collection_block(collected_at, f"{GITHUB_API}/repos/{repo_slug}"),
        "notes": "Derived from GitHub repository security_and_analysis block.",
    }


def _environments_payload(
    envs: list[dict[str, Any]],
    *,
    attested_at: str,
    attested_by: str,
    repo_slug: str,
    collected_at: str,
) -> dict[str, Any] | None:
    if not envs:
        return None
    mapped: list[dict[str, Any]] = []
    for env in envs:
        name = str(env.get("name", "unknown"))
        rules = cast(list[Any], env.get("protection_rules") or [])
        requires_reviewers = False
        prevent_self_review = False
        wait_timer = 0
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if str(rule.get("type", "")).lower() == "required_reviewers":
                requires_reviewers = True
                params = cast(dict[str, Any], rule.get("parameters") or {})
                reviewers = params.get("reviewers") or []
                if isinstance(reviewers, list) and len(reviewers) > 0:
                    requires_reviewers = True
            if str(rule.get("type", "")).lower() == "wait_timer":
                params = cast(dict[str, Any], rule.get("parameters") or {})
                w = params.get("wait_timer")
                if isinstance(w, int):
                    wait_timer = max(wait_timer, w)
        mapped.append(
            {
                "name": name,
                "requires_reviewers": requires_reviewers,
                "prevent_self_review": prevent_self_review,
                "wait_timer_minutes": wait_timer,
            }
        )
    return {
        "schema_version": "github-environment-protection/v1",
        "attested_at": attested_at,
        "attested_by": attested_by,
        "environments": mapped,
        "collection": _github_collection_block(collected_at, f"{GITHUB_API}/repos/{repo_slug}/environments"),
        "notes": "Derived from GitHub environments API (first page).",
    }
