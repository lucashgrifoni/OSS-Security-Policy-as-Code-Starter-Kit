"""Collect AWS CodeBuild / CodePipeline evidence via boto3."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any, NoReturn, cast

from oss_policy_kit.domain.errors import CollectionNetworkError, CollectionPermissionError, RateLimitError
from oss_policy_kit.infrastructure.collectors.base import CollectionResult, EvidenceCollector

logger = logging.getLogger(__name__)

_ENV_CODEBUILD = "AWS_CODEBUILD_PROJECT"
_ENV_CODEPIPELINE = "AWS_CODEPIPELINE_NAME"


def _utc_iso_timestamp() -> str:
    """Return current UTC time as ISO-8601 with ``Z`` suffix (no micros)."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso_date_prefix(ts: str) -> str:
    return ts[:10] if len(ts) >= 10 else ts


def _client_error_code(exc: Any) -> str:
    if hasattr(exc, "response"):
        resp = getattr(exc, "response", None)
        if isinstance(resp, dict):
            err = resp.get("Error") or {}
            if isinstance(err, dict):
                return str(err.get("Code", ""))
    return ""


def _map_client_error(exc: Any, *, operation: str) -> NoReturn:
    """Translate a boto3 ``ClientError`` into a typed collector error.

    Always raises; never returns. The ``NoReturn`` annotation lets callers chain logic after this
    helper without triggering "possibly undefined variable" warnings.
    """

    code = _client_error_code(exc)
    if code in ("AccessDeniedException", "UnauthorizedOperation", "InvalidClientTokenId", "AuthFailure"):
        raise CollectionPermissionError(
            f"AWS API denied access during {operation} ({code}). "
            "Verify IAM credentials and that the principal can read CodeBuild and/or CodePipeline."
        ) from exc
    if code in ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded"):
        raise RateLimitError(f"AWS API rate limit during {operation} ({code}). Retry after a short wait.") from exc
    raise CollectionNetworkError(f"AWS API error during {operation} ({code or 'unknown'}): {exc}") from exc


def _artifact_store_encryption_enabled(pipeline: dict[str, Any]) -> bool:
    """True when pipeline artifact store(s) declare a KMS/S3 encryption key in the API model."""

    store = pipeline.get("artifactStore")
    if isinstance(store, dict) and store.get("encryptionKey"):
        return True
    stores = pipeline.get("artifactStores")
    if isinstance(stores, dict):
        for s in stores.values():
            if not isinstance(s, dict) or not s.get("encryptionKey"):
                return False
        return len(stores) > 0
    return False


def _manual_approval_before_production(stages: list[dict[str, Any]]) -> bool:
    """Heuristic: a manual approval action exists in a stage before the final stage."""

    if len(stages) < 2:
        return False
    last_idx = len(stages) - 1
    for idx, stage in enumerate(stages):
        if idx >= last_idx:
            break
        for action in cast(list[Any], stage.get("actions") or []):
            if not isinstance(action, dict):
                continue
            tid = cast(dict[str, Any], action.get("actionTypeId") or {})
            cat = str(tid.get("category", "")).lower()
            prov = str(tid.get("provider", "")).lower()
            if cat == "approval" and prov == "manual":
                return True
    return False


def _production_execution_mode_not_parallel(pipeline: dict[str, Any]) -> bool:
    """Treat ``PARALLEL`` execution mode as parallel; otherwise assume non-parallel defaults."""

    mode = str(pipeline.get("executionMode") or "").upper()
    return mode != "PARALLEL"


def _codebuild_posture(project: dict[str, Any]) -> dict[str, bool]:
    env_block = cast(dict[str, Any], project.get("environment") or {})
    privileged = bool(env_block.get("privilegedMode"))
    no_plaintext = True
    for ev in cast(list[Any], env_block.get("environmentVariables") or []):
        if not isinstance(ev, dict):
            continue
        if str(ev.get("type", "")).upper() == "PLAINTEXT":
            no_plaintext = False
            break
    role = str(project.get("serviceRole") or "").strip()
    return {
        "privileged_mode_disabled": not privileged,
        "no_plaintext_credentials_in_project_config": no_plaintext,
        "codebuild_service_role_configured": role.startswith("arn:aws:iam::"),
    }


class AWSEvidenceCollector(EvidenceCollector):
    """Collect AWS evidence JSON files using boto3 (CodeBuild, CodePipeline)."""

    def __init__(self, *, region_name: str | None = None) -> None:
        self._region = (region_name or "").strip() or None

    def collect_sbom_artifact(self, repo_slug: str) -> list[CollectionResult]:
        """Optional hook for **AWS-SBOMART-058** (no API payload emitted here).

        Neither ``codebuild:BatchGetProjects``, ``codepipeline:GetPipeline``, nor CodeArtifact APIs used by this
        kit return a CycloneDX/SPDX document keyed to a released artifact digest in the shape of
        ``evidence-aws-sbom-artifact.schema.json``. Populate ``aws-sbom-artifact.json`` manually or from your
        pipeline SBOM export (S3, Inspector SBOM export, etc.).
        """

        logger.info(
            "collect_sbom_artifact(%r): skipped — digest-bound SBOM evidence is manual/pipeline-only; "
            "see docs/evidence-pack.md.",
            repo_slug,
        )
        return []

    def collect_provenance_artifact(self, repo_slug: str) -> list[CollectionResult]:
        """Optional hook for **AWS-PROVART-059** (no API payload emitted here).

        Build provenance / in-toto predicates for a specific artifact digest are not returned by the CodeBuild
        or CodePipeline calls in this collector. Use manual JSON or your provenance/attestation pipeline.
        """

        logger.info(
            "collect_provenance_artifact(%r): skipped — artifact provenance JSON is manual/pipeline-only; "
            "see docs/evidence-pack.md.",
            repo_slug,
        )
        return []

    def collect(self, repo_slug: str) -> list[CollectionResult]:
        """Collect evidence for env-configured CodeBuild project and/or CodePipeline.

        **Environment variables**

        * ``AWS_CODEBUILD_PROJECT`` — CodeBuild project name (optional).
        * ``AWS_CODEPIPELINE_NAME`` — CodePipeline name (optional).
        * ``AWS_REGION`` / ``AWS_DEFAULT_REGION`` — passed to boto3 when ``region_name`` was not set on init.

        *repo_slug* is currently unused for AWS but kept for the
        :class:`~oss_policy_kit.infrastructure.collectors.base.EvidenceCollector` contract; it is forwarded
        to the optional artifact hooks for traceability only.

        **IAM (typical read-only policy fragments)**

        * ``codebuild:BatchGetProjects`` on the evaluated project(s).
        * ``codepipeline:GetPipeline`` on the evaluated pipeline(s).
        * Optional posture helpers used by evaluators (not always invoked here): ``iam:GetRole``,
          ``iam:SimulatePrincipalPolicy`` for pipeline/CodeBuild role checks — grant only when you collect those
          evidence files.

        Missing permissions surface as :class:`~oss_policy_kit.domain.errors.CollectionPermissionError` or
        transport errors from boto3.

        **Optional hooks:** :meth:`collect_sbom_artifact` / :meth:`collect_provenance_artifact` run at the end of
        a successful collection and return no extra files today (see ``docs/evidence-pack.md``).
        """

        try:
            import boto3
            from botocore.exceptions import BotoCoreError
        except ImportError as exc:
            msg = "AWS evidence collection requires boto3. Install with: pip install 'oss-policy-kit[aws]'"
            raise RuntimeError(msg) from exc

        build_name = os.environ.get(_ENV_CODEBUILD, "").strip()
        pipeline_name = os.environ.get(_ENV_CODEPIPELINE, "").strip()

        if not build_name and not pipeline_name:
            raise ValueError(
                f"Nothing to collect for AWS: set {_ENV_CODEBUILD} and/or {_ENV_CODEPIPELINE}. "
                "Run 'oss-policy-kit collect-evidence --platform aws --dry-run' to preview the files "
                "that would be written once inputs are provided."
            )

        session = boto3.Session(region_name=self._region)
        collected_at = _utc_iso_timestamp()
        attested_date = _iso_date_prefix(collected_at)
        attested_by = "aws-api-collection"
        results: list[CollectionResult] = []

        try:
            if build_name:
                results.append(
                    self._collect_codebuild(
                        session,
                        build_name,
                        attested_date=attested_date,
                        attested_by=attested_by,
                        collected_at=collected_at,
                    )
                )
            if pipeline_name:
                results.append(
                    self._collect_codepipeline(
                        session,
                        pipeline_name,
                        attested_date=attested_date,
                        attested_by=attested_by,
                        collected_at=collected_at,
                    )
                )
        except (CollectionPermissionError, RateLimitError, ValueError, RuntimeError):
            raise
        except BotoCoreError as exc:
            raise CollectionNetworkError(f"AWS transport error: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise CollectionNetworkError(f"AWS evidence collection failed: {exc}") from exc

        results.extend(self.collect_sbom_artifact(repo_slug))
        results.extend(self.collect_provenance_artifact(repo_slug))
        return results

    def _collect_codebuild(
        self,
        session: Any,
        project_name: str,
        *,
        attested_date: str,
        attested_by: str,
        collected_at: str,
    ) -> CollectionResult:
        from botocore.exceptions import BotoCoreError, ClientError

        cb = session.client("codebuild")
        try:
            resp = cb.batch_get_projects(names=[project_name])
        except ClientError as exc:
            if _client_error_code(exc) == "ResourceNotFoundException":
                raise ValueError(f"CodeBuild project {project_name!r} not found.") from exc
            _map_client_error(exc, operation="codebuild:BatchGetProjects")
        except BotoCoreError as exc:
            raise CollectionNetworkError(f"CodeBuild transport error: {exc}") from exc

        projects = cast(list[Any], resp.get("projects") or [])
        if not projects:
            raise ValueError(f"CodeBuild project {project_name!r} not found.")
        proj = cast(dict[str, Any], projects[0])
        posture = _codebuild_posture(proj)
        notes = (
            "Derived from codebuild:BatchGetProjects (serviceRole, environment.privilegedMode, "
            "and environmentVariables types). IAM trust/OIDC for the role requires separate IAM evidence."
        )
        collection = {
            "evidence_collection_method": "live",
            "collected_at": collected_at,
            "source_url": f"aws:codebuild:BatchGetProjects?name={project_name}",
            "mode": "api",
        }
        data: dict[str, Any] = {
            "schema_version": "aws-codebuild-project/v1",
            "attested_at": attested_date,
            "attested_by": attested_by,
            "project": project_name,
            "posture": posture,
            "collection": collection,
            "identity": {
                "service_role_arn_present": bool(posture.get("codebuild_service_role_configured")),
                "no_plaintext_environment_credentials": bool(posture.get("no_plaintext_credentials_in_project_config")),
            },
            "notes": notes,
        }
        return CollectionResult(
            evidence_key="aws-codebuild-project",
            data=data,
            source_url=f"aws:codebuild:BatchGetProjects?name={project_name}",
            collected_at=collected_at,
        )

    def _collect_codepipeline(
        self,
        session: Any,
        name: str,
        *,
        attested_date: str,
        attested_by: str,
        collected_at: str,
    ) -> CollectionResult:
        from botocore.exceptions import BotoCoreError, ClientError

        cp = session.client("codepipeline")
        try:
            resp = cp.get_pipeline(name=name)
        except ClientError as exc:
            if _client_error_code(exc) in ("PipelineNotFoundException", "ResourceNotFoundException"):
                raise ValueError(f"CodePipeline {name!r} not found.") from exc
            _map_client_error(exc, operation="codepipeline:GetPipeline")
        except BotoCoreError as exc:
            raise CollectionNetworkError(f"CodePipeline transport error: {exc}") from exc

        pipe = cast(dict[str, Any], resp.get("pipeline") or {})
        if not pipe:
            raise ValueError(f"CodePipeline {name!r} not found or empty response.")
        stages_raw = cast(list[Any], pipe.get("stages") or [])
        stages = [cast(dict[str, Any], s) for s in stages_raw if isinstance(s, dict)]
        posture = {
            "manual_approval_before_production": _manual_approval_before_production(stages),
            "artifact_store_encryption_enabled": _artifact_store_encryption_enabled(pipe),
            "production_execution_mode_not_parallel": _production_execution_mode_not_parallel(pipe),
        }
        notes = (
            "Derived from codepipeline:GetPipeline (stages, artifactStore encryptionKey, executionMode). "
            "Confirm S3 default encryption when encryptionKey is absent."
        )
        role_ok = bool(str(pipe.get("roleArn", "")).strip().startswith("arn:aws:iam::"))
        collection = {
            "evidence_collection_method": "live",
            "collected_at": collected_at,
            "source_url": f"aws:codepipeline:GetPipeline?name={name}",
            "mode": "api",
        }
        data: dict[str, Any] = {
            "schema_version": "aws-codepipeline/v1",
            "attested_at": attested_date,
            "attested_by": attested_by,
            "pipeline": name,
            "posture": posture,
            "collection": collection,
            "iam": {"pipeline_service_role_arn_configured": role_ok},
            "notes": notes,
        }
        return CollectionResult(
            evidence_key="aws-codepipeline",
            data=data,
            source_url=f"aws:codepipeline:GetPipeline?name={name}",
            collected_at=collected_at,
        )
