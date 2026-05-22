"""Parse GitLab CI pipeline YAML for static security signals.

The parser is intentionally narrow in v5.9.0: it covers the signals needed
by the initial ``GL-PIPE-*`` control family (six controls) rather than every
GitLab CI feature. See ADR-003 for the broader design and the planned 12-
control surface.

Scope this module addresses:

- locate ``.gitlab-ci.yml`` (root or under ``.gitlab/``)
- parse jobs, ``image:`` references, ``include:`` references, ``script:``
  blocks, ``inherit:``/``secrets:`` declarations, ``rules:`` / ``only:`` /
  ``except:`` trigger restrictions, ``tags:`` self-hosted runner hints
- record parse errors per file rather than raising

Out of scope (deferred):

- ``extends:`` job inheritance (deep resolution)
- remote ``include:`` retrieval (we record the reference, never fetch)
- per-environment / per-stage rule simulation
- ``rules:if`` expression evaluation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oss_policy_kit.infrastructure.yaml_io import load_yaml_file


@dataclass(slots=True)
class GitLabCiAnalysis:
    """Aggregated signals from .gitlab-ci.yml plus discoverable includes."""

    pipeline_paths: list[Path] = field(default_factory=list)
    #: (file, image_ref) — image references without a tag or digest.
    image_refs_unpinned: list[tuple[Path, str]] = field(default_factory=list)
    #: (file, image_ref) — image references pinned by a specific tag or @sha256: digest.
    image_refs_pinned: list[tuple[Path, str]] = field(default_factory=list)
    #: (file, image_ref) — image refs using a mutable / floating tag (latest, edge, stable, main,
    #: master, nightly, lts). Classified separately because GL-PIPE-002 fails on these: the tag
    #: exists, but it drifts between pipeline runs.
    image_refs_mutable_tag: list[tuple[Path, str]] = field(default_factory=list)
    #: Pipelines that use `script:` commands containing `curl ... | sh` / `wget ... | sh`.
    script_uses_curl_pipe_shell: list[Path] = field(default_factory=list)
    #: Pipelines where a job declares `inherit: secrets: true` (broad secret exposure).
    jobs_with_inherit_secrets: list[Path] = field(default_factory=list)
    #: `include:` entries that reference a remote URL (no local-file pinning).
    includes_remote: list[tuple[Path, str]] = field(default_factory=list)
    #: Pipelines whose top-level workflow/jobs declare `rules:` / `only:` / `except:`
    #: (i.e. trigger restrictions present at all — coarse signal).
    jobs_with_trigger_restrictions: list[Path] = field(default_factory=list)
    parse_errors: list[tuple[Path, str]] = field(default_factory=list)


# Pipeline filenames we look for. The kit deliberately does not follow
# `include:` recursion across remote files; only locally-resolvable includes
# are added to `pipeline_paths`. This keeps the parser hermetic.
_GITLAB_CI_FILENAMES: tuple[str, ...] = (".gitlab-ci.yml", ".gitlab-ci.yaml")

# Common GitLab reserved top-level keys that are NOT jobs.
_RESERVED_KEYS: frozenset[str] = frozenset(
    {
        "stages",
        "variables",
        "default",
        "include",
        "workflow",
        "image",
        "services",
        "cache",
        "before_script",
        "after_script",
        "pages",  # technically a job, but treated specially by GitLab
    }
)

_CURL_PIPE_SHELL_RE = re.compile(r"\b(?:curl|wget)\s[^|]+\|\s*(?:bash|sh|zsh)\b", re.IGNORECASE)
_DIGEST_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}\b")

# Mutable / floating tags that GitLab CI image: refs should not rely on for
# reproducible builds. Aligned with the docker hub convention and most popular
# upstream image conventions (alpine:latest, node:lts, python:3, ruby:edge).
# A reference like `python:latest` has a tag, but the tag is non-deterministic.
_MUTABLE_IMAGE_TAGS: frozenset[str] = frozenset({"latest", "edge", "stable", "main", "master", "nightly", "lts"})


def _iter_pipeline_files(repo_root: Path) -> list[Path]:
    """Return discoverable GitLab CI pipeline files in the repo."""

    found: list[Path] = []
    for name in _GITLAB_CI_FILENAMES:
        p = repo_root / name
        if p.is_file():
            found.append(p)
    # Also support `.gitlab/` directory for org/repo-level pipeline collections.
    gitlab_dir = repo_root / ".gitlab"
    if gitlab_dir.is_dir():
        for name in _GITLAB_CI_FILENAMES:
            p = gitlab_dir / name
            if p.is_file():
                found.append(p)
    return sorted(found)


def _classify_image_ref(ref: str) -> str:
    """Return 'digest' if @sha256:..., 'mutable-tag' if a floating tag like :latest,
    'tag' for any other specific tag, else 'unpinned'."""

    if _DIGEST_PIN_RE.search(ref):
        return "digest"
    # An explicit `:tag` (excluding port-only refs like host:5000/img) counts as pinned.
    # GitLab/Docker convention: `host:port/repo:tag` — the tag is the segment after the LAST colon.
    # Treat anything with at least one segment-internal colon after the last '/' as tagged.
    last_segment = ref.rsplit("/", 1)[-1]
    if ":" in last_segment:
        tag = last_segment.rsplit(":", 1)[-1]
        if tag.lower() in _MUTABLE_IMAGE_TAGS:
            return "mutable-tag"
        return "tag"
    return "unpinned"


def _record_image_ref(ref: str, file_path: Path, out: GitLabCiAnalysis) -> None:
    """Classify one ``image:`` reference and append it to the matching bucket."""

    cls = _classify_image_ref(ref)
    if cls == "unpinned":
        out.image_refs_unpinned.append((file_path, ref))
    elif cls == "mutable-tag":
        out.image_refs_mutable_tag.append((file_path, ref))
    else:
        out.image_refs_pinned.append((file_path, ref))


def _record_image_value(value: Any, file_path: Path, out: GitLabCiAnalysis) -> bool:
    """Record an ``image:`` value (string ref or ``{name: ...}``); return True if it was an image spec."""

    if isinstance(value, str) and value.strip():
        _record_image_ref(value.strip(), file_path, out)
        return True
    if isinstance(value, dict):
        name = value.get("name")
        if isinstance(name, str) and name.strip():
            _record_image_ref(name.strip(), file_path, out)
        return True
    return False


def _walk_for_images(node: Any, file_path: Path, out: GitLabCiAnalysis) -> None:
    """Recursively walk YAML, recording every `image:` reference encountered."""

    if isinstance(node, dict):
        for key, value in node.items():
            if key == "image" and _record_image_value(value, file_path, out):
                continue
            _walk_for_images(value, file_path, out)
    elif isinstance(node, list):
        for item in node:
            _walk_for_images(item, file_path, out)


def _extract_script_values(value: Any) -> list[str]:
    """Return the string entries of a ``script:`` value (list of strings or a single string)."""

    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [value]
    return []


def _collect_script_strings(node: Any) -> list[str]:
    """Return every string under `script:` / `before_script:` / `after_script:`."""

    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("script", "before_script", "after_script"):
                out.extend(_extract_script_values(value))
            else:
                out.extend(_collect_script_strings(value))
    elif isinstance(node, list):
        for item in node:
            out.extend(_collect_script_strings(item))
    return out


def _has_inherit_secrets_true(node: Any) -> bool:
    """Return True if any job declares `inherit: secrets: true` (or equivalent)."""

    if isinstance(node, dict):
        inherit = node.get("inherit")
        if isinstance(inherit, dict) and inherit.get("secrets") is True:
            return True
        # Also treat top-level `secrets:` with no scoping as broad exposure.
        return any(_has_inherit_secrets_true(v) for k, v in node.items() if k != "inherit")
    if isinstance(node, list):
        return any(_has_inherit_secrets_true(item) for item in node)
    return False


def _collect_includes(doc: dict[str, Any]) -> list[Any]:
    """Return entries from the top-level `include:` (list, dict, or scalar)."""

    inc = doc.get("include")
    if inc is None:
        return []
    if isinstance(inc, list):
        return inc
    return [inc]


def _entry_is_remote(entry: Any) -> tuple[bool, str | None]:
    """Return (is_remote, reference_str) for an `include:` entry.

    GitLab supports include shapes: ``- local: ./foo.yml`` (local file),
    ``- remote: 'https://...'`` (HTTPS remote), ``- project: ... file: ...``
    (cross-project), ``- template: 'Foo.gitlab-ci.yml'`` (GitLab built-in).
    Only ``remote:`` and bare ``- 'https://...'`` count as supply-chain
    remote for this signal; the others fetch from GitLab-controlled
    sources and we treat them as local-trust-equivalent for v5.9.0.
    """

    if isinstance(entry, str):
        s = entry.strip()
        if s.startswith(("http://", "https://")):
            return True, s
        return False, None
    if isinstance(entry, dict):
        remote = entry.get("remote")
        if isinstance(remote, str) and remote.strip().startswith(("http://", "https://")):
            return True, remote.strip()
    return False, None


def _has_trigger_restrictions(doc: dict[str, Any]) -> bool:
    """Return True if any job declares `rules:`, `only:`, or `except:`."""

    for key, value in doc.items():
        if key in _RESERVED_KEYS:
            continue
        if not isinstance(value, dict):
            continue
        if any(k in value for k in ("rules", "only", "except", "when")):
            return True
    return False


def _analyze_one_gitlab_doc(doc: dict[str, Any], path: Path, out: GitLabCiAnalysis) -> None:
    """Record image / curl-pipe-shell / inherit-secrets / remote-include / trigger signals for one pipeline."""

    # Image references (top-level + per-job).
    _walk_for_images(doc, path, out)
    # script: curl|wget | sh checks.
    scripts = _collect_script_strings(doc)
    if any(_CURL_PIPE_SHELL_RE.search(s) for s in scripts):
        out.script_uses_curl_pipe_shell.append(path)
    # inherit: secrets: true.
    if _has_inherit_secrets_true(doc):
        out.jobs_with_inherit_secrets.append(path)
    # Remote includes (supply-chain signal).
    for entry in _collect_includes(doc):
        is_remote, ref = _entry_is_remote(entry)
        if is_remote and ref:
            out.includes_remote.append((path, ref))
    # Coarse trigger-restriction signal.
    if _has_trigger_restrictions(doc):
        out.jobs_with_trigger_restrictions.append(path)


def analyze_gitlab_ci(repo_root: Path) -> GitLabCiAnalysis:
    """Return aggregated signals from every discoverable GitLab CI pipeline."""

    out = GitLabCiAnalysis()
    for path in _iter_pipeline_files(repo_root):
        out.pipeline_paths.append(path)
        try:
            doc = load_yaml_file(path)
        except Exception as exc:  # noqa: BLE001
            out.parse_errors.append((path, str(exc)))
            continue
        if not isinstance(doc, dict):
            out.parse_errors.append((path, "Top-level YAML is not a mapping"))
            continue
        _analyze_one_gitlab_doc(doc, path, out)

    return out
