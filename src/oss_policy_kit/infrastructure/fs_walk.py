"""Shared filesystem walk used by the IaC/K8s scanners.

Globs the include patterns under a repo root, skips noisy directories, honors
operator excludes, and de-duplicates by resolved path. Extracted so each
scanner's ``_walk_*`` stays a one-line delegate (keeps cognitive complexity low
and the discovery behavior identical across scanners).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


def _accept(
    p: Path,
    repo_root: Path,
    excludes: tuple[str, ...],
    skip_dirs: frozenset[str],
) -> Path | None:
    """Return the resolved path if ``p`` is an includable file, else ``None``."""

    if not p.is_file():
        return None
    try:
        rel = p.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return None
    if any(part in skip_dirs for part in rel.parts):
        return None
    if excludes and any(p.match(eg) for eg in excludes):
        return None
    return p.resolve()


def walk_matching_files(
    repo_root: Path,
    include_globs: Iterable[str],
    exclude_globs: Iterable[str] | None,
    skip_dirs: frozenset[str],
) -> list[Path]:
    """Return files matching ``include_globs`` under ``repo_root`` (skip dirs + excludes applied)."""

    seen: set[Path] = set()
    out: list[Path] = []
    excludes = tuple(exclude_globs or ())
    for pat in include_globs:
        for p in repo_root.glob(pat):
            resolved = _accept(p, repo_root, excludes, skip_dirs)
            if resolved is None or resolved in seen:
                continue
            seen.add(resolved)
            out.append(p)
    return out
