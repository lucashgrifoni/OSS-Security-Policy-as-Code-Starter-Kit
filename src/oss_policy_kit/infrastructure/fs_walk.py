"""Shared filesystem walk used by the IaC/K8s scanners.

Globs the include patterns under a repo root, skips noisy directories, honors
operator excludes, and de-duplicates by resolved path. Extracted so each
scanner's ``_walk_*`` stays a one-line delegate (keeps cognitive complexity low
and the discovery behavior identical across scanners).

Every candidate is resolved exactly once. It used to be resolved three times --
``p.resolve()`` for the ``relative_to`` comparison, ``repo_root.resolve()``
recomputed inside the loop although it cannot change, and ``p.resolve()`` again
to build the return value. On Windows each ``Path.resolve()`` costs two
``nt._getfinalpathname`` calls, so the walk paid six of them per file where two
suffice. Profiled on a 20,002-file Python tree, ``scan-pulumi`` spent 8.56s of a
14.76s run inside this walk, 3.82s of it in ``_getfinalpathname`` alone across
120,012 calls; the parse the scanner exists to do cost 0.61s. Hoisting the root
and reusing the candidate is pure common-subexpression elimination -- the same
values, computed once -- and it narrows rather than widens the window in which
the filesystem could change between the comparison and the returned path.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


def _accept(
    p: Path,
    repo_root_resolved: Path,
    excludes: tuple[str, ...],
    skip_dirs: frozenset[str],
) -> Path | None:
    """Return the resolved path if ``p`` is an includable file, else ``None``.

    *repo_root_resolved* is the already-resolved root, passed in so it is not
    recomputed once per candidate.
    """

    if not p.is_file():
        return None
    resolved = p.resolve()
    try:
        rel = resolved.relative_to(repo_root_resolved)
    except ValueError:
        return None
    if any(part in skip_dirs for part in rel.parts):
        return None
    if excludes and any(p.match(eg) for eg in excludes):
        return None
    return resolved


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
    repo_root_resolved = repo_root.resolve()
    for pat in include_globs:
        for p in sorted(repo_root.glob(pat)):
            resolved = _accept(p, repo_root_resolved, excludes, skip_dirs)
            if resolved is None or resolved in seen:
                continue
            seen.add(resolved)
            out.append(p)
    return out
