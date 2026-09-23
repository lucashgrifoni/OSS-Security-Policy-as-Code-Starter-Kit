#!/usr/bin/env python3
"""Refuse a wheel or sdist that carries compiled bytecode.

``pyproject.toml`` excludes ``__pycache__`` and ``*.py[co]`` from package data, and nothing
checked that the exclusion held. The builds in CI and in the release start from a fresh
checkout, which has no bytecode in it, so a clean artifact proved only that there was nothing
to leave out.

Measured on 2026-09-23 with bytecode compiled into ``src/`` first, the rule is not what keeps
it out today. The package-data patterns name ``py.typed``, ``.yaml``, ``.yml`` and ``.json``,
so a ``.pyc`` matches none of them, and the wheel came out clean with the rule deleted. With
the patterns widened to ``data/**/*``, the shape the comment above them warns against,
``data/schema/__pycache__/__init__.cpython-312.pyc`` shipped without the rule and stayed out
with it. Two layers, then, and this checks the outcome both of them exist for.

The Package job compiles ``src/`` before it builds, so there is bytecode for this to refuse.

Run from the repository root after ``python -m build``::

    python scripts/check_dist_ships_no_bytecode.py
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


def bytecode_members(names: list[str]) -> list[str]:
    """Members of an archive that are compiled bytecode or sit in a bytecode cache."""

    return sorted(name for name in names if "__pycache__" in name.split("/") or name.endswith((".pyc", ".pyo")))


def _members(archive: Path) -> list[str]:
    if archive.suffix == ".whl":
        with zipfile.ZipFile(archive) as handle:
            return handle.namelist()
    with tarfile.open(archive) as handle:
        return handle.getnames()


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    root = Path(arguments[0]) if arguments else Path("dist")
    archives = sorted([*root.glob("*.whl"), *root.glob("*.tar.gz")])
    if not archives:
        print(f"no distribution under {root.as_posix()}/; run `python -m build` first", file=sys.stderr)
        return 2

    failed = False
    for archive in archives:
        offenders = bytecode_members(_members(archive))
        if offenders:
            failed = True
            listed = "\n  ".join(offenders[:20])
            print(f"{archive.name} ships {len(offenders)} bytecode member(s):\n  {listed}", file=sys.stderr)
        else:
            print(f"[dist] OK: {archive.name} ships no bytecode.")
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
