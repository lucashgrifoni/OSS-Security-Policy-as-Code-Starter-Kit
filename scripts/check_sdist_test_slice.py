#!/usr/bin/env python3
"""Refuse an sdist that carries a slice of the test suite which cannot run.

The sdist used to contain the eight top-level files of ``tests/`` and nothing else from
it, chosen by the setuptools default rather than by anyone. ``tests/conftest.py`` stayed
behind, and two of the eight do ``from tests.conftest import ROOT``, so pytest inside the
unpacked sdist aborted collection and none of the eight ran.

The rule this enforces is not "ship no tests". Shipping the whole suite is a reasonable
thing for a project to do, and distribution packagers ask for it. What is never reasonable
is shipping a part of it that raises on import, because it looks like test coverage and is
not. So: either the sdist carries no test module at all, or it carries ``conftest.py``
alongside the modules that import it.

Run from the repository root after ``python -m build``::

    python scripts/check_sdist_test_slice.py
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

#: Every module under a top-level ``tests`` directory inside the archive.
_TESTS_PREFIX = "tests/"
_CONFTEST = "tests/conftest.py"


def _inside_archive(name: str) -> str:
    """The path of *name* relative to the sdist's single top-level directory.

    An sdist member is ``oss_policy_kit-10.0.24/tests/x.py``; the version in that prefix
    changes every release, so every comparison below is made after stripping it.
    """

    _, _, remainder = name.partition("/")
    return remainder


def unrunnable_test_slice(names: list[str]) -> list[str]:
    """Test modules in *names* that ship without the ``conftest.py`` they need.

    Returns an empty list both when no test module ships and when ``conftest.py`` ships
    with them, because those are the two states this check accepts.
    """

    inside = [_inside_archive(name) for name in names]
    modules = sorted(
        path for path in inside if path.startswith(_TESTS_PREFIX) and path.endswith(".py") and path != _CONFTEST
    )
    if not modules or _CONFTEST in inside:
        return []
    return modules


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    root = Path(arguments[0]) if arguments else Path("dist")
    archives = sorted(root.glob("*.tar.gz"))
    if not archives:
        print(f"no sdist under {root.as_posix()}/; run `python -m build` first", file=sys.stderr)
        return 2

    failed = False
    for archive in archives:
        with tarfile.open(archive) as handle:
            offenders = unrunnable_test_slice(handle.getnames())
        if offenders:
            failed = True
            listed = "\n  ".join(offenders)
            print(
                f"{archive.name} ships {len(offenders)} test module(s) without tests/conftest.py, "
                f"so pytest aborts collection inside the unpacked sdist:\n  {listed}\n"
                "Either prune tests from the sdist or ship conftest.py with them.",
                file=sys.stderr,
            )
        else:
            print(f"[sdist] OK: {archive.name} ships no test slice that cannot run.")
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
