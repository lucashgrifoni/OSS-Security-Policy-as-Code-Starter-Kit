"""Eleven shipped commands ran the kit with the repository it was scanning on ``sys.path``.

``python -m oss_policy_kit`` puts the current working directory first on ``sys.path``. Several
shipped surfaces set that directory to the repository under evaluation, so an
``oss_policy_kit.py`` committed at the root of a scanned repo ran as ``__main__`` before any
control did, with whatever the job holds in its environment:

- ``action.yml`` runs it in ``GITHUB_WORKSPACE``, and ``rc=$?`` on the next line makes the
  decoy's exit status the gate's verdict -- a measured run wrote ``exit_code=0`` with no
  report and no evaluation;
- the container ``ENTRYPOINT`` and ``HEALTHCHECK`` run under ``WORKDIR /work``, the bind-mount
  point every command in ``docs/container-image.md`` uses for the adopter's repository;
- ``.pre-commit-hooks.yaml`` runs in the adopter's clone and decides the exit code of a commit.

The six workflow templates teach it too, and ``init --with-workflow`` writes one of them into
the adopter's repository, where it runs on ``pull_request``.

The mechanism was already understood here. ``action.yml`` uses ``python -P`` for its version
check thirty-seven lines above the defect, under a comment explaining that an import from the
workspace must not shadow the installed distribution. What that comment describes shadowing a
version assertion, line 211 executes.

This guard is derived rather than listed, because a list is what fails next time. It sweeps the
shipped surfaces, finds every ``python -m oss_policy_kit``, and requires each to be hardened or
to carry a waiver naming why its working directory is trusted. Comments are blanked before the
sweep: this project has already shipped a control that read raw text and gave a commented-out
step a PASS.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT

#: Files and directories that run, or teach, the kit's module invocation.
_SWEPT: tuple[Path, ...] = (
    ROOT / "action.yml",
    ROOT / "Dockerfile",
    ROOT / ".pre-commit-hooks.yaml",
    ROOT / "templates" / "workflows",
    ROOT / "src" / "oss_policy_kit" / "data" / "templates" / "workflows",
    ROOT / ".github" / "workflows",
    ROOT / "pipelines",
)

#: Path fragments whose working directory is the kit's own tree, each carrying the reason the
#: invocation is safe there. A job that already runs ``pytest`` and ``pip install -e .`` against
#: the same checkout gains nothing from ``-m``: it has been handed the tree already. The waivers
#: are asserted to still match something below, because a waiver that covers nothing is a rule
#: nobody follows any more, left behind to be trusted later.
_TRUSTED_CWD: dict[str, str] = {
    # ".github/workflows" was waived here until 2026-09-19, on the grounds that the kit's own
    # CI already installs and tests the checkout it runs in. That was true and it is gone:
    # every invocation in those files now carries -P, so the waiver covered nothing, and a
    # waiver that covers nothing is a rule nobody follows any more. Removing it also makes
    # this guard refuse the next unhardened one rather than excusing it.
    "pipelines": "the kit's own Azure mirror of that CI: same tree, same trust",
}

#: The interpreter flag that removes the current directory from ``sys.path`` for ``-m``.
#: ``-E`` and ``-s`` do not: they touch environment variables and the user site directory.
_HARDENED = "-P"

_INTERPRETERS = frozenset({"python", "python3", "py"})

_EXTENSIONS = frozenset({".yml", ".yaml"})


def _uncommented(line: str) -> str:
    """A full-line comment contributes nothing. Reading raw text is how a PASS was once forged."""

    return "" if line.lstrip().startswith("#") else line


def _module_invocations(text: str) -> list[tuple[int, list[str]]]:
    """``(line number, interpreter flags)`` for each ``python ... -m oss_policy_kit`` in ``text``.

    Quoting is normalised away first, so the shell form and the JSON exec form in the Dockerfile
    are read by one pass rather than by two regexes that can disagree with each other.
    """

    found: list[tuple[int, list[str]]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        tokens = re.sub(r"[\"',\[\]]", " ", _uncommented(raw)).split()
        for index, token in enumerate(tokens):
            if token not in _INTERPRETERS:
                continue
            flags: list[str] = []
            cursor = index + 1
            while cursor < len(tokens) and tokens[cursor].startswith("-") and tokens[cursor] != "-m":
                flags.append(tokens[cursor])
                cursor += 1
            if tokens[cursor : cursor + 2] == ["-m", "oss_policy_kit"]:
                found.append((number, flags))
    return found


def _files() -> list[Path]:
    paths: list[Path] = []
    for entry in _SWEPT:
        if entry.is_dir():
            paths.extend(sorted(p for p in entry.rglob("*") if p.is_file() and p.suffix in _EXTENSIONS))
        elif entry.is_file():
            paths.append(entry)
    return paths


def _waiver_for(path: Path) -> str | None:
    relative = path.relative_to(ROOT).as_posix()
    for fragment, reason in _TRUSTED_CWD.items():
        if relative.startswith(fragment):
            return reason
    return None


def _sweep() -> tuple[list[str], list[str]]:
    """``(unhardened invocations outside any waiver, invocations a waiver covered)``."""

    offending: list[str] = []
    waived: list[str] = []
    for path in _files():
        relative = path.relative_to(ROOT).as_posix()
        for number, flags in _module_invocations(path.read_text(encoding="utf-8")):
            if _HARDENED in flags:
                continue
            where = f"{relative}:{number}"
            if _waiver_for(path) is None:
                offending.append(where)
            else:
                waived.append(where)
    return offending, waived


def test_every_shipped_surface_that_runs_the_kit_keeps_the_scanned_repo_off_sys_path() -> None:
    offending, _ = _sweep()

    assert not offending, (
        "these run `python -m oss_policy_kit` with the directory being evaluated first on "
        f"sys.path; add {_HARDENED}, or a waiver naming why the cwd is trusted: {offending}"
    )


def test_the_flag_the_guard_looks_for_actually_defeats_a_shadowing_module(tmp_path: Path) -> None:
    """The text guard is worth nothing the day ``-P`` stops meaning what it assumes."""

    (tmp_path / "oss_policy_kit.py").write_text("import sys\nsys.exit(42)\n", encoding="utf-8")

    without = subprocess.run([sys.executable, "-m", "oss_policy_kit", "--version"], cwd=tmp_path, capture_output=True)
    hardened = subprocess.run(
        [sys.executable, _HARDENED, "-m", "oss_policy_kit", "--version"], cwd=tmp_path, capture_output=True
    )

    assert without.returncode == 42, "the decoy never ran, so this proves nothing about the flag"
    assert hardened.returncode == 0, hardened.stderr.decode(errors="replace")


def test_every_waiver_still_matches_a_real_invocation() -> None:
    """A waiver nothing matches is a claim about the tree that stopped being true."""

    _, waived = _sweep()
    unused = sorted(fragment for fragment in _TRUSTED_CWD if not any(w.startswith(fragment) for w in waived))

    assert not unused, f"waived paths that no longer hold an unhardened invocation: {unused}"


def test_the_guard_is_reading_something() -> None:
    """An anti-vacuum floor: every assertion above passes trivially on an empty sweep."""

    files = _files()

    assert len(files) >= 10, f"the sweep found {len(files)} files, so it read almost nothing"
    assert any(_module_invocations(path.read_text(encoding="utf-8")) for path in files), (
        "no module invocation was parsed at all, so the sweep was blind"
    )
    assert _module_invocations("  run: python -P -m oss_policy_kit evaluate\n") == [(1, ["-P"])]
    assert _module_invocations('  CMD ["python", "-m", "oss_policy_kit"]\n') == [(1, [])]
    assert _module_invocations("# python -m oss_policy_kit evaluate\n") == []
