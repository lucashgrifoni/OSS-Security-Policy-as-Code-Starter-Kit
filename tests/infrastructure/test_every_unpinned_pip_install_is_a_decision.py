"""Every `pip install` this repository runs is pinned, or is on a list of decisions.

Scorecard's Pinned-Dependencies check reports each `pip install` that could resolve
something the repository has not committed to. Three of ours are deliberate and are
written up in SECURITY.md. The rest are pinned, and must stay that way.

The alert stream is not a usable guard for that. On 2026-09-02 the real Scorecard
reported EIGHT unpinned pip commands in this tree while GitHub code scanning showed
four; whatever caused the gap, reading the alert count as the finding count would have
missed half of them. Two of the eight were also the same `python -m pip install -U pip`
string in one file, 124 lines apart, and a pass that fixed one of them described the
class as fixed.

So this test applies Scorecard's own rule locally, to every workflow and the Dockerfile,
and asserts the unpinned set is exactly the three accepted ones. A new unpinned install
fails here, in the pull request that adds it, with the reason it failed -- rather than
appearing as an alert some weeks later, or not appearing at all.

The rule is transcribed from `isUnpinnedPipInstall` in ossf/scorecard
(`checks/raw/shell_download_validate.go`), read at that same date. In particular:

- `--require-hashes` pins, and short-circuits the rest of the scan;
- an argument ending in `.whl` pins, on the suffix alone -- which is why the Dockerfile
  builds a wheel and installs that, and why `dist/*.whl` is accepted while
  `"${wheels[0]}"` is not, though the two install the identical file;
- `--no-deps` pins nothing on its own for a non-editable install. A comment in
  github-ci-cd.yml claimed it did, and was wrong for as long as it stood;
- `-e .` pins only when `--no-deps` is also present.

If Scorecard changes the rule, this test keeps enforcing the old one. That is the
intended failure mode: it is a guard over our own decisions, and the numbers it
produces are checked against the real scanner when the rule is revisited, not on every
run.
"""

from __future__ import annotations

import re
import shlex
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"
_DOCKERFILE = _REPO_ROOT / "Dockerfile"

#: Interpreters Scorecard recognises as able to carry `-m pip`.
_PYTHON_INTERPRETERS = frozenset({"python", "python3"})
_PIP_BINARIES = frozenset({"pip", "pip3"})

#: A floor under the number of pip installs the scan finds. Without it, a change to the
#: comment stripping or the splitting below could quietly reduce this test to asserting
#: that an empty set equals an empty set. The tree held 23 on 2026-09-02; the floor is
#: deliberately lower so that removing a job does not fail the build for the wrong reason.
_MINIMUM_PIP_INSTALLS_FOUND = 16

#: The unpinned installs that are accepted, and why. Each entry is (path relative to the
#: repo root, the command after `shlex.split` -- so shell quoting is already removed, and
#: `-e ".[dev]"` in the workflow appears here as `-e .[dev]`). Counted, not set-compared:
#: the dev extra is installed in three separate jobs in that file and all are accepted.
#:
#: - the three `.[dev]` installs resolve the dev tool ranges `pyproject.toml` declares. A
#:   lock would have to be regenerated inside every Dependabot bump of a dev tool, and
#:   would fail silently when it drifted -- CI testing one ruff while the project
#:   declares another.
#: - the pip-audit install is the job's whole point: it audits the runtime closure the
#:   declared ranges resolve to. Pinning it would audit the lock instead, and report
#:   clean on the day a newly published range-satisfying version became vulnerable.
#: - the live-collector canary installs the same dev extra as the quality job, and for the
#:   same reason. Its purpose is to run one test the way this repository runs every other
#:   one, so an install shape unique to that job would be testing a configuration nothing
#:   else uses. It is also the only job here that never gates a merge.
#: - the dependency-floors job installs the dev extra for its test tooling and then forces
#:   every runtime dependency down to the floor `pyproject.toml` declares. Pinning the dev
#:   install would not change what that job measures, which is the runtime floors, and it
#:   would tie the job to a lock it has no reason to care about.
_ACCEPTED_UNPINNED = Counter(
    {
        (".github/workflows/github-ci-cd.yml", "python -m pip install -e .[dev]"): 3,
        (".github/workflows/security-ci-cd.yml", "python -m pip install -e ."): 1,
        (".github/workflows/live-collector-canary.yml", "python -m pip install -e .[dev]"): 1,
    }
)


def _is_pinned_editable_source(source: str) -> bool:
    """Scorecard treats a non-VCS editable source as pinned; a VCS one needs a 40-hex ref."""

    if not re.match(r"^(git|svn|hg|bzr).+$", source):
        return True
    return bool(re.match(r"^git(\+(https?|ssh|git))?://.*(\.git)?@[a-fA-F0-9]{40}(#egg=.*)?$", source))


def _is_unpinned_pip_install(cmd: list[str]) -> bool:
    """Transcription of `isUnpinnedPipInstall`. `cmd` is normalised to start `pip install`."""

    has_no_deps = False
    is_editable = False
    is_pinned_editable = True
    has_require_hashes = False
    has_additional_args = False
    has_wheel = False

    for arg in cmd[2:]:
        if arg.lower() == "--no-deps":
            has_no_deps = True
            continue
        if arg in ("-e", "--editable"):
            is_editable = True
            continue
        if arg.lower() == "--require-hashes":
            has_require_hashes = True
            break
        if arg.startswith("-"):
            continue
        if arg.endswith(".whl"):
            has_wheel = True
            continue
        if is_editable:
            if not _is_pinned_editable_source(arg):
                is_pinned_editable = False
            continue
        has_additional_args = True

    if is_editable:
        return not has_no_deps or not is_pinned_editable
    if has_require_hashes:
        return False
    if has_additional_args:
        return True
    return not has_wheel


def _as_pip_install(tokens: list[str]) -> list[str] | None:
    """Return the command normalised to `['pip', 'install', ...]`, or None if it is not one."""

    if len(tokens) < 2:
        return None
    binary = Path(tokens[0]).name
    if binary in _PIP_BINARIES and tokens[1] == "install":
        return ["pip", *tokens[1:]]
    if binary in _PYTHON_INTERPRETERS:
        for i in range(len(tokens) - 2):
            if tokens[i] == "-m" and tokens[i + 1] == "pip" and tokens[i + 2] == "install":
                return ["pip", *tokens[i + 2 :]]
    return None


def _shell_fragments(text: str, join_continuations: bool) -> list[str]:
    """Comment-free shell fragments, split on the operators that separate commands.

    Comments are dropped BEFORE anything else. A commented-out install is not an
    install, and this repository has already shipped one control that judged raw text
    and passed a step that was commented out.
    """

    if join_continuations:
        text = re.sub(r"\\\n\s*", " ", text)
    live = [line for line in text.split("\n") if not line.lstrip().startswith("#")]
    return [frag for line in live for frag in re.split(r"&&|\|\||;|(?<!\|)\|(?!\|)", line)]


def _pip_installs_in(path: Path) -> list[tuple[str, str]]:
    """Every pip install in one file, as (relative path, command as written)."""

    text = path.read_text(encoding="utf-8")
    found: list[tuple[str, str]] = []
    for fragment in _shell_fragments(text, join_continuations=path.name == "Dockerfile"):
        stripped = fragment.strip()
        if "pip" not in stripped or "install" not in stripped:
            continue
        stripped = re.sub(r"^RUN\s+", "", stripped)
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            continue
        if _as_pip_install(tokens) is not None:
            found.append((path.relative_to(_REPO_ROOT).as_posix(), " ".join(tokens)))
    return found


def _scan() -> tuple[list[tuple[str, str]], Counter[tuple[str, str]]]:
    """All pip installs, and the subset Scorecard's rule calls unpinned."""

    targets = sorted(_WORKFLOW_DIR.glob("*.yml")) + [_DOCKERFILE]
    every: list[tuple[str, str]] = []
    for target in targets:
        every.extend(_pip_installs_in(target))

    unpinned: Counter[tuple[str, str]] = Counter()
    for rel_path, command in every:
        cmd = _as_pip_install(shlex.split(command))
        assert cmd is not None  # _pip_installs_in only returns commands that parse
        if _is_unpinned_pip_install(cmd):
            unpinned[(rel_path, command)] += 1
    return every, unpinned


def test_the_scan_actually_reaches_the_pip_installs() -> None:
    """A guard that finds nothing to check would pass no matter what the workflows said."""

    every, _ = _scan()
    assert len(every) >= _MINIMUM_PIP_INSTALLS_FOUND, (
        f"found only {len(every)} pip installs across {_WORKFLOW_DIR.name}/ and the Dockerfile, "
        f"below the floor of {_MINIMUM_PIP_INSTALLS_FOUND}. Either a lot of CI was deleted, or "
        "the comment stripping / command splitting in this module stopped seeing them -- in "
        "which case the assertion below is passing for the wrong reason."
    )
    assert any(path == "Dockerfile" for path, _ in every), (
        "no pip install found in the Dockerfile, which builds the published image. The "
        "continuation-joining in _shell_fragments is the first thing to check."
    )


def test_the_unpinned_installs_are_exactly_the_accepted_ones() -> None:
    _, unpinned = _scan()

    added = unpinned - _ACCEPTED_UNPINNED
    removed = _ACCEPTED_UNPINNED - unpinned

    if added:
        listing = "\n".join(f"  {path}: {command}" for (path, command), n in sorted(added.items()) for _ in range(n))
        raise AssertionError(
            "a pip install in this repository resolves something that is not committed to:\n"
            f"{listing}\n\n"
            "Pin it, or add it to _ACCEPTED_UNPINNED with the reason. Ways to pin, in "
            "descending order of preference:\n"
            "  --require-hashes -r .github/requirements/<name>.txt   (a hashed lock; Dependabot watches these)\n"
            "  install a built wheel by a path ending in .whl        (what the Dockerfile does)\n"
            "  -e . together with --no-deps                          (source install, dependencies from a lock)\n"
            "Note that --no-deps alone does NOT pin a non-editable install."
        )

    if removed:
        listing = "\n".join(f"  {path}: {command}" for (path, command), n in sorted(removed.items()) for _ in range(n))
        raise AssertionError(
            "an accepted unpinned install is pinned now, or no longer exists:\n"
            f"{listing}\n\n"
            "Good news, but the acceptance has to go too: remove it from _ACCEPTED_UNPINNED "
            "here and from the 'Findings dismissed on purpose' section of SECURITY.md. An "
            "exception that outlives its reason is worse than one never granted."
        )


def test_the_accepted_installs_are_documented_in_the_security_policy() -> None:
    """The list above is a decision; SECURITY.md is where a reader looks for the reason.

    This used to check only that the section's heading existed, and the table under it said
    three while five were accepted here: the dependency-floors job and the live collector
    canary each added one, and the prose never moved. So the table is counted too, per file.
    """

    policy = (_REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Findings dismissed on purpose" in policy, (
        "SECURITY.md no longer has the section that explains the accepted findings, but "
        f"{sum(_ACCEPTED_UNPINNED.values())} unpinned pip installs are still accepted here."
    )
    accepted: Counter[str] = Counter()
    for (path, _), count in _ACCEPTED_UNPINNED.items():
        accepted[path] += count
    documented = Counter(
        match.group(1) for match in re.finditer(r"^\| `([^`]+\.yml)` \| `python -m pip install", policy, re.MULTILINE)
    )
    assert documented == accepted, (
        f"SECURITY.md lists {dict(documented)} unpinned installs per workflow, and this test accepts "
        f"{dict(accepted)}. The contract is one table row per accepted install, naming its job."
    )
