"""The runtime stage is what makes the base-image alerts not apply to the published image.

Eleven of the twelve open code-scanning alerts on this repository come from one job,
`base-image-trivy`, which scans the image the `Dockerfile` builds *from*. They are
accurate about that image and none of them can be closed by editing this repository:
measured 2026-09-09, the current upstream `python:3.12-slim-bookworm` digest carries the
identical eleven, so refreshing the pin clears nothing.

What keeps them out of the image this project *publishes* is two lines in the runtime
stage, and nothing else:

- `apt-get upgrade` applies the Debian security pocket, which moves `libpcre2-8-0` from
  `10.42-1` to `10.42-1+deb12u1` -- the five `libpcre2` advisories;
- two `pip uninstall` commands remove the interpreter's package installer from both the
  system Python and the venv -- the six `pip 25.0.1` advisories.

Delete either and the published image silently regains those CVEs while the alert list
on this repository does not move by one, because the alerts were never measuring the
published image. That is the failure this test exists to make loud. It ran on the built
image on 2026-09-09: `libpcre2-8-0 10.42-1+deb12u1`, no `pip` dist-info under either
interpreter, and Trivy reporting zero fixable vulnerabilities at any severity, against
eleven on the base.

The Dockerfile is read rather than the image built, so this runs in the ordinary test job
in seconds. Comments are stripped before anything is matched: the prose in the runtime
stage discusses `pip uninstall` at length, so a check that judged raw text would pass on
the explanation alone with the command deleted. This repository has already shipped one
control that read a commented-out step as a live one.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE = _REPO_ROOT / "Dockerfile"

#: A floor under the number of commands found in the runtime stage. Without it, a stage
#: split that stopped matching would reduce every assertion below to a search of an empty
#: string, and an empty string contains no deleted command either. The stage held 4 `RUN`
#: commands on 2026-09-09.
_MINIMUM_RUNTIME_COMMANDS = 3


def _instructions(text: str) -> list[str]:
    """Dockerfile instructions with comments removed and continuations joined.

    Comment lines go first, before continuations are joined: a `#` line inside a `\\`
    continuation would otherwise swallow the command that follows it.
    """

    live = [line for line in text.split("\n") if not line.lstrip().startswith("#")]
    joined = re.sub(r"\\\n\s*", " ", "\n".join(live))
    return [line.strip() for line in joined.split("\n") if line.strip()]


def _runtime_stage(text: str) -> list[str]:
    """The instructions of the stage named `runtime`, up to the next `FROM` or the end."""

    out: list[str] = []
    collecting = False
    for instruction in _instructions(text):
        if re.match(r"^FROM\s", instruction, flags=re.IGNORECASE):
            collecting = bool(re.search(r"\bAS\s+runtime\s*$", instruction, flags=re.IGNORECASE))
            continue
        if collecting:
            out.append(instruction)
    return out


def _runtime_commands(text: str) -> list[str]:
    return [i for i in _runtime_stage(text) if re.match(r"^RUN\s", i, flags=re.IGNORECASE)]


def test_the_runtime_stage_is_actually_being_read() -> None:
    """A guard over an empty string would pass with every command below deleted."""

    text = _DOCKERFILE.read_text(encoding="utf-8")
    commands = _runtime_commands(text)

    assert len(commands) >= _MINIMUM_RUNTIME_COMMANDS, (
        f"found only {len(commands)} RUN commands in the `runtime` stage, below the floor of "
        f"{_MINIMUM_RUNTIME_COMMANDS}. Either the stage was gutted, or the `AS runtime` split "
        "in this module stopped matching -- in which case the assertions below are searching "
        "an empty stage and pass no matter what the Dockerfile says."
    )

    # The builder stage must not leak in: it installs pip and would satisfy a pip search
    # on its own, which would make this file assert nothing about the published image.
    assert not any("venv /opt/venv" in c for c in commands), (
        "the builder stage's `python -m venv` turned up in what was parsed as the runtime "
        "stage, so the two stages are not being separated and a builder command could "
        "satisfy an assertion meant for the runtime."
    )


def test_comments_are_stripped_before_anything_is_matched() -> None:
    """The runtime stage explains `pip uninstall` in prose; prose must not count as a command."""

    commented_out = "\n".join(
        [
            "FROM scratch AS runtime",
            "# RUN /usr/local/bin/python3 -m pip uninstall --yes pip",
            "# and then apt-get upgrade -y keeps libpcre2 current",
            "RUN true",
        ]
    )
    commands = _runtime_commands(commented_out)

    assert commands == ["RUN true"], (
        f"comment stripping does not work: parsed {commands!r}. A commented-out command "
        "would be read as a live one, and this whole file would pass on the explanation "
        "with the command deleted."
    )


def test_the_runtime_stage_applies_debian_security_updates() -> None:
    """Without this, the published image ships the base image's `libpcre2-8-0 10.42-1`."""

    text = _DOCKERFILE.read_text(encoding="utf-8")
    commands = _runtime_commands(text)

    upgrades = [c for c in commands if re.search(r"apt-get\s+upgrade", c)]
    assert upgrades, (
        "the `runtime` stage no longer runs `apt-get upgrade`. That command is the only "
        "thing moving `libpcre2-8-0` off the vulnerable `10.42-1` the pinned base image "
        "ships, and the five `libpcre2` alerts on this repository will NOT change if it "
        "goes -- they are raised against the base image, not the published one. Removing "
        "it silently reintroduces those CVEs into what users pull. If the base image is "
        "ever rebuilt with the fix included, delete this test and say so in SECURITY.md."
    )


def test_the_runtime_stage_removes_pip_from_both_interpreters() -> None:
    """Two interpreters ship a pip; the image must carry neither."""

    text = _DOCKERFILE.read_text(encoding="utf-8")
    joined = "\n".join(_runtime_commands(text))

    uninstalls = re.findall(r"(\S+)\s+-m\s+pip\s+uninstall", joined)
    interpreters = {Path(path.split("/")[-1] or path).name: path for path in uninstalls}

    assert any("/usr/local" in path for path in uninstalls), (
        "the `runtime` stage no longer uninstalls pip from the system interpreter at "
        "/usr/local. The base image's `pip 25.0.1` carries the six advisories that are "
        f"open against the base image on this repository. Found: {uninstalls!r}"
    )
    assert any("/opt/venv" in path for path in uninstalls), (
        "the `runtime` stage no longer uninstalls pip from the venv interpreter at "
        "/opt/venv. pip vendors msgpack and setuptools and, since 26.x, ships a CycloneDX "
        "BOM that lets a scanner see them, so a venv pip carries whatever those vendored "
        f"copies are missing. Found: {uninstalls!r}"
    )
    assert len(interpreters) >= 2, (
        f"expected pip to be uninstalled from two distinct interpreters, found {uninstalls!r}"
    )
