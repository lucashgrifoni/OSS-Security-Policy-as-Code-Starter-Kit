"""Install every runtime dependency at exactly the floor `pyproject.toml` declares.

The floors are a published promise: `python-hcl2>=6.1` tells an adopter that 6.1 works.
Until 2026-09-19 nothing had ever run the suite against them, and one of the nine was
wrong. It failed quietly, which is the part that matters: at `python-hcl2==6.1.0` four
Terraform controls answered `manual-review-required` where the fixture gives `pass` and a
fifth stopped triggering, so the tool produced wrong verdicts rather than an error.

The pins come from `pyproject.toml`, so this cannot drift from what the package declares.
A second list of floors maintained beside the first is the defect this is meant to catch,
one level up.

Only `>=` floors are installed. A pin (`==`) is already exact, and a dependency with no
lower bound has no floor to test; both are reported and skipped.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # noqa: S404 - fixed argv built from pyproject, shell=False
import sys
import tomllib
from pathlib import Path

#: `name>=version`, with optional extras and whitespace. Anything else is not a floor.
_FLOOR = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*(?P<extras>\[[^\]]*\])?\s*>=\s*(?P<version>[0-9][^,;\s]*)")


def _requirements(pyproject: Path, groups: list[str]) -> list[str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data["project"]
    out: list[str] = list(project.get("dependencies", []))
    optional = project.get("optional-dependencies", {})
    for group in groups:
        if group not in optional:
            raise SystemExit(f"no optional-dependency group named {group!r} in {pyproject.name}")
        out.extend(optional[group])
    return out


def floor_pins(requirements: list[str]) -> tuple[list[str], list[str]]:
    """Split *requirements* into exact floor pins and the ones that have no floor."""

    pins: dict[str, str] = {}
    skipped: list[str] = []
    for raw in requirements:
        spec = raw.split("#", 1)[0].strip()
        if not spec:
            continue
        match = _FLOOR.match(spec)
        if match is None:
            skipped.append(spec)
            continue
        name = match.group("name")
        extras = match.group("extras") or ""
        version = match.group("version")
        # A package named in more than one group must resolve to one pin, and the highest
        # floor is the one the package actually promises.
        candidate = f"{name}{extras}=={version}"
        previous = pins.get(name.lower())
        if previous is None or _as_tuple(version) > _as_tuple(previous.split("==", 1)[1]):
            pins[name.lower()] = candidate
    return [pins[key] for key in sorted(pins)], skipped


def _as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument(
        "--group",
        action="append",
        default=None,
        help="An optional-dependency group to include. Repeatable. Default: all.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the pins and install nothing.")
    args = parser.parse_args(argv)

    groups = args.group if args.group is not None else ["all"]
    pins, skipped = floor_pins(_requirements(args.pyproject, groups))

    print(f"Floors declared in {args.pyproject.name} for groups {groups}:")
    for pin in pins:
        print(f"  {pin}")
    if skipped:
        print("No lower bound to test, skipped:")
        for spec in skipped:
            print(f"  {spec}")
    if not pins:
        print("Nothing to install.", file=sys.stderr)
        return 1
    if args.dry_run:
        return 0

    argv_install = [sys.executable, "-m", "pip", "install", *pins]
    print("\n" + " ".join(argv_install))
    return subprocess.run(argv_install, shell=False, check=False).returncode  # noqa: S603 - fixed argv


if __name__ == "__main__":
    raise SystemExit(main())
