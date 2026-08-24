"""Static checks for the optional GitHub Pages site."""

from __future__ import annotations

import json
import re
from pathlib import Path

_GITPAGE = Path(__file__).parents[2] / "gitpage"


def test_gitpage_uses_committed_tailwind_css_not_runtime_cdn() -> None:
    index = (_GITPAGE / "index.html").read_text(encoding="utf-8")

    assert "cdn.tailwindcss.com" not in index
    assert 'href="site.css"' in index
    assert (_GITPAGE / "tailwind.css").is_file()
    assert (_GITPAGE / "site.css").is_file()
    assert (_GITPAGE / "bundle.js").is_file()


#: Series each build dependency must stay within, and why the boundary sits there.
#:
#: Tailwind is held to major 4: PR #29 moved it across a major and broke the published page,
#: which is the incident this guard was written for. esbuild is held to its minor because it
#: is pre-1.0, where a minor bump is where breakage is allowed to live.
_ALLOWED_SERIES = {
    "tailwindcss": "4",
    "@tailwindcss/cli": "4",
    "esbuild": "0.28",
}

_CARET_RANGE = re.compile(r"^\^(\d+\.\d+\.\d+)$")


def test_gitpage_tailwind_build_is_pinned_and_repeatable() -> None:
    """Declared range and lockfile must agree, and neither may leave its series.

    This used to assert three literal version strings. That made it fail on every routine
    patch bump -- a Dependabot pull request could not go green until someone hand-edited the
    test -- so the bumps sat open instead, which is a worse outcome than the drift the guard
    was protecting against.

    The properties it was actually written to hold are asserted directly instead: the range
    is a caret on an exact version rather than a floating one, the lockfile resolves to that
    same version, and neither dependency crosses the boundary where breakage is expected. A
    patch bump now passes on its own; a major Tailwind bump still cannot.
    """

    package = json.loads((_GITPAGE / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((_GITPAGE / "package-lock.json").read_text(encoding="utf-8"))

    for name, series in _ALLOWED_SERIES.items():
        declared = package["devDependencies"][name]
        match = _CARET_RANGE.match(declared)
        assert match, (
            f"{name} is declared as {declared!r}. The build is meant to be repeatable, which "
            "needs a caret range on an exact version, not a floating one."
        )
        pinned = match.group(1)

        resolved = lock["packages"][f"node_modules/{name}"]["version"]
        assert resolved == pinned, (
            f"{name}: package.json asks for {declared!r} and package-lock.json resolved "
            f"{resolved!r}. Run `npm install` in gitpage/ so the two agree, or the build is "
            "not reproducible from the checked-in files."
        )

        assert pinned == series or pinned.startswith(f"{series}."), (
            f"{name} moved to {pinned}, outside the {series}.x series this page is built "
            "against. That is where breaking changes are allowed to live for this package, "
            "so the bump needs the page rebuilt and looked at, not just a green test."
        )

    assert "node ./node_modules/@tailwindcss/cli/dist/index.mjs" in package["scripts"]["build:css"]
    assert package["scripts"]["build:js"] == "node build-js.mjs"


def test_gitpage_readme_documents_tailwind_build_boundary() -> None:
    readme = (_GITPAGE / "README.md").read_text(encoding="utf-8")

    assert "npm run build" in readme
    assert "Tailwind is bundled" in readme
    assert "JSX is bundled" in readme
