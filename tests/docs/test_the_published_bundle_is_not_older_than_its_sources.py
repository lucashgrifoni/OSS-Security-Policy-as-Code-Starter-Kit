"""Pages serves a prebuilt bundle, and nothing checked that the bundle matched its sources.

`gitpage/bundle.js` and `gitpage/site.css` are committed artifacts. The deploy workflow uploads
the directory as it stands and runs no Node toolchain, so editing a `.jsx` source changes nothing
a visitor sees until someone runs `npm run build` in `gitpage/` and commits the result. Forget
that step and the site keeps serving the previous version of a page whose source has changed --
with every check green, because no check looked.

This repository has already paid for it once: the deploy workflow's own header records a page
"whose numbers were a third of the truth" sitting behind a comment that claimed Babel ran in the
browser.

**Why commit dates rather than a rebuild.** Rebuilding here would need Node and esbuild on the
runner, and esbuild's install fetches a platform binary from a host this workflow's egress policy
does not admit. Widening that policy to gain a check is a poor trade. The commit history answers
the same question without a toolchain: if a source was last touched AFTER the artifact built from
it, the artifact cannot contain that change. That is exactly the failure mode, and it is the one
a person actually produces.

What this does not catch, stated rather than implied: a source and its artifact committed
together where the artifact was stale at the time. Only a rebuild proves that, and the build was
verified by hand against these files on 2026-09-15 (`bundle.js` and `site.css` matched a fresh
`npm run build` byte for byte).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GITPAGE = _REPO_ROOT / "gitpage"
_BUILDER = _GITPAGE / "build-js.mjs"

#: Derived from the builder rather than listed here, so a source added to the bundle joins this
#: guard without anybody remembering to extend a list. Each artifact gets its OWN sources: a
#: `.jsx` edit cannot make `site.css` stale, and the first version of this guard said it could.
_JSX_SOURCE = re.compile(r'^\s*"([^"]+\.jsx)",\s*$', re.MULTILINE)
_CSS_SOURCE = re.compile(r'\[([^\]]*\.css"[^\]]*)\]')

#: artifact -> the sources the builder concatenates into it.
_BUILT_FROM = {"bundle.js": "jsx", "site.css": "css"}


def _last_commit_iso(path: Path) -> str | None:
    """The committer date of the last commit touching *path*, or None when it has none."""

    out = subprocess.run(
        ["git", "log", "-1", "--format=%cI", "--", path.relative_to(_REPO_ROOT).as_posix()],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() or None


def _declared_sources(kind: str = "jsx") -> list[Path]:
    text = _BUILDER.read_text(encoding="utf-8")
    if kind == "jsx":
        return [_GITPAGE / name for name in _JSX_SOURCE.findall(text)]
    block = _CSS_SOURCE.search(text)
    names = re.findall(r'"([^"]+\.css)"', block.group(1)) if block else []
    return [_GITPAGE / name for name in names]


def test_the_builder_still_declares_the_sources_this_guard_reads() -> None:
    """Anti-vacuum: an empty source list would pass every assertion below and prove nothing."""

    jsx = _declared_sources("jsx")
    css = _declared_sources("css")

    assert len(jsx) >= 10, f"only {len(jsx)} jsx sources parsed out of build-js.mjs"
    assert len(css) >= 2, f"only {len(css)} css sources parsed out of build-js.mjs"
    for source in (*jsx, *css):
        assert source.is_file(), f"{source.name} is declared by the builder and does not exist"


def test_git_answers_for_these_paths() -> None:
    """If git cannot date the artifact, every comparison below is vacuously true."""

    assert _last_commit_iso(_GITPAGE / "bundle.js"), "bundle.js has no commit history here"


@pytest.mark.parametrize("artifact", ["bundle.js", "site.css"])
def test_the_built_artifact_is_not_older_than_any_source_it_contains(artifact: str) -> None:
    built = _last_commit_iso(_GITPAGE / artifact)
    if built is None:  # pragma: no cover - a shallow clone has no history to compare
        pytest.skip("no commit history for the artifact in this checkout")

    stale = []
    for source in _declared_sources(_BUILT_FROM[artifact]):
        touched = _last_commit_iso(source)
        if touched and touched > built:
            stale.append(f"{source.name} ({touched}) is newer than {artifact} ({built})")

    assert not stale, (
        "gitpage/ is stale: a source changed after the artifact Pages serves was built, so the "
        "published site does not contain that change.\n    "
        + "\n    ".join(stale)
        + "\n\n  Run `cd gitpage && npm run build` and commit bundle.js, site.css and "
        "tailwind.css alongside the source edit."
    )


def test_the_catalog_data_partial_is_regenerated_not_hand_edited() -> None:
    """`generate-gitpage-catalog-data.py --check` exists and nothing was calling it.

    The site's control and profile counts come from this generated partial. Left unregenerated,
    the page advertises a catalog the kit no longer ships.
    """

    result = subprocess.run(
        ["python", "scripts/generate-gitpage-catalog-data.py", "--check"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, (
        "gitpage/parts/catalog-data.jsx does not match the bundled catalog:\n"
        f"{result.stdout}{result.stderr}\n"
        "  Run `python scripts/generate-gitpage-catalog-data.py` and commit the result."
    )
