"""A link in the docs that points at a page which has never existed.

`docs/v6.0.0-migration-guide.md` sent readers to `docs/reports-contract.md` for "the current
contracts". No such file has ever been in the tree. The same page links
`reports-contract-v2.0.md` correctly twice further down, so the broken one was a typo that
nothing could see: a relative markdown link is not a Python import and not a CLI flag, so none
of the guards that check either of those looks at it.

Only relative links are checked. An external URL needs the network, which would make the suite
depend on somebody else's uptime; those are out of scope here and stay so deliberately.

One subtlety worth keeping. GitHub's heading slugs do NOT collapse runs of spaces: a heading
containing " - " becomes `--` in the anchor, with two hyphens. A checker that collapses them
reports a false positive on `docs/framework-alignment.md#nist-sp-800-218a--generative-ai...`,
which is a correct link. `_slug` below keeps every hyphen for that reason.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from tests.conftest import ROOT

#: `[text](target)`, target captured. Skips images, which start with `!`.
_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

#: An ATX heading, whose text becomes an anchor.
_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)

#: A fenced block, so a link inside an example is not mistaken for a live one.
_FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)


def _markdown_files() -> list[Path]:
    """Every markdown file git TRACKS, which is the set that actually ships.

    Not `rglob`. A working tree carries whatever the maintainer left in it, and this one had a
    `.tmp-validation/` directory of generated reports whose own links point at sibling files
    that come and go; the first version of this guard walked into it and crashed on a path that
    vanished between the listing and the read. Asking git keeps the guard measuring the
    repository rather than one machine's leftovers.
    """

    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return sorted(ROOT / name for name in listed.split("\0") if name)


def _slug(heading: str) -> str:
    """GitHub's anchor slug: strip formatting, lowercase, spaces to hyphens, drop the rest.

    Runs of spaces are NOT collapsed, which is the part that produces double hyphens.
    """

    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\*\*?([^*]*)\*\*?", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return text.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    body = _FENCE.sub("", path.read_text(encoding="utf-8"))
    return {_slug(h) for h in _HEADING.findall(body)}


def test_every_relative_documentation_link_resolves() -> None:
    broken: list[str] = []
    for page in _markdown_files():
        body = _FENCE.sub("", page.read_text(encoding="utf-8"))
        for target in _LINK.findall(body):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue
            resolved = (page.parent / path_part).resolve()
            if not resolved.exists():
                broken.append(f"{page.relative_to(ROOT).as_posix()} -> {target} (no such path)")

    assert not broken, "documentation links that resolve to nothing: " + "; ".join(broken)


def test_every_anchor_a_document_links_to_exists() -> None:
    """The half a path check misses: the file is right and the heading is not."""

    missing: list[str] = []
    for page in _markdown_files():
        body = _FENCE.sub("", page.read_text(encoding="utf-8"))
        for target in _LINK.findall(body):
            if target.startswith(("http://", "https://", "mailto:")) or "#" not in target:
                continue
            path_part, anchor = target.split("#", 1)
            if not anchor:
                continue
            other = page if not path_part else (page.parent / path_part).resolve()
            if other.suffix != ".md" or not other.exists():
                continue
            if anchor.lower() not in _anchors(other):
                where = page.relative_to(ROOT).as_posix()
                missing.append(f"{where} -> {target} (no heading slugs to that)")

    assert not missing, "documentation anchors that match no heading: " + "; ".join(missing)


def test_the_link_guard_is_reading_something() -> None:
    """Anti-vacuum: both checks above pass on an empty corpus, which is how a walker rots."""

    pages = _markdown_files()
    relative = [
        t
        for p in pages
        for t in _LINK.findall(_FENCE.sub("", p.read_text(encoding="utf-8")))
        if not t.startswith(("http://", "https://", "mailto:", "#"))
    ]

    assert len(pages) >= 50, f"only {len(pages)} markdown files found; the walk is not reaching docs/"
    assert len(relative) >= 100, f"only {len(relative)} relative links parsed; the link pattern has stopped matching"
