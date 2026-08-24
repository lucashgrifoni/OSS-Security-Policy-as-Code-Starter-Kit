"""Every script the published site loads from a third party must be pinned by hash.

`deploy-github-pages.yml` uploads `path: ./gitpage` — the whole directory, with no filter — so
every HTML file sitting there is served from the project's Pages origin. `index.html`, the page
anyone actually visits, was hardened for this: it loads `react@18.3.1` and `react-dom@18.3.1` with
`integrity="sha384-…"` and `crossorigin`.

`gitpage/preview.html` was versioned as a standalone local preview and then went out with the
directory. It loads `https://cdn.tailwindcss.com` with **no version and no integrity** — a JIT CDN
whose own documentation says not to use it in production. Whoever controls that response executes
arbitrary JavaScript on the project's Pages origin. For a kit whose product is supply-chain policy,
that is also the exact control it ships to others.

**Scripts only, and the reason matters.** The same file loads a Google Fonts stylesheet without
integrity, and that is not the same defect: Google Fonts returns different CSS per user-agent, so
SRI is impossible there by construction, and a stylesheet cannot execute script. A guard demanding
integrity on every external subresource would fail on the font and could only be satisfied by
deleting it — a guard that forces a wrong change is worse than no guard.

**The published set is derived, not hardcoded.** It is the upload step's `path:` minus whatever the
job removes before uploading. `actions/upload-pages-artifact` has no `exclude` input — its inputs
are `name`, `path`, `retention-days`, `include-hidden-files` — so an `exclude:` added in good faith
would be a silent no-op, and pruning has to be a real step. If the pruning mechanism ever changes
shape, this guard fails rather than quietly passing, which is the correct direction to fail in.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests.conftest import ROOT

_WORKFLOW = ROOT / ".github" / "workflows" / "deploy-github-pages.yml"

#: A `<script>` or `<link>` pulling a third-party subresource, captured whole so the attribute
#: order does not matter when looking for `integrity`.
#:
#: Both quote styles and protocol-relative URLs are matched. The first version required double
#: quotes and an explicit `https?:` scheme, so `src='https://cdn…'` and `src="//cdn…"` -- ordinary
#: HTML, and the two forms anyone would reach for next -- walked past a guard whose whole job is
#: to notice exactly that. Reproduced against the old pattern before this was widened.
_EXTERNAL = re.compile(
    r"<(?P<tag>script|link)\b[^>]*?(?:src|href)\s*=\s*(?P<q>[\"'])(?P<url>(?:https?:)?//[^\"']+)(?P=q)[^>]*?>",
    re.I | re.S,
)

#: The `integrity` ATTRIBUTE, not the substring. A plain `"integrity=" in tag` check also
#: accepts `data-was-integrity=` and any other attribute whose name merely ends that way --
#: a mutation renaming the attribute walked straight past the first version of this guard.
_INTEGRITY = re.compile(r"(?<![-\w])integrity\s*=", re.I)

#: `rm -f gitpage/preview.html` and friends, in a `run:` block of the same job.
_REMOVAL = re.compile(r"\brm\b[^\n]*?(?P<path>gitpage/[^\s;&|]+)")


def _build_job() -> dict:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    for job in jobs.values():
        steps = job.get("steps") or []
        if any("upload-pages-artifact" in str(step.get("uses", "")) for step in steps):
            return job
    raise AssertionError("no job in deploy-github-pages.yml uploads a Pages artifact")


def _published_html() -> list[Path]:
    """HTML files that reach the artifact: the uploaded directory minus what the job removes."""

    job = _build_job()
    steps = job["steps"]
    upload = next(s for s in steps if "upload-pages-artifact" in str(s.get("uses", "")))
    uploaded_root = ROOT / str(upload["with"]["path"]).lstrip("./")

    # A removal only counts when it is unconditional and runs BEFORE the upload. Both were
    # reproduced as holes in the first version: a step carrying `if: false` was honoured as a
    # prune, and so was one placed after the artifact had already been uploaded. Any `if:` at all
    # disqualifies the step, because an expression cannot be evaluated here and a conditional
    # removal is not a guarantee -- the safe reading of "maybe removed" is "still published".
    upload_index = steps.index(upload)
    removed: set[Path] = set()
    for index, step in enumerate(steps):
        if index > upload_index or "if" in step:
            continue
        for match in _REMOVAL.finditer(str(step.get("run", ""))):
            removed.add((ROOT / match.group("path")).resolve())

    return [p for p in sorted(uploaded_root.rglob("*.html")) if p.resolve() not in removed]


def test_the_published_set_was_actually_computed() -> None:
    """A guard over an empty set passes for the wrong reason."""

    published = _published_html()
    assert published, "no published HTML was found; the workflow's upload path stopped resolving"
    assert any(p.name == "index.html" for p in published), "index.html is missing from the published set"


@pytest.mark.parametrize("html", _published_html(), ids=lambda p: p.name)
def test_a_published_page_pins_every_third_party_script(html: Path) -> None:
    unpinned = [
        match.group("url")
        for match in _EXTERNAL.finditer(html.read_text(encoding="utf-8", errors="replace"))
        if match.group("tag").lower() == "script" and not _INTEGRITY.search(match.group(0))
    ]

    assert unpinned == [], (
        f"{html.name} is served from the project's Pages origin and loads {unpinned} without an "
        "integrity hash. Whoever controls that response runs arbitrary JavaScript on this origin. "
        "Either pin it by hash like index.html pins React, or keep the file out of the artifact."
    )


def test_the_page_everyone_visits_pins_what_it_loads() -> None:
    """`index.html` is the reason this standard is reachable at all -- pinned so it stays that way."""

    index = ROOT / "gitpage" / "index.html"
    external = list(_EXTERNAL.finditer(index.read_text(encoding="utf-8")))
    scripts = [m for m in external if m.group("tag").lower() == "script"]

    assert scripts, "index.html stopped loading any third-party script; this guard now proves nothing"
    assert all(_INTEGRITY.search(m.group(0)) for m in scripts)
