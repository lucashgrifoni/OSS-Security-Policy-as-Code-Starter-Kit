"""Static checks for the optional GitHub Pages site."""

from __future__ import annotations

import json
from pathlib import Path

_GITPAGE = Path(__file__).parents[2] / "gitpage"


def test_gitpage_uses_committed_tailwind_css_not_runtime_cdn() -> None:
    index = (_GITPAGE / "index.html").read_text(encoding="utf-8")

    assert "cdn.tailwindcss.com" not in index
    assert 'href="site.css"' in index
    assert (_GITPAGE / "tailwind.css").is_file()
    assert (_GITPAGE / "site.css").is_file()
    assert (_GITPAGE / "bundle.js").is_file()


def test_gitpage_tailwind_build_is_pinned_and_repeatable() -> None:
    package = json.loads((_GITPAGE / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((_GITPAGE / "package-lock.json").read_text(encoding="utf-8"))

    assert package["devDependencies"]["tailwindcss"] == "^4.3.0"
    assert package["devDependencies"]["@tailwindcss/cli"] == "^4.3.0"
    assert package["devDependencies"]["esbuild"] == "^0.28.0"
    assert lock["packages"]["node_modules/tailwindcss"]["version"] == "4.3.0"
    assert lock["packages"]["node_modules/@tailwindcss/cli"]["version"] == "4.3.0"
    assert lock["packages"]["node_modules/esbuild"]["version"] == "0.28.0"
    assert "node ./node_modules/@tailwindcss/cli/dist/index.mjs" in package["scripts"]["build:css"]
    assert package["scripts"]["build:js"] == "node build-js.mjs"


def test_gitpage_readme_documents_tailwind_build_boundary() -> None:
    readme = (_GITPAGE / "README.md").read_text(encoding="utf-8")

    assert "npm run build" in readme
    assert "Tailwind is bundled" in readme
    assert "JSX is bundled" in readme
