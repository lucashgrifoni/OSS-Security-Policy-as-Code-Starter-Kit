"""Parse ``git`` remote URLs for evidence collection."""

from __future__ import annotations

import re
from pathlib import Path

from oss_policy_kit.application.input_limits import MAX_CI_CONFIG_BYTES, oversize_reason


def read_github_repo_slug_from_git_config(repo_root: Path) -> str | None:
    """Return ``owner/repo`` from ``origin`` when it points to github.com, else ``None``."""

    cfg = repo_root / ".git" / "config"
    if not cfg.is_file():
        return None
    if oversize_reason(cfg, MAX_CI_CONFIG_BYTES, label="git config") is not None:
        return None
    text = cfg.read_text(encoding="utf-8", errors="replace")
    return _parse_origin_github_slug(text)


def _parse_origin_github_slug(config_text: str) -> str | None:
    """Extract ``owner/repo`` from ``.git/config`` text for ``origin``."""

    lines = config_text.splitlines()
    in_origin = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_origin = line.lower() == '[remote "origin"]'
            continue
        if not in_origin:
            continue
        if not line.lower().startswith("url"):
            continue
        m = re.match(r"url\s*=\s*(.+)", line, flags=re.IGNORECASE)
        if not m:
            continue
        url = m.group(1).strip().strip('"')
        slug = _github_slug_from_url(url)
        if slug:
            return slug
    return None


def _github_slug_from_url(url: str) -> str | None:
    u = url.strip()
    if u.startswith("git@github.com:"):
        path = u.removeprefix("git@github.com:").removesuffix(".git")
        return path if "/" in path else None
    u = u.replace("ssh://git@github.com/", "https://github.com/")
    if u.startswith(("https://github.com/", "http://github.com/")):
        path = u.split("github.com/", 1)[-1].split("?", 1)[0].removesuffix(".git").strip("/")
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    return None
