"""Create a commit through the GitHub API, which signs it, instead of `git commit`.

A runner has no signing key, so a commit made with `git commit` on one is unsigned. The
`Default Master` ruleset requires signatures, so such a commit blocks its own pull request and
every release merge has needed the owner's admin bypass to get past it. Measured on the 10.0.23
release branch, where the two commits differ only in how they were made:

    736a4b89d  verified=true   chore(master): release 10.0.23      <- release-please, via the API
    0f75a716b  verified=false  chore(release): regenerate the ...  <- this job, via git commit

Same App token, same branch, same workflow run. GitHub signs a commit created through the Git
Data API by a GitHub App, so routing the write through the API is the whole fix.

The four calls go through `gh`, not through a hand-written HTTP client. See `_call` for why.

The script builds the commit from the working-tree status restricted to one path prefix, which
keeps the blast radius the same as the `git add <prefix>` it replaces: a file outside the
prefix cannot enter the commit even if the regeneration touched it, and a file git has never
seen still can, which reading the diff instead would have quietly dropped.

It then reads the commit back and fails if GitHub did not sign it. Without that check this
would silently return to pushing unsigned commits the day anything upstream changes, and the
symptom would again be a blocked release rather than a failed job.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast


def changed_paths(repo: Path, prefix: str) -> list[tuple[str, str]]:
    """`(status, path)` for every working-tree change under *prefix*.

    `git status` rather than `git diff`, because a regenerated sample set can add a file that
    did not exist before and `git diff` does not report untracked paths. The code this replaced
    ran `git add <prefix>`, which did stage them, so reading only the diff here would have
    dropped a new report from the commit without saying so.

    Status is narrowed to what the tree payload needs: `D` for a path to remove, `M` for a path
    to write. `-z` keeps paths with spaces or non-ASCII bytes intact, which `--porcelain`
    otherwise quotes and escapes.
    """

    out = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", prefix],
        cwd=repo,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    fields = [field for field in out.split("\0") if field]
    rows: list[tuple[str, str]] = []
    skip_next = False
    for field in fields:
        if skip_next:  # the source path of a rename or copy, which the new path already covers
            skip_next = False
            continue
        if len(field) < 4:
            continue
        index_status, worktree_status, path = field[0], field[1], field[3:]
        if index_status in {"R", "C"}:
            skip_next = True
        deleted = "D" in {index_status, worktree_status}
        rows.append(("D" if deleted else "M", path))
    return rows


def tree_entries(
    repo: Path, changes: list[tuple[str, str]], blob_for: Callable[[bytes], str]
) -> list[dict[str, object]]:
    """The `tree` payload for the API, one entry per change.

    A deletion is `sha: None`, which is how the API is told to remove a path from the base
    tree. Anything else carries a blob sha produced by *blob_for*, which is passed in so the
    shape of this function can be tested without a network.

    Every entry is mode `100644`. That is an assumption about one prefix rather than a general
    truth: the five tracked files under `docs/sample-reports/` are all `100644` today, and the
    job that calls this only ever regenerates reports. An executable or a symlink arriving under
    that prefix would be written back as a plain file.
    """

    entries: list[dict[str, object]] = []
    for status, path in changes:
        if status == "D":
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            continue
        content = (repo / path).read_bytes()
        entries.append(
            {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "sha": blob_for(content),
            }
        )
    return entries


def gh_argv(method: str, path: str, *, has_body: bool) -> list[str]:
    """The argv for one `gh api` call, split out so a test can read it without a network.

    The body goes in on stdin rather than as arguments: `gh`'s own field flags coerce types and
    split values on `=`, which is not something a report's bytes should be subjected to.
    """

    argv = [
        "gh",
        "api",
        "--method",
        method,
        path,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        "X-GitHub-Api-Version: 2022-11-28",
    ]
    if has_body:
        argv.extend(["--input", "-"])
    return argv


def _call(method: str, path: str, payload: dict[str, object] | None = None) -> dict[str, Any]:
    """One GitHub API call, made by `gh`.

    Not `urllib`. Writing the request by hand meant assembling a URL out of this script's own
    arguments and building the Authorization header here, which both scanners in this project's
    Security CI read as a request sink fed by command-line input, and which nothing else in this
    repository does. `gh` ships on every GitHub-hosted runner, already talks to GitHub for
    `publish-pypi.yml` and `release.yml`, resolves the host itself and reads the token from the
    environment, so no URL and no credential are assembled in this file at all.
    """

    proc = subprocess.run(  # noqa: S603 - argv is a list of strings and shell is False
        gh_argv(method, path, has_body=payload is not None),
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        check=False,
        shell=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:400]
        raise SystemExit(f"{method} {path} failed: gh exit {proc.returncode} {detail}")
    return cast("dict[str, Any]", json.loads(proc.stdout or "{}"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--branch", required=True)
    parser.add_argument("--prefix", required=True, help="only paths under this prefix are committed")
    parser.add_argument("--message", required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    # `gh` reads GH_TOKEN before GITHUB_TOKEN, and this project's workflows already pass it
    # under that name. Checked here rather than left to `gh` so the failure names the App token
    # the signature depends on, instead of reporting a generic authentication problem.
    if not os.environ.get("GH_TOKEN", ""):
        raise SystemExit("GH_TOKEN is not set; the commit must be made by the App to be signed.")

    changes = changed_paths(args.root, args.prefix)
    if not changes:
        print(f"Nothing changed under {args.prefix}; nothing to commit.")
        return 0

    ref = _call("GET", f"/repos/{args.repo}/git/ref/heads/{args.branch}")
    parent = ref["object"]["sha"]
    base_tree = _call("GET", f"/repos/{args.repo}/git/commits/{parent}")["tree"]["sha"]

    def blob_for(content: bytes) -> str:
        created = _call(
            "POST",
            f"/repos/{args.repo}/git/blobs",
            {"content": base64.b64encode(content).decode("ascii"), "encoding": "base64"},
        )
        return str(created["sha"])

    tree = _call(
        "POST",
        f"/repos/{args.repo}/git/trees",
        {"base_tree": base_tree, "tree": tree_entries(args.root, changes, blob_for)},
    )
    commit = _call(
        "POST",
        f"/repos/{args.repo}/git/commits",
        {"message": args.message, "tree": tree["sha"], "parents": [parent]},
    )
    _call(
        "PATCH",
        f"/repos/{args.repo}/git/refs/heads/{args.branch}",
        {"sha": commit["sha"], "force": False},
    )

    verification = _call("GET", f"/repos/{args.repo}/commits/{commit['sha']}")["commit"]["verification"]
    print(f"Committed {len(changes)} path(s) under {args.prefix} as {commit['sha'][:12]}")
    if not verification.get("verified"):
        raise SystemExit(
            f"the API returned an UNSIGNED commit (reason: {verification.get('reason')}). "
            "This job exists to stop producing those; the required_signatures rule will block "
            "the release pull request until it is resolved."
        )
    print("Signed by GitHub, so the release pull request needs no bypass.")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main() in tests
    sys.exit(main())
