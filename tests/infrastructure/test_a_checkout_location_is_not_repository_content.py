"""Where the adopter cloned the repository must not change what the scan finds.

The skip-list exists to ignore vendored and generated directories *inside* the repository. It was
applied to the absolute path, so an ancestor directory the adopter happened to name `build`,
`dist`, `venv` or `node_modules` silenced the scan entirely -- and twelve controls then assert,
positively, "No Terraform / OpenTofu sources detected in repository". That is a false statement
about the repository, produced with no attacker involved: any CI that checks out into `build/`
gets an empty IaC scan and a green `--fail-on fail`.

`fs_walk._accept` already does this correctly, testing the skip-list against the path relative to
the repository root, and the other four IaC/K8s scanners route through it. Its own docstring says
it was extracted so every scanner's walker becomes a one-line delegate with identical discovery.
The Terraform walker was the one never converted.

The invariant is metamorphic: the same repository, scanned from two different ancestor paths, must
produce the same findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.iac.scanner import run_scan

_PUBLIC_BUCKET = """resource "aws_s3_bucket_public_access_block" "b" {
  bucket              = "x"
  block_public_acls   = false
  block_public_policy = false
}
"""

#: Ancestor directory names that are in the scanner's own skip-list.
_COLLIDING_ANCESTORS = ["build", "dist", "venv", "node_modules", "target"]


def _repo_with_terraform(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "main.tf").write_text(_PUBLIC_BUCKET, encoding="utf-8")
    return root


@pytest.mark.parametrize("ancestor", _COLLIDING_ANCESTORS)
def test_an_ancestor_directory_name_does_not_silence_the_scan(tmp_path: Path, ancestor: str) -> None:
    plain = _repo_with_terraform(tmp_path / "plain" / "repo")
    nested = _repo_with_terraform(tmp_path / ancestor / "repo")

    from_plain = run_scan(plain)
    from_nested = run_scan(nested)

    assert len(from_plain.files_scanned) == 1, "the control case stopped finding the file; fixture is wrong"
    assert from_plain.findings, "the control case stopped reporting findings; fixture is wrong"

    assert len(from_nested.files_scanned) == len(from_plain.files_scanned), (
        f"a repository checked out under '{ancestor}/' scanned {len(from_nested.files_scanned)} files "
        f"instead of {len(from_plain.files_scanned)}. The checkout location is not repository content."
    )
    assert len(from_nested.findings) == len(from_plain.findings), (
        f"under '{ancestor}/' the scan reported {len(from_nested.findings)} findings instead of "
        f"{len(from_plain.findings)}, so the controls would assert no Terraform exists"
    )


def test_the_skip_list_still_skips_those_directories_inside_the_repository(tmp_path: Path) -> None:
    """The counterpart, without which the fix above could be 'stop skipping anything'."""

    repo = _repo_with_terraform(tmp_path / "repo")
    vendored = repo / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "vendored.tf").write_text(_PUBLIC_BUCKET, encoding="utf-8")

    result = run_scan(repo)

    assert len(result.files_scanned) == 1, "a vendored .tf inside the repository stopped being skipped"
