"""Aggregate parsed HCL files into a resource-type index.

The index is what evaluators actually consume: ``index.resources("aws_s3_bucket")``
returns every block of that type across the repo, with the source file
remembered so findings can carry a precise location.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .hcl_loader import HclLoadError, load_hcl_file


@dataclass(frozen=True)
class TfBlock:
    """One ``resource <type> <name> { ... }`` block plus its origin file."""

    resource_type: str
    name: str
    body: dict[str, Any]
    source_path: Path

    def get(self, key: str, default: Any = None) -> Any:
        """Read a top-level attribute from the block body."""

        return self.body.get(key, default)


@dataclass
class TfResourceIndex:
    """In-memory index of every resource block discovered in a target tree."""

    by_type: dict[str, list[TfBlock]] = field(default_factory=dict)
    files_parsed: list[Path] = field(default_factory=list)
    parse_errors: list[tuple[Path, str]] = field(default_factory=list)
    raw_files: dict[Path, dict[str, Any]] = field(default_factory=dict)

    def resources(self, resource_type: str) -> list[TfBlock]:
        """Return all resources of a given type (empty list when absent)."""

        return list(self.by_type.get(resource_type, ()))

    def types_matching(self, prefix: str) -> Iterator[str]:
        """Yield every resource type starting with ``prefix`` (e.g. ``aws_``)."""

        for rt in self.by_type:
            if rt.startswith(prefix):
                yield rt

    def all_blocks(self) -> Iterator[TfBlock]:
        """Iterate over every block regardless of resource type."""

        for blocks in self.by_type.values():
            yield from blocks


def _blocks_from_resource_entry(entry: Any, source_path: Path) -> Iterator[TfBlock]:
    """Yield :class:`TfBlock`s from one ``resource`` entry dict (``{type: {name: body}}``)."""

    if not isinstance(entry, dict):
        return
    for resource_type, names in entry.items():
        if not isinstance(names, dict):
            continue
        for name, body in names.items():
            if isinstance(body, dict):
                yield TfBlock(resource_type=resource_type, name=name, body=body, source_path=source_path)


def _iter_resource_blocks(
    parsed: dict[str, Any],
    source_path: Path,
) -> Iterator[TfBlock]:
    """Walk the ``resource`` list emitted by hcl2 and produce :class:`TfBlock`s."""

    raw_resources = parsed.get("resource") or []
    if not isinstance(raw_resources, list):
        return
    for entry in raw_resources:
        yield from _blocks_from_resource_entry(entry, source_path)


def build_index(files: Iterable[Path]) -> TfResourceIndex:
    """Parse every path and build a :class:`TfResourceIndex` from the results.

    Files that fail to parse are recorded in ``parse_errors`` (so callers can
    write ``manual-review-required`` evidence) but never raise — the goal is
    to be best-effort like a real CSPM tool, not crash on a single bad file.
    """

    index = TfResourceIndex()
    for path in files:
        try:
            parsed = load_hcl_file(path)
        except HclLoadError as exc:
            index.parse_errors.append((path, str(exc.original)))
            continue
        index.files_parsed.append(path)
        index.raw_files[path] = parsed
        for block in _iter_resource_blocks(parsed, path):
            index.by_type.setdefault(block.resource_type, []).append(block)
    return index
