"""Safe YAML loading."""

from pathlib import Path
from typing import Any, cast

import yaml

from oss_policy_kit.application.input_limits import (
    MAX_CI_CONFIG_BYTES,
    overexpanded_reason,
    oversize_reason,
)
from oss_policy_kit.infrastructure.source_text import decode_source


def load_yaml_file(path: Path, *, max_bytes: int = MAX_CI_CONFIG_BYTES) -> Any:
    """Load YAML using safe_load only, refusing a document too large or too expanded to read.

    This is the funnel every CI parser reads an untrusted repository through, which is why the
    expansion guard belongs here rather than at each walker: several of those walkers return
    lists, so making them skip repeated nodes would silently change what they count, while
    refusing the document changes nothing about how an honest file is read.

    ``yaml.YAMLError`` is raised deliberately rather than a new exception type. Every call site
    already handles a parse failure, and ``BAD_INPUT_ERRORS`` already lists it, so the refusal
    arrives at the existing "this file could not be read" path -- which, per ADR-045, is
    reported as evidence the kit could not read, not as a verdict about the repository.
    """

    # Size is checked before the read, not after: the expansion guard below runs on a parsed
    # document, so it can only refuse a file the process has already paid to read and parse.
    # Both guards are needed -- one bounds a small file that expands, the other a file that is
    # simply large -- and only this one is reached before any of the cost is spent.
    #
    # ``max_bytes`` because one caller reads a different kind of file: a Scorecard document is
    # evidence, not CI config, and its own boundary already admits five times as much.
    # Defaulting to the CI ceiling would have narrowed a contract that is not at fault here.
    reason = oversize_reason(path, max_bytes, label=f"YAML file '{path.name}'")
    if reason is not None:
        raise yaml.YAMLError(reason)

    # `decode_source` rather than a UTF-8 read: YAML 1.2 requires a processor to accept UTF-8,
    # UTF-16 and UTF-32, and GitHub Actions and GitLab CI run such files. Reading them as UTF-8
    # produced mojibake, the mojibake failed to parse, and the pipeline was recorded as broken --
    # so a mutable `python:latest` image or an unpinned action inside it was never seen. The
    # helper honours a BOM and otherwise falls back to exactly the previous read, so nothing
    # reads worse than it did before.
    text = decode_source(path.read_bytes())
    doc = cast(Any, yaml.safe_load(text))
    reason = overexpanded_reason(doc, label=f"YAML file '{path.name}'")
    if reason is not None:
        raise yaml.YAMLError(reason)
    return doc
