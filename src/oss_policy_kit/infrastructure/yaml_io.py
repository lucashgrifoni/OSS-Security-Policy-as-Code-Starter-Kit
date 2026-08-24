"""Safe YAML loading."""

from pathlib import Path
from typing import Any, cast

import yaml

from oss_policy_kit.application.input_limits import overexpanded_reason
from oss_policy_kit.infrastructure.source_text import decode_source


def load_yaml_file(path: Path) -> Any:
    """Load YAML using safe_load only, refusing a document that expands past the node limit.

    This is the funnel every CI parser reads an untrusted repository through, which is why the
    expansion guard belongs here rather than at each walker: several of those walkers return
    lists, so making them skip repeated nodes would silently change what they count, while
    refusing the document changes nothing about how an honest file is read.

    ``yaml.YAMLError`` is raised deliberately rather than a new exception type. Every call site
    already handles a parse failure, and ``BAD_INPUT_ERRORS`` already lists it, so the refusal
    arrives at the existing "this file could not be read" path -- which, per ADR-045, is
    reported as evidence the kit could not read, not as a verdict about the repository.
    """

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
