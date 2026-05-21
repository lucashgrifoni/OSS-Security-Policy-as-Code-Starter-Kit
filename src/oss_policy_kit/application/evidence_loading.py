"""Centralized loader for bundled evidence JSON schemas.

Extracted from ``evaluators.py`` (M7) to remove the ~19x duplicated
``importlib.resources.files(...).joinpath(...).read_bytes()`` + ``json.loads``
boilerplate that every ``_*_schema()`` helper repeated.

Behavior is identical to the previous inline pattern: the schema is read from
the ``oss_policy_kit.data.schema`` package and a *fresh* ``dict`` is returned on
every call (no caching), so existing callers that may mutate the result keep the
same semantics.
"""

from __future__ import annotations

import importlib.resources as ir
import json
from typing import Any, cast

_SCHEMA_PACKAGE = "oss_policy_kit.data.schema"


def load_evidence_schema(schema_filename: str) -> dict[str, Any]:
    """Load a bundled evidence JSON schema by file name.

    Args:
        schema_filename: e.g. ``"evidence-branch-protection.schema.json"``.

    Returns:
        The parsed schema as a new ``dict`` on each call.
    """

    raw = ir.files(_SCHEMA_PACKAGE).joinpath(schema_filename).read_bytes()
    return cast(dict[str, Any], json.loads(raw))
