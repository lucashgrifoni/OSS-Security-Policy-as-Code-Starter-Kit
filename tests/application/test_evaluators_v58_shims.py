"""Tests for the v5.8.0 evaluator pack shims (refactor steps F2-01..F2-05).

These five modules are public package boundaries for the CI/CD,
platform, release, vulnerability-management, and SAST control packs.
Like ``evaluators_governance.py`` and ``evaluators_supply_chain.py``,
they re-export the existing callables from ``evaluators.py`` so
``EVALUATOR_REGISTRY`` stays **byte-equivalent** across the v5.7 -> v5.8
transition. Future v5.8.x work will move the function bodies into these
modules.

The tests below pin three invariants:

1. Every control ID listed in each pack's ``*_CONTROL_IDS`` tuple has an
   entry in ``EVALUATOR_REGISTRY``.
2. Each shim's ``build_*_evaluators()`` returns the **same function
   objects** as ``EVALUATOR_REGISTRY`` (byte-equivalence guarantee).
3. The five v5.8.0 packs plus the two v5.7.0 packs partition the
   in-evaluators-py control IDs without overlap (excluding the
   intentional ``CONT-SIGN-001`` cross-bucket case already documented in
   ``evaluators_supply_chain``).
"""

from __future__ import annotations

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_ci_cd import (
    CI_CD_CONTROL_IDS,
    build_ci_cd_evaluators,
)
from oss_policy_kit.application.evaluators_governance import (
    GOVERNANCE_CONTROL_IDS,
)
from oss_policy_kit.application.evaluators_platform import (
    PLATFORM_CONTROL_IDS,
    build_platform_evaluators,
)
from oss_policy_kit.application.evaluators_release import (
    RELEASE_CONTROL_IDS,
    build_release_evaluators,
)
from oss_policy_kit.application.evaluators_sast import (
    SAST_CONTROL_IDS,
    build_sast_evaluators,
)
from oss_policy_kit.application.evaluators_supply_chain import (
    SUPPLY_CHAIN_CONTROL_IDS,
)
from oss_policy_kit.application.evaluators_vuln_management import (
    VULN_MANAGEMENT_CONTROL_IDS,
    build_vuln_management_evaluators,
)

_NEW_PACKS: tuple[tuple[str, tuple[str, ...], object], ...] = (
    ("ci_cd", CI_CD_CONTROL_IDS, build_ci_cd_evaluators),
    ("platform", PLATFORM_CONTROL_IDS, build_platform_evaluators),
    ("release", RELEASE_CONTROL_IDS, build_release_evaluators),
    ("vuln_management", VULN_MANAGEMENT_CONTROL_IDS, build_vuln_management_evaluators),
    ("sast", SAST_CONTROL_IDS, build_sast_evaluators),
)


@pytest.mark.parametrize("pack_name,control_ids,_builder", _NEW_PACKS, ids=lambda x: x if isinstance(x, str) else "")
def test_every_control_in_pack_has_registry_entry(
    pack_name: str, control_ids: tuple[str, ...], _builder: object
) -> None:
    """Each control listed by a pack must be registered in EVALUATOR_REGISTRY."""

    missing = [cid for cid in control_ids if cid not in EVALUATOR_REGISTRY]
    assert not missing, f"{pack_name}: EVALUATOR_REGISTRY missing controls {missing}"


@pytest.mark.parametrize("pack_name,_control_ids,builder", _NEW_PACKS, ids=lambda x: x if isinstance(x, str) else "")
def test_shim_returns_identical_callables(pack_name: str, _control_ids: tuple[str, ...], builder: object) -> None:
    """Byte-equivalence: shim must return the same function object the registry uses."""

    built = builder()  # type: ignore[operator]
    for cid, fn in built.items():
        assert EVALUATOR_REGISTRY[cid] is fn, (
            f"{pack_name} shim returned a different callable for {cid} than EVALUATOR_REGISTRY. "
            "Byte-equivalence guarantee broken."
        )


def test_v58_packs_are_pairwise_disjoint() -> None:
    """The five v5.8.0 packs must not overlap each other."""

    packs = {name: set(ids) for name, ids, _ in _NEW_PACKS}
    items = list(packs.items())
    for i, (a_name, a_ids) in enumerate(items):
        for b_name, b_ids in items[i + 1 :]:
            overlap = a_ids & b_ids
            assert not overlap, f"Packs {a_name!r} and {b_name!r} overlap on {sorted(overlap)}"


def test_v58_packs_are_disjoint_from_v57_packs() -> None:
    """The five v5.8.0 packs must not overlap with governance / supply-chain v5.7.0 packs."""

    v58_ids: set[str] = set()
    for _, ids, _ in _NEW_PACKS:
        v58_ids.update(ids)
    overlap_gov = v58_ids & set(GOVERNANCE_CONTROL_IDS)
    assert not overlap_gov, f"v5.8 packs overlap governance: {sorted(overlap_gov)}"
    overlap_sc = v58_ids & set(SUPPLY_CHAIN_CONTROL_IDS)
    assert not overlap_sc, f"v5.8 packs overlap supply-chain: {sorted(overlap_sc)}"
