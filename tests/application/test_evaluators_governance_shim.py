"""Tests for the v5.7.0 governance / supply-chain evaluator pack shims (refactor steps 2 & 3).

These modules are the public package boundary for the governance and
supply-chain control packs. They re-export the existing callables from
``evaluators.py`` so ``EVALUATOR_REGISTRY`` stays **byte-equivalent**
across the v5.6 -> v5.7 transition. Future v5.8 work will move the
function bodies into these modules.

The tests below pin two invariants:

1. Every control ID listed in ``GOVERNANCE_CONTROL_IDS`` /
   ``SUPPLY_CHAIN_CONTROL_IDS`` has an entry in ``EVALUATOR_REGISTRY``.
2. The shim's ``build_*_evaluators()`` returns the **same function
   objects** as ``EVALUATOR_REGISTRY`` — byte-equivalence guarantee.
"""

from __future__ import annotations

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_governance import (
    GOVERNANCE_CONTROL_IDS,
    build_governance_evaluators,
)
from oss_policy_kit.application.evaluators_supply_chain import (
    SUPPLY_CHAIN_CONTROL_IDS,
    build_supply_chain_evaluators,
)


def test_every_governance_control_has_registry_entry() -> None:
    for cid in GOVERNANCE_CONTROL_IDS:
        assert cid in EVALUATOR_REGISTRY, f"EVALUATOR_REGISTRY missing governance control {cid}."


def test_every_supply_chain_control_has_registry_entry() -> None:
    for cid in SUPPLY_CHAIN_CONTROL_IDS:
        assert cid in EVALUATOR_REGISTRY, f"EVALUATOR_REGISTRY missing supply-chain control {cid}."


def test_governance_shim_returns_identical_callables() -> None:
    """Byte-equivalence: shim must return the *same* function object the registry uses."""

    built = build_governance_evaluators()
    for cid, fn in built.items():
        assert EVALUATOR_REGISTRY[cid] is fn, (
            f"Governance shim returned a different callable for {cid} than EVALUATOR_REGISTRY. "
            "Byte-equivalence guarantee broken."
        )


def test_supply_chain_shim_returns_identical_callables() -> None:
    built = build_supply_chain_evaluators()
    for cid, fn in built.items():
        assert EVALUATOR_REGISTRY[cid] is fn, (
            f"Supply-chain shim returned a different callable for {cid} than EVALUATOR_REGISTRY. "
            "Byte-equivalence guarantee broken."
        )


def test_governance_and_supply_chain_packs_are_disjoint() -> None:
    """No control should appear in both governance and supply-chain packs."""

    overlap = set(GOVERNANCE_CONTROL_IDS) & set(SUPPLY_CHAIN_CONTROL_IDS)
    assert not overlap, f"Packs overlap: {sorted(overlap)}; pick one canonical home per control."
