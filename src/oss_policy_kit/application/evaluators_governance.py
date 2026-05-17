"""Governance-category evaluators (refactor step 2 of ``evaluators.py`` decomposition).

This module is the **public package boundary** for governance controls
(``GOV-*``, ``REL-CHANGE-012``, ``GOV-DISC-013``, ``GOV-WAIV-014``,
``GOV-EVIDFRESH-054``). The evaluator function bodies still live in
``evaluators.py`` so that ``EVALUATOR_REGISTRY`` remains
**byte-equivalent** across the v5.6 -> v5.7 transition; this module
re-exports the existing callables under their canonical names and exposes
:func:`build_governance_evaluators` for the registry loader.

Future steps (tracked for v5.8.x) will move the function bodies into this
module incrementally so each move can be validated against the
byte-equivalence guarantee in isolation. Until then, this module is the
import surface that external code should target when it cares about the
governance pack as a unit.

The list of governance control IDs is **closed** here so that adding new
governance controls in the future requires touching this module — a small
nudge against silently growing the megafile.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oss_policy_kit.domain.models import EvalOutcome

#: Stable, alphabetized list of every control ID that belongs to the
#: governance category. The v5.7.0 registry loader uses this set to
#: discover which evaluators it should re-register through this shim.
GOVERNANCE_CONTROL_IDS: tuple[str, ...] = (
    "GOV-SEC-001",
    "GOV-CON-002",
    "GOV-COWN-003",
    "GOV-LIC-004",
    "GOV-DISC-013",
    "GOV-WAIV-014",
    "GOV-EVIDFRESH-054",
    "GOV-DISC-065",
    "REL-CHANGE-012",
)


def build_governance_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every governance control.

    Pulled from :mod:`oss_policy_kit.application.evaluators` so that
    :data:`EVALUATOR_REGISTRY` keeps pointing at the same function objects
    as in v5.6 (byte-equivalence guarantee). Future v5.8 work will move
    the bodies into this module without changing this public function's
    contract.
    """

    from oss_policy_kit.application import evaluators as _e

    return {
        "GOV-SEC-001": _e.eval_gov_sec_001,
        "GOV-CON-002": _e.eval_gov_con_002,
        "GOV-COWN-003": _e.eval_gov_cown_003,
        "GOV-LIC-004": _e.eval_gov_lic_004,
        "GOV-DISC-013": _e.eval_gov_disc_013,
        "GOV-WAIV-014": _e.eval_gov_waiv_014,
        "GOV-EVIDFRESH-054": _e.eval_gov_evidfresh_054,
        "GOV-DISC-065": _e.eval_gov_disc_065,
        "REL-CHANGE-012": _e.eval_rel_change_012,
    }
