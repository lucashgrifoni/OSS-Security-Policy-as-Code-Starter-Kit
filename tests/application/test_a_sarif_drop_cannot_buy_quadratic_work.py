"""Deduplicating dropped SARIF locations is linear in their count, not quadratic.

`sarif_partial_location_warnings` names the affected files a finding cannot carry, so that a
`results[]` entry pointing at three files does not silently publish one. It collected them with

    if uri not in dropped:
        dropped.append(uri)

which rescans a growing list for every location -- and the same pattern appeared a second time,
one frame down, in `_extra_location_uris`. A scanner reporting one rule across a monorepo
produces exactly that shape, and the drop stays comfortably inside the 20 MiB cap the kit already
enforces, so nothing refuses the file. It just takes minutes.

Measured before the fix, on a 3.84 MiB drop naming 50,000 distinct files:

    _dropped_locations_in_drop   19.16s
    correlate-findings (CLI)      7.39s on a 2.45 MiB drop, and 10.26s on this one

After: 0.26s, 1.19s and 1.34s.

WHY THIS MEASURES A RATIO AND NOT A CLOCK. The first version asserted a wall-clock budget. It
passed standalone at 0.57s and then FAILED the real gate at 5.27s, because the suite runs under
`--cov`, and coverage tracing costs about 9x on a loop this size. A budget therefore pins how
fast the runner is and whether instrumentation is on -- not the complexity class the test is
named after. Timing the same code at N and at 2N cancels both: every constant factor multiplies
the two measurements equally, and only the exponent survives.

    implementation   N=25,000     2N        ratio
    linear            0.120s     0.253s     2.11x
    one quadratic     1.318s     5.477s     4.15x
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from oss_policy_kit.application.finding_sarif import _dropped_locations_in_drop

#: Distinct affected files named by one result, at the smaller of the two sizes.
#:
#: Calibrated against removing only the CHEAPER of the two dedups, not both: the test has to fail
#: on either alone. Large enough that the linear cost is far above timer noise even before
#: coverage inflates it, small enough that the pair costs about a second in a normal run.
_LOCATIONS = 25_000

#: Doubling the input doubles linear work and quadruples quadratic work. 3.0 sits between the two
#: measured ratios with roughly 40% of headroom on each side.
_MAX_DOUBLING_RATIO = 3.0


def _drop_naming_many_files(directory: Path, count: int) -> Path:
    locations = [{"physicalLocation": {"artifactLocation": {"uri": f"src/pkg{i}/mod{i}.py"}}} for i in range(count)]
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "zizmor"}},
                "results": [{"ruleId": "R1", "level": "error", "message": {"text": "x"}, "locations": locations}],
            }
        ],
    }
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "zizmor.sarif.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _seconds_to_walk(path: Path) -> float:
    started = time.perf_counter()
    _dropped_locations_in_drop(path, "zizmor.sarif.json")
    return time.perf_counter() - started


def test_doubling_the_dropped_locations_does_not_quadruple_the_work(tmp_path: Path) -> None:
    small = _drop_naming_many_files(tmp_path / "small", _LOCATIONS)
    large = _drop_naming_many_files(tmp_path / "large", _LOCATIONS * 2)
    assert large.stat().st_size < 20 * 1024 * 1024, "both drops must stay inside the cap, or the cap is the guard"

    _seconds_to_walk(small)  # warm-up: the first walk pays one-off costs the comparison must not carry
    at_n = _seconds_to_walk(small)
    at_2n = _seconds_to_walk(large)

    ratio = at_2n / at_n
    assert ratio < _MAX_DOUBLING_RATIO, (
        f"doubling {_LOCATIONS} dropped locations multiplied the work by {ratio:.2f}x "
        f"({at_n:.3f}s -> {at_2n:.3f}s). Linear growth is ~2x; ~4x is a list scan per location, "
        "and these drops are inside the size cap so nothing else refuses them."
    )


def test_the_dedup_still_dedupes_and_keeps_document_order(tmp_path: Path) -> None:
    """The counterpart: a faster dedup that dedupes differently is a different bug.

    Order is part of the contract -- the warning names the first ten and counts the rest, so a
    set alone would make which ten an adopter sees depend on hashing.
    """

    locations = [
        {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        for uri in ("a.py", "b.py", "a.py", "c.py", "b.py", "d.py")
    ]
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "zizmor"}},
                "results": [{"ruleId": "R1", "level": "error", "message": {"text": "x"}, "locations": locations}],
            }
        ],
    }
    path = tmp_path / "zizmor.sarif.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    # locations[0] is "a.py" and is the primary; the extras are b, a, c, b, d -> b, a, c, d.
    assert _dropped_locations_in_drop(path, "zizmor.sarif.json") == ["b.py", "a.py", "c.py", "d.py"]
