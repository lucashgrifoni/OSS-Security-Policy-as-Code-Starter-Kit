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
passed standalone at 0.57s and then FAILED the real gate at 5.27s, because the gate leg runs
under `--cov`, and coverage tracing costs about 9x on a loop this size. A budget therefore pins
how fast the runner is and whether instrumentation is on -- not the complexity class the test is
named after. Timing the same code at N and at kN cancels both: every constant factor multiplies
the two measurements equally, and only the exponent survives.

WHY THE GROWTH IS 4x AND NOT 2x, AND WHY THAT IS NOT A LOOSENED THRESHOLD. Doubling was the
first design and it produced a false red on 2026-09-12: `Quality (ubuntu, Python 3.13)` read
3.03 against a threshold of 3.0. The tempting repair is to raise 3.0. It does not work, because
at 2x the two distributions overlap. Measured on the correct implementation and on the quadratic
one it exists to catch, with no coverage -- which is the condition that broke, since the two
non-gate legs run `pytest tests -q` with no `--cov` and are therefore about nine times faster,
which makes the same scheduler noise about nine times larger relative to the reading:

    growth   form         min     median    max
    2x       linear       1.96      2.01    3.25     <- clears 3.0 on its own
    2x       quadratic    3.57      3.60    3.71
    4x       linear       3.86      4.22    4.61
    4x       quadratic   15.38     15.86   16.22

At 2x there is no threshold at all: 3.25 and 3.57 leave 10% between them. At 4x the gap is 3.3x
and 8.0 sits near its geometric middle, 1.7x above the worst correct reading and 1.9x below the
best broken one. The number moved because the measurement changed, not to make a red test green.

WHY THE MINIMUM OF THREE AND NOT ONE READING. Scheduler noise is one-sided -- time is taken away
and never given back -- so the minimum of a few samples estimates the cost and the mean does not.
It narrowed the spread of the correct implementation from 1.19x to 1.10x.

WHY `perf_counter` AND NOT `process_time`, WHICH WOULD EXCLUDE THAT NOISE AT THE SOURCE. It was
tried, and it is worse: spread 1.56x against 1.10x, with one reading at 6.50. The reason is in
the clock, not the code. `get_clock_info` advertises a resolution of 0.000 ms and the advertised
figure is not the real one; the small side costs 62 ms, which is four ticks of the ~15.6 ms
Windows actually quantises to. Four ticks cannot carry a ratio.

WHAT IT COSTS, SO THE NEXT PERSON DOES NOT HAVE TO FIND OUT. 1.93s on a leg with no coverage,
stable across five consecutive runs, and 20.2s on the gate leg where coverage multiplies the
walk -- about 15s more than the single-reading version it replaces, or 3% of that job. A broken
implementation fails in 36s with one dedup reverted and 69s with both. That is the price of
three readings at 4x, and it buys a guard that stops reporting the runner's mood as a defect.

WHY 12,500 AND NOT THE 25,000 THIS USED TO WALK. Both bases separate equally well -- 25,000 puts
the quadratic floor at 16.64 against 15.38 here -- but the broken form has to walk 4x the base,
and quadratic work at 100,000 locations takes 96s to fail where 50,000 takes 18s. A guard that
needs a minute and a half to say something is wrong is the failure mode recorded in the note
about a guard that hangs. Halving the base keeps the margin and returns the verdict five times
sooner.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from oss_policy_kit.application.finding_sarif import _dropped_locations_in_drop

#: Distinct affected files named by one result, at the smaller of the two sizes.
#:
#: Calibrated against removing only the CHEAPER of the two dedups, not both: the test has to fail
#: on either alone. Large enough that the linear cost is far above timer noise even on a leg with
#: no coverage, small enough that the broken form fails in about 18s rather than 96s.
_LOCATIONS = 12_500

#: Growing the input 4x grows linear work 4x and quadratic work 16x. Chosen over 2x because at 2x
#: the correct implementation's own spread reaches 3.25 and the quadratic floor is 3.57, which
#: leaves no room for any threshold. See the module docstring for both distributions.
_GROWTH = 4

#: Scheduler noise only ever adds time, so the smallest of a few readings is the estimate.
_SAMPLES = 3

#: Between the measured 4.61 worst case of the correct implementation and the measured 15.38 best
#: case of the quadratic one: 1.7x of headroom above, 1.9x below.
_MAX_GROWTH_RATIO = 8.0


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


def _cheapest_walk(path: Path) -> float:
    """The smallest of `_SAMPLES` readings, because the noise only ever adds."""

    return min(_seconds_to_walk(path) for _ in range(_SAMPLES))


def test_growing_the_dropped_locations_does_not_grow_the_work_quadratically(tmp_path: Path) -> None:
    small = _drop_naming_many_files(tmp_path / "small", _LOCATIONS)
    large = _drop_naming_many_files(tmp_path / "large", _LOCATIONS * _GROWTH)
    assert large.stat().st_size < 20 * 1024 * 1024, "both drops must stay inside the cap, or the cap is the guard"

    _seconds_to_walk(small)  # warm-up: the first walk pays one-off costs the comparison must not carry
    at_n = _cheapest_walk(small)
    at_kn = _cheapest_walk(large)

    ratio = at_kn / at_n
    assert ratio < _MAX_GROWTH_RATIO, (
        f"growing {_LOCATIONS} dropped locations {_GROWTH}x multiplied the work by {ratio:.2f}x "
        f"({at_n:.3f}s -> {at_kn:.3f}s). Linear growth is ~{_GROWTH}x and a list scan per location "
        f"is ~{_GROWTH**2}x, measured at 15.4x; these drops are inside the size cap so nothing "
        "else refuses them."
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
