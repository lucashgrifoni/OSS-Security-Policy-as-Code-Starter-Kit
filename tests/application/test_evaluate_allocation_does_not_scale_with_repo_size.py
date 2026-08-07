"""The evaluator probes for signals; it must never grow memory with the target's size.

Measured on the published 10.0.8 wheel, peak allocation for one ``evaluate`` was
~2.7 MiB against the bundled example repo and ~2.6 MiB against a 2051-file synthetic
repo -- flat, because the evaluators open the specific files a control asks about
rather than walking and holding the tree. That flatness is what lets a CI gate run
against a monorepo for the same cost as against a toy repo, and nothing in the suite
pinned it.

The regression this catches is a plausible one-line mistake: an evaluator that reaches
for ``list(root.rglob("*"))``, ``read_text()`` over every match, or any accumulator
keyed by file, turns a bounded probe into a load of the whole repository. Functional
tests stay green through that change -- the verdicts do not move -- so only an
allocation assertion sees it.

On test shape: this measures *allocation* via ``tracemalloc``, not wall time. Wall
time on a shared CI runner is noisy enough that a threshold either flakes or is so
loose it catches nothing; allocation under a fixed workload is stable across runners.

The assertion is on the *delta* between two targets, compared against the number of
bytes the larger target actually holds -- not on a ratio. A ratio was tried first and
was decorative: baseline allocation for one ``evaluate`` is ~2.7 MiB of catalog and
profile parsing, so a mutation that read every ``*.py`` in a 1200-file repo added only
~540 KiB and stayed under any ratio ceiling loose enough not to flake. Comparing the
delta to the repo's own size states the real invariant -- *the evaluator must not
allocate on the order of the target's content* -- and it fails on exactly the mutation
the ratio missed.
"""

from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

# Files in the synthetic "large" repo, and the payload each carries. 600 x 8 KiB is
# ~4.8 MiB of content: far above measurement noise, so holding the tree is unmistakable,
# and small enough that writing it keeps the test under a few seconds.
_LARGE_REPO_FILES = 600
_PAYLOAD_BYTES = 8 * 1024

# An evaluator that held the target would allocate roughly the target's whole size.
# Fail once the delta reaches half of it -- comfortably above the noise floor of two
# tracemalloc samples, comfortably below what any real slurp would produce.
_MAX_DELTA_FRACTION_OF_REPO = 0.5


def _write_repo(root: Path, *, n_files: int, payload_bytes: int = _PAYLOAD_BYTES) -> Path:
    """A repo shaped like a real one: a workflow, a README, and ``n_files`` sources."""

    root.mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("# fixture\n", encoding="utf-8")
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    for i in range(n_files):
        # Non-trivial content: a body that would be expensive to hold for every file.
        (root / f"module_{i}.py").write_text(
            f'"""Module {i}."""\n\nVALUE = {i}\nPAYLOAD = "{"x" * payload_bytes}"\n',
            encoding="utf-8",
        )
    return root


def _content_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


def _peak_allocation_bytes(runner: CliRunner, target: Path, out_dir: Path) -> int:
    """Peak bytes allocated by one ``evaluate`` against ``target``."""

    tracemalloc.start()
    try:
        result = runner.invoke(
            app,
            [
                "evaluate",
                "--target",
                str(target),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(out_dir),
                "--summary-only",
            ],
        )
        # evaluate exits 0 or 1 (1 = gate threshold met); 2/3 mean the run did not
        # happen and the measurement would be meaningless.
        assert result.exit_code in (0, 1), (
            f"evaluate against {target.name} exited {result.exit_code}; "
            f"the allocation measurement below would be meaningless.\n{result.output}"
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak


def test_evaluate_peak_allocation_is_flat_across_repo_sizes(tmp_path: Path) -> None:
    small = _write_repo(tmp_path / "small-repo", n_files=1)
    large = _write_repo(tmp_path / "large-repo", n_files=_LARGE_REPO_FILES)
    runner = CliRunner()

    # Warm up once: first invocation pays for lazy imports and catalog parsing, which
    # would otherwise land entirely on whichever target ran first.
    _peak_allocation_bytes(runner, small, tmp_path / "warmup")

    small_peak = _peak_allocation_bytes(runner, small, tmp_path / "out-small")
    large_peak = _peak_allocation_bytes(runner, large, tmp_path / "out-large")

    assert small_peak > 0, "tracemalloc recorded no allocation; the probe is broken"

    repo_bytes = _content_bytes(large)
    delta = large_peak - small_peak
    budget = repo_bytes * _MAX_DELTA_FRACTION_OF_REPO

    assert delta < budget, (
        f"evaluate allocated {delta / 1024:.0f} KiB more against a "
        f"{_LARGE_REPO_FILES}-file repo than against a 1-file repo, which is "
        f"{delta / repo_bytes:.0%} of that repo's {repo_bytes / 1024:.0f} KiB of "
        f"content (budget: {budget / 1024:.0f} KiB). Allocation is now scaling with "
        f"the target's size, which means an evaluator is reading or holding the whole "
        f"tree instead of probing the files its control asks about. A CI gate on a "
        f"monorepo pays that cost on every run."
    )


@pytest.mark.parametrize("n_files", [1, _LARGE_REPO_FILES])
def test_evaluate_completes_regardless_of_repo_size(tmp_path: Path, n_files: int) -> None:
    """The flatness assertion above is only meaningful if both runs actually evaluate."""

    target = _write_repo(tmp_path / f"repo-{n_files}", n_files=n_files)
    result = CliRunner().invoke(
        app,
        [
            "evaluate",
            "--target",
            str(target),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(tmp_path / f"out-{n_files}"),
            "--summary-only",
        ],
    )

    assert result.exit_code in (0, 1), result.output
    assert (tmp_path / f"out-{n_files}" / "evaluation-report.json").is_file()
