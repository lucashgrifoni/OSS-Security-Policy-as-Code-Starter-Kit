"""What the agent/MCP evaluators say when the repository carries no signal at all.

The positive branches are covered elsewhere. The branch nobody had executed is the one an
adopter actually hits first: a repository that is agentic enough to make the control apply,
but carries none of the evidence the control looks for.

That verdict has to be MANUAL_REVIEW_REQUIRED, and specifically not PASS. These are
low-confidence textual signals -- "the file mentions an egress allowlist" -- so absence of
the signal cannot be read as absence of the risk, and silently passing would tell an
operator their agent runtime was reviewed when nothing reviewed it.

Each test asserts the status *and* that a remediation is offered, because a manual-review
verdict with no instruction is a dead end for the person receiving it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import _shared as s
from oss_policy_kit.application.evaluators import ai
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> s.EvalContext:
    return s.EvalContext(
        repo_root=tmp_path,
        profile_id="ai-agent-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


@pytest.fixture
def agentic_repo(tmp_path: Path) -> Path:
    """A repo the agent controls apply to, holding no signal any of them look for.

    ``.mcp/`` is what makes the controls applicable; its contents are deliberately inert so
    the only thing under test is the no-signal verdict.
    """

    (tmp_path / ".mcp").mkdir()
    (tmp_path / ".mcp" / "servers.json").write_text('{"servers": {}}', encoding="utf-8")
    (tmp_path / "README.md").write_text("An agent project.\n", encoding="utf-8")
    return tmp_path


_NO_SIGNAL_EVALUATORS = [
    "eval_mcp_confirm_001",
    "eval_mcp_egress_001",
    "eval_mcp_scope_001",
    "eval_agent_asi_tool_002",
    "eval_agent_asi_memory_006",
    "eval_agent_asi_inter_007",
    "eval_agent_asi_confirm_009",
]


@pytest.mark.parametrize("evaluator_name", _NO_SIGNAL_EVALUATORS)
def test_absent_signal_asks_for_review_and_never_passes(agentic_repo: Path, evaluator_name: str) -> None:
    """A textual signal that is missing means "unknown", not "safe"."""

    outcome: EvalOutcome = getattr(ai, evaluator_name)(_ctx(agentic_repo))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert outcome.status is not ControlStatus.PASS


@pytest.mark.parametrize("evaluator_name", _NO_SIGNAL_EVALUATORS)
def test_the_review_verdict_tells_the_operator_what_to_do(agentic_repo: Path, evaluator_name: str) -> None:
    """A manual-review verdict with no remediation is a dead end for whoever receives it."""

    outcome: EvalOutcome = getattr(ai, evaluator_name)(_ctx(agentic_repo))

    assert outcome.reason.strip()
    assert outcome.remediation.strip()


def test_model_files_without_a_pin_ask_for_review(tmp_path: Path) -> None:
    """A model reference the scanner cannot classify is reviewed, not assumed pinned."""

    (tmp_path / ".mcp").mkdir()
    (tmp_path / "agent.py").write_text(
        "# configures a model but names it through a variable the scanner cannot resolve\n"
        "MODEL = os.environ['MODEL_NAME']\n"
        "client.messages.create(model=MODEL)\n",
        encoding="utf-8",
    )

    outcome = ai.eval_ai_agent_010(_ctx(tmp_path))

    assert outcome.status in {ControlStatus.MANUAL_REVIEW_REQUIRED, ControlStatus.FAIL}
    assert outcome.remediation.strip()


# --------------------------------------------------------------------------- #
# the output-filter file walk
# --------------------------------------------------------------------------- #


def test_a_file_that_cannot_be_read_is_not_credited_with_a_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Crediting an unreadable file would turn an I/O error into a passing control."""

    target = tmp_path / "guard.py"
    target.write_text("OUTPUT_FILTER = True  # moderation\n", encoding="utf-8")

    real = Path.read_text

    def _read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "guard.py":
            raise OSError(13, "Permission denied")
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", _read_text)

    assert ai._file_has_output_filter(target, tmp_path) is False


@pytest.mark.parametrize("excluded", [".git", ".venv", "node_modules"])
def test_vendored_directories_are_not_scanned_for_signals(tmp_path: Path, excluded: str) -> None:
    """A dependency's own moderation code is not evidence about this project."""

    vendored = tmp_path / excluded / "pkg" / "filter.py"
    vendored.parent.mkdir(parents=True)
    vendored.write_text("output_filter = True\n", encoding="utf-8")

    assert ai._file_has_output_filter(vendored, tmp_path) is False


def test_the_filter_file_search_stops_at_its_limit(tmp_path: Path) -> None:
    """The evaluator reason lists examples; an unbounded walk on a monorepo is the cost."""

    for i in range(12):
        (tmp_path / f"guard_{i:02d}.py").write_text("apply_output_filter(response)\n", encoding="utf-8")

    matched = ai._find_output_filter_files(tmp_path, limit=3)

    assert len(matched) == 3


def test_the_search_returns_everything_it_found_when_under_the_limit(tmp_path: Path) -> None:
    """The cap must not be reached by accident; below it, nothing is dropped."""

    for i in range(2):
        (tmp_path / f"guard_{i}.py").write_text("guardrails.configure()\n", encoding="utf-8")

    assert len(ai._find_output_filter_files(tmp_path, limit=5)) == 2
