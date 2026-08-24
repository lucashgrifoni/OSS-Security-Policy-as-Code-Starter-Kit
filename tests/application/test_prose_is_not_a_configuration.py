"""Source text mentions things. A verdict needs the thing itself.

Two AI controls read source files by lowercasing them and testing whether a word appeared
anywhere, which made prose indistinguishable from behaviour:

* ``AI-AGENT-010`` answered **FAIL** -- `exit 1` under `--fail-on fail`, the gate almost everyone
  runs -- on a billing API with no AI in it, because a changelog comment read "we evaluated
  pinning the model to claude or gpt-4 last year and decided against adding any AI".
* ``LLM-AI-ACT-002`` answered **PASS** on an EU AI Act Annex IV §3 output-filtering claim because
  a file contained ``# TODO: we really should add guardrails before shipping this to users`` --
  a line whose entire content is that the filter is missing.

**Two obvious repairs were measured and both were worse than the bug**, which is why the fix
looks the way it does:

* *Strip comments.* Does not fix ``AI-AGENT-010`` at all -- the provider words also appear in a
  module docstring, which is a string literal. And it deletes a true ``AI-AGENT-008`` FAIL from a
  repository whose maintainer honestly documented a `token_passthrough` gap in a comment: the
  more honest the repository, the more findings the change erases.
* *Strip docstrings as well.* Fixes ``AI-AGENT-010`` and destroys a true ``LLM-AI-ACT-002`` PASS
  on a helpdesk assistant that really does moderate every completion, whose only textual trace of
  the hint is the docstring (``client.moderations.create`` matches none of the detector tokens).

So neither control reads syntax. ``AI-AGENT-010`` asks whether the provider name sits on the
**value side of a binding** -- `model: gpt-4o` is a configuration, a sentence is not.
``LLM-AI-ACT-002`` asks whether the line **claims the thing exists** -- a `TODO` or `FIXME` says
the opposite, in a comment or anywhere else.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_ai_agent_010, eval_llm_ai_act_002
from oss_policy_kit.application.evaluators._shared import (
    _configured_value_mentions,
    _hint_on_a_line_that_claims_it_exists,
)
from oss_policy_kit.domain.models import ControlStatus

#: (label, filename, contents, an unpinned model is really configured here)
_MODEL_CASES: tuple[tuple[str, str, str, bool], ...] = (
    ("yaml-binding", "config.yaml", "model: gpt-4o\n", True),
    ("python-constant", "settings.py", 'MODEL = "claude-3-opus"\n', True),
    ("json-binding", "cfg.json", '{"model": "gemini-pro"}\n', True),
    (
        "changelog-comment",
        "util.py",
        "# Changelog: we evaluated pinning the model to claude or gpt-4 last year\n"
        "# and decided against adding any AI to this codebase at all.\n"
        "def add(a, b):\n    return a + b\n",
        False,
    ),
    (
        "prose-docstring",
        "pricing.py",
        '"""The 2023 pricing model was drafted with help from gpt-4 and claude."""\n\n'
        "def price(x):\n    return x * 2\n",
        False,
    ),
)

#: (label, contents, the file claims an output filter EXISTS)
_FILTER_CASES: tuple[tuple[str, str, bool], ...] = (
    ("call-in-code", "def f(text):\n    return content_moderation(text)\n", True),
    (
        "docstring-describing-real-behaviour",
        '"""Guardrails: every completion is passed through :meth:`_moderate` before return."""\n\n'
        "def _moderate(text):\n    return text\n",
        True,
    ),
    (
        "todo-saying-it-is-missing",
        "# TODO: we really should add guardrails before shipping this to users.\n"
        "def chat(prompt):\n    return call_model(prompt)\n",
        False,
    ),
    (
        "fixme-saying-it-is-unwired",
        "# FIXME: output_filter is not wired up yet\ndef g():\n    pass\n",
        False,
    ),
    (
        "wip-note",
        "# WIP: content_moderation planned for the next sprint\ndef g():\n    pass\n",
        False,
    ),
)


@pytest.mark.parametrize(("label", "filename", "body", "configured"), _MODEL_CASES, ids=[c[0] for c in _MODEL_CASES])
def test_a_model_is_pinned_or_not_only_where_one_is_configured(
    tmp_path: Path, label: str, filename: str, body: str, configured: bool
) -> None:
    (tmp_path / filename).write_text(body, encoding="utf-8")

    outcome = eval_ai_agent_010(SimpleNamespace(repo_root=tmp_path))

    if configured:
        assert outcome.status is ControlStatus.FAIL, (
            f"{label}: a model is bound to a floating alias here and the control stopped failing "
            f"({outcome.status.value}). An unpinned model going unreported is worse than the "
            f"false failure this change removed: {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.FAIL, (
            f"{label}: no model is configured in this repository and the control failed it, which "
            f"is exit 1 under `--fail-on fail`: {outcome.reason}"
        )


@pytest.mark.parametrize(("label", "body", "exists"), _FILTER_CASES, ids=[c[0] for c in _FILTER_CASES])
def test_an_output_filter_counts_only_when_a_line_says_it_exists(
    tmp_path: Path, label: str, body: str, exists: bool
) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text(body, encoding="utf-8")

    outcome = eval_llm_ai_act_002(SimpleNamespace(repo_root=tmp_path))

    if exists:
        assert outcome.status is ControlStatus.PASS, (
            f"{label}: the filter really is there and the control stopped crediting it "
            f"({outcome.status.value}). A docstring describing behaviour that exists is not a "
            f"TODO: {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.PASS, (
            f"{label}: the only mention of a filter is a line saying it is NOT done, and the "
            f"control turned it into an EU AI Act conformance claim: {outcome.reason}"
        )


def test_the_binding_test_reads_the_value_side_only() -> None:
    """A key named after a provider is not a model configured to it."""

    aliases = ("gpt-", "claude")

    assert _configured_value_mentions("model: gpt-4o\n", aliases)
    assert _configured_value_mentions('MODEL = "claude-3"\n', aliases)
    assert _configured_value_mentions('  "model": "gpt-4o",\n', aliases)

    assert not _configured_value_mentions("# model: gpt-4o is what we rejected\n", aliases)
    assert not _configured_value_mentions("// model: gpt-4o\n", aliases)
    assert not _configured_value_mentions("We considered gpt-4 for the pricing model.\n", aliases)

    # The name on the KEY side is not a configured model: `claude_notes: internal` is a field
    # about Claude, not a model binding.
    assert not _configured_value_mentions("claude_notes: internal\n", aliases)

    # Prose that happens to carry a colon. The first version of this check tested whether the
    # value CONTAINED an alias, so every one of these produced the exact false FAIL the function
    # was written to stop -- and no test noticed, because the fixtures happened to have no colon
    # in them. Mutation testing found it: disabling the binding check failed nothing.
    assert not _configured_value_mentions("Changelog: we evaluated pinning the model to claude\n", aliases)
    assert not _configured_value_mentions('"""Changelog: we rejected gpt-4 last year."""\n', aliases)
    assert not _configured_value_mentions("Note: the model claude was considered\n", aliases)
    assert not _configured_value_mentions("decision = we did not adopt claude\n", aliases)

    # A quoted value with trailing punctuation is still the model itself.
    assert _configured_value_mentions("  'model': 'gpt-4o',\n", aliases)


def test_a_not_done_marker_defeats_the_claim_wherever_it_appears() -> None:
    """The marker is read, not the syntax, which is what keeps docstrings usable as evidence."""

    hints = ("guardrails", "output_filter")

    assert _hint_on_a_line_that_claims_it_exists("Guardrails wrap every call.\n", hints)
    assert _hint_on_a_line_that_claims_it_exists("    return output_filter(text)\n", hints)

    assert not _hint_on_a_line_that_claims_it_exists("# TODO: add guardrails\n", hints)
    assert not _hint_on_a_line_that_claims_it_exists('"""TODO: wire up output_filter."""\n', hints)
    assert not _hint_on_a_line_that_claims_it_exists("guardrails: not implemented\n", hints)

    # One honest line is enough even when a pending one sits beside it.
    assert _hint_on_a_line_that_claims_it_exists(
        "# TODO: add guardrails for images\nreturn output_filter(text)\n", hints
    )


#: (label, filename, contents) -- shapes in which a floating model REALLY is configured.
#:
#: The rule "the alias must be the whole value of the first binding on the line" is narrower
#: than the way anybody writes a model. It reads only the FIRST `:` or `=` on the line, so an
#: assignment in front of the call hides the call, and it rejects any value with whitespace
#: left in it, so a trailing comment or a second key on the same line hides the binding too.
#: Each of these went FAIL -> manual-review-required, which is exit 1 -> exit 0 under the gate
#: almost everyone runs.
_REAL_BINDINGS: tuple[tuple[str, str, str], ...] = (
    (
        "sdk-call-with-preceding-assignment",
        "app.py",
        'resp = client.chat.completions.create(model="gpt-4o", messages=msgs)\n',
    ),
    ("yaml-with-trailing-comment", "config.yaml", "model: gpt-4o  # chosen for latency\n"),
    ("json-two-keys-one-line", "cfg.json", '{"model": "gpt-4o", "temperature": 0}\n'),
    ("kwarg-inside-a-call", "run.py", 'agent = Agent(model="claude-3-opus", tools=[])\n'),
)


@pytest.mark.parametrize(("label", "filename", "body"), _REAL_BINDINGS, ids=[c[0] for c in _REAL_BINDINGS])
def test_a_configured_model_is_found_wherever_the_binding_sits(
    tmp_path: Path, label: str, filename: str, body: str
) -> None:
    (tmp_path / filename).write_text(body, encoding="utf-8")

    outcome = eval_ai_agent_010(SimpleNamespace(repo_root=tmp_path))

    assert outcome.status is ControlStatus.FAIL, (
        f"{label}: a floating model alias is bound here and the control did not report it "
        f"({outcome.status.value}). Under `--fail-on fail` that is exit 1 becoming exit 0 on the "
        f"commonest way a model is actually configured: {outcome.reason}"
    )


def test_a_detector_declaring_its_own_aliases_is_still_not_a_configuration() -> None:
    """The counterpart, and the reason the narrow rule existed in the first place.

    A configuration binds a scalar; a detector declares a collection. Reading every binding on
    the line must not turn this module's own hint tuples into a configured model -- that is the
    false FAIL the whole prose rule was written to remove.
    """

    aliases = ("gpt-", "claude")

    assert not _configured_value_mentions('_ALIASES: tuple[str, ...] = ("gpt-", "claude")\n', aliases)
    assert not _configured_value_mentions('HINTS = ["gpt-", "claude"]\n', aliases)
    assert not _configured_value_mentions('MAP = {"a": "gpt-"}\n', aliases)
