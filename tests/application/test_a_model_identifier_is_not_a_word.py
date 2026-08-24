"""A configured model is an identifier, not any value that happens to contain a vendor's name.

`AI-AGENT-010` has now been wrong FOUR ways, each the correction of the last overshooting:

1. It searched the whole file, so a changelog line saying the team REJECTED a model failed the
   repository. Fixed by requiring the name to sit on the value side of a binding.
2. That rule demanded the alias be the ENTIRE value, so `create(model="gpt-4o", messages=q)` --
   the commonest way anyone configures a model -- stopped failing. Fixed by reading every binding
   on the line and taking the quoted string or the bare token after each.
3. That fix tested CONTAINMENT, so any value carrying a vendor's name anywhere became a
   configured model. An adversarial review found four ordinary repositories it fails, and two
   real configurations it had started missing.

The four false FAILs are exit 1 under `--fail-on fail` on repositories with no AI in them at all:

    locales/fr.json   {"greeting": "Bonjour Claude"}
    package.json      {"description": "Gemini-style CLI for our API"}
    docs/NOTES.md     Author: Claude Bernard
    CHANGELOG.md      - Tokenizer: llama byte-pair edge case

The two false negatives are configurations HEAD and the pre-fix tree both reported:

    cfg/agent.yaml    model: [gpt-4o]
    cfg/models.json   {"models": ["gpt-4o"], "fallback": "none"}

So the rule is neither "appears" nor "is the value": a model IDENTIFIER is the alias followed by
a version, and it is one token. `claude` is a first name, `claude-3-opus` is a model. That single
distinction also retires the collection-opener special case invented for step 3, which existed
only to stop this module's own `("gpt-", "claude")` hint tuples reading as configuration -- bare
aliases have no version after them, so they are not identifiers either.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_ai_agent_010
from oss_policy_kit.domain.models import ControlStatus

#: (label, files, a floating model really is configured here)
_CASES: tuple[tuple[str, dict[str, str], bool], ...] = (
    # --- prose and human names: no AI here at all -------------------------------------------
    ("locale-greeting", {"locales/fr.json": json.dumps({"greeting": "Bonjour Claude"})}, False),
    ("npm-description", {"package.json": json.dumps({"description": "Gemini-style CLI for our API"})}, False),
    ("author-line", {"docs/NOTES.md": "Author: Claude Bernard\n"}, False),
    ("changelog-mention", {"CHANGELOG.md": "- Tokenizer: llama byte-pair edge case on empty input\n"}, False),
    ("rejected-in-prose", {"util.py": "# Changelog: we evaluated pinning the model to claude or gpt-4\n"}, False),
    # --- this module's own vocabulary, which is what the collection rule guarded -------------
    ("detector-tuple", {"rules/p.py": 'MODEL_HINTS = ("model", "claude", "gpt-")\n'}, False),
    ("detector-list", {"rules/q.py": 'HINTS = ["gpt-", "claude"]\n'}, False),
    ("detector-map", {"rules/r.py": 'MAP = {"a": "gpt-"}\n'}, False),
    # --- real configurations, in every shape that appears in the wild ------------------------
    ("yaml-scalar", {"config.yaml": "model: gpt-4o\n"}, True),
    ("yaml-with-comment", {"config.yaml": "model: gpt-4o  # chosen for latency\n"}, True),
    ("python-constant", {"settings.py": 'MODEL = "claude-3-opus"\n'}, True),
    ("sdk-call", {"app.py": 'resp = client.chat.completions.create(model="gpt-4o", messages=m)\n'}, True),
    ("json-two-keys", {"cfg.json": '{"model": "gpt-4o", "temperature": 0}\n'}, True),
    ("yaml-array", {"cfg/agent.yaml": "agent:\n  model: [gpt-4o]\n  temperature: 0\n"}, True),
    ("json-array", {"cfg/models.json": json.dumps({"models": ["gpt-4o"], "fallback": "none"})}, True),
    ("getenv-default", {"settings.py": 'MODEL = os.getenv("AGENT_MODEL", "claude-3-opus")\n'}, True),
    # A flag separates its value with a SPACE, not with `=`. `cmd: app --model gpt-4o` in a
    # workflow or a compose file configures a model as plainly as `model: gpt-4o` does, and HEAD
    # reported it. A YAML list item is the same shape with `-` as the separator.
    ("cli-flag-space-separated", {"run.yaml": "cmd: app --model gpt-4o\n"}, True),
    ("yaml-list-item", {"cfg.yaml": "models:\n  - gpt-4o\n  - claude-3-opus\n"}, True),
    # The counterpart the `-` rule must not swallow: a bullet whose words are a sentence.
    ("bullet-of-prose", {"notes.yaml": "changelog:\n  - Tokenizer llama byte-pair edge case\n"}, False),
    # A short flag names no model: `-M` is `-M`. HEAD required the word `model` somewhere in the
    # file and so never reported `cmd: app -M claude-3-opus` either, which is why dropping it
    # reads no less than the previous release did. Kept as a case rather than deleted, because a
    # false negative that is deliberate has to stay visible.
    ("cli-flag-short-names-no-model", {"run.yaml": "cmd: app -M claude-3-opus\n"}, False),
    # --- what a FOURTH overshoot cost, found by a second adversarial round --------------------
    # `_MODEL_VERSION_START` admitted a bare `-` as a version, so every hyphenated word beginning
    # with a vendor name became a configured model; and the list-item rule read the token after
    # ANY dash, so a Markdown bullet became a binding. Four repositories with no AI in them at
    # all exit 1 under `--fail-on fail`:
    #
    #     CHANGELOG.md      - gpt-4o was released last year
    #     docs/AUTHORS.md   Author: Claude-Bernard
    #     NOTES.md          topic: claude-related tooling
    #     README.md         - llama-index is not used here
    #
    # The first repair for this required a NUMBER in the identifier, and it deleted a true
    # finding: `gemini-pro`, `mistral-large` and `claude-instant` are real floating aliases with
    # no digit anywhere, and they are exactly what this control is for. What separates a surname
    # from a model is not the value, it is the KEY -- so a line is read for aliases only when it
    # is ABOUT a model, and a sequence entry borrows that anchor from the mapping above it.
    ("changelog-bullet-sentence", {"CHANGELOG.md": "- gpt-4o was released last year\n"}, False),
    ("hyphenated-surname", {"docs/AUTHORS.md": "Author: Claude-Bernard\n"}, False),
    ("hyphenated-adjective", {"NOTES.md": "topic: claude-related tooling\n"}, False),
    ("bullet-saying-it-is-unused", {"README.md": "- llama-index is not used here\n"}, False),
    ("hyphenated-package-name", {"package.json": json.dumps({"description": "llama-index helpers"})}, False),
    # The counterpart, so the digit rule cannot be satisfied by rejecting everything: a current
    # model name whose version sits at the END still has to be found, and so does a dotted one.
    ("version-at-the-end", {"cfg.yaml": "model: claude-sonnet-4-5\n"}, True),
    ("dotted-version", {"cfg.yaml": "model: gemini-1.5-pro\n"}, True),
    # A list entry carrying a trailing comment is one entry, not a sentence -- and it is the
    # commonest annotated form of the very shape this rule exists to find.
    ("list-item-with-a-comment", {"cfg.yaml": "models:\n  - gpt-4o  # pinned for latency\n"}, True),
    # ... and an entry under that same `models:` key which turns out to be a SENTENCE is prose
    # again. Without this case the entry rule could read the token after any dash and nothing
    # would notice, because every other bullet in this corpus is anchored by its key already.
    ("sentence-under-a-model-key", {"cfg.yaml": "models:\n  - gpt-4o was removed in v2\n"}, False),
    # `ClaudeBot/1.0` is Anthropic's crawler, and a page documenting which crawlers a site admits
    # is the opposite of an AI configuration. The digit rule alone accepts it -- there IS a number
    # in `bot/1.0` -- so the version has to start where the alias ENDS. Written into a file the
    # control actually reads: the first draft of this case used `robots.txt`, which matches none
    # of the scanned patterns, so it passed while testing nothing.
    ("crawler-user-agent", {"docs/crawlers.md": "User-agent: ClaudeBot/1.0\nDisallow: /private\n"}, False),
)


def _repo(tmp_path: Path, files: dict[str, str]) -> SimpleNamespace:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return SimpleNamespace(repo_root=tmp_path)


@pytest.mark.parametrize(("label", "files", "configured"), _CASES, ids=[c[0] for c in _CASES])
def test_only_a_model_identifier_counts_as_a_configured_model(
    tmp_path: Path, label: str, files: dict[str, str], configured: bool
) -> None:
    outcome = eval_ai_agent_010(_repo(tmp_path, files))

    if configured:
        assert outcome.status is ControlStatus.FAIL, (
            f"{label}: a floating model identifier is configured here and the control did not "
            f"report it ({outcome.status.value}): {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.FAIL, (
            f"{label}: nothing here configures a model, and the control failed the repository -- "
            f"exit 1 under the gate almost everyone runs: {outcome.reason}"
        )
