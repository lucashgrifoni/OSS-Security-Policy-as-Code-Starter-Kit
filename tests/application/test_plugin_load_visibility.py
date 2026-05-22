"""Third-party evaluator plugin load visibility (LOW-001).

Broken plugins must not break built-in evaluation, and the failure must be
recorded (visible via `evaluate --verbose`) instead of silently skipped.
"""

from __future__ import annotations

import importlib.metadata

import pytest

from oss_policy_kit.application import evaluators as ev


class _FakeEP:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


class _FakeEPs:
    def __init__(self, eps):
        self._eps = eps

    def select(self, *, group):
        assert group == "oss_policy_kit.evaluators"
        return self._eps


@pytest.fixture
def _restore_registry():
    before_errors = list(ev.PLUGIN_LOAD_ERRORS)
    before_keys = set(ev.EVALUATOR_REGISTRY)
    yield
    ev.PLUGIN_LOAD_ERRORS[:] = before_errors
    for k in set(ev.EVALUATOR_REGISTRY) - before_keys:
        ev.EVALUATOR_REGISTRY.pop(k, None)


def _patch_eps(monkeypatch, eps):
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda: _FakeEPs(eps))


def test_broken_plugin_recorded_not_raised(monkeypatch, _restore_registry):
    def _boom():
        raise RuntimeError("import blew up")

    _patch_eps(monkeypatch, [_FakeEP("MY-BROKEN-001", _boom)])
    ev._load_external_evaluators()  # must not raise
    errs = {e["name"]: e for e in ev.plugin_load_errors()}
    assert "MY-BROKEN-001" in errs and errs["MY-BROKEN-001"]["kind"] == "load"
    assert "MY-BROKEN-001" not in ev.EVALUATOR_REGISTRY


def test_good_plugin_registers(monkeypatch, _restore_registry):
    def _ok():
        return lambda ctx: None

    _patch_eps(monkeypatch, [_FakeEP("MY-GOOD-001", _ok)])
    ev._load_external_evaluators()
    assert "MY-GOOD-001" in ev.EVALUATOR_REGISTRY
    assert all(e["name"] != "MY-GOOD-001" for e in ev.plugin_load_errors())


def test_builtin_precedence_recorded(monkeypatch, _restore_registry):
    # Pick any existing built-in id.
    builtin = next(iter(ev.EVALUATOR_REGISTRY))
    sentinel = lambda ctx: "OVERRIDE"  # noqa: E731
    _patch_eps(monkeypatch, [_FakeEP(builtin, lambda: sentinel)])
    ev._load_external_evaluators()
    # Built-in must not be overridden.
    assert ev.EVALUATOR_REGISTRY[builtin] is not sentinel
    errs = {e["name"]: e for e in ev.plugin_load_errors()}
    assert errs.get(builtin, {}).get("kind") == "builtin-precedence"


def test_non_callable_plugin_recorded(monkeypatch, _restore_registry):
    _patch_eps(monkeypatch, [_FakeEP("MY-NOTCALLABLE-001", lambda: 42)])
    ev._load_external_evaluators()
    errs = {e["name"]: e for e in ev.plugin_load_errors()}
    assert errs.get("MY-NOTCALLABLE-001", {}).get("kind") == "not-callable"
    assert "MY-NOTCALLABLE-001" not in ev.EVALUATOR_REGISTRY


def test_discovery_failure_recorded(monkeypatch, _restore_registry):
    def _boom():
        raise RuntimeError("metadata unavailable")

    monkeypatch.setattr(importlib.metadata, "entry_points", _boom)
    ev._load_external_evaluators()  # must not raise
    assert any(e["kind"] == "discovery" for e in ev.plugin_load_errors())
