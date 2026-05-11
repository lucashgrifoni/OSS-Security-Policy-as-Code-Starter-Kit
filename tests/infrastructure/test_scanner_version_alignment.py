"""Tests for ``_kit_version()`` in the IaC and K8s scanner modules.

The scanners stamp their evidence files with a ``tool_version`` field. When the
working tree and the installed wheel disagree (typical during dev: pyproject
already bumped to ``X.Y+1.0.dev0`` while only ``X.Y.0`` is installed in the
venv), the scanner must prefer the source ``oss_policy_kit.__version__`` so
evidence reflects the code actually doing the scanning, not a stale wheel.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError

import pytest

import oss_policy_kit
from oss_policy_kit.infrastructure.iac import scanner as iac_scanner
from oss_policy_kit.infrastructure.k8s import scanner as k8s_scanner


@pytest.mark.parametrize(
    "scanner_module",
    [iac_scanner, k8s_scanner],
    ids=["iac", "k8s"],
)
def test_kit_version_returns_installed_when_matching_source(scanner_module, monkeypatch: pytest.MonkeyPatch) -> None:
    """Installed wheel == source __version__ -> returns the installed string."""

    monkeypatch.setattr(scanner_module, "_pkg_version", lambda _name: oss_policy_kit.__version__)
    assert scanner_module._kit_version() == oss_policy_kit.__version__


@pytest.mark.parametrize(
    "scanner_module",
    [iac_scanner, k8s_scanner],
    ids=["iac", "k8s"],
)
def test_kit_version_prefers_source_when_installed_diverges(scanner_module, monkeypatch: pytest.MonkeyPatch) -> None:
    """Installed wheel diverges from source __version__ -> source wins.

    Dev cycles bump ``oss_policy_kit.__version__`` ahead of the installed
    package; stamping evidence with the stale wheel version would lie about
    which code produced the findings.
    """

    monkeypatch.setattr(scanner_module, "_pkg_version", lambda _name: "0.0.1-stale-wheel")
    assert scanner_module._kit_version() == oss_policy_kit.__version__


@pytest.mark.parametrize(
    "scanner_module",
    [iac_scanner, k8s_scanner],
    ids=["iac", "k8s"],
)
def test_kit_version_falls_back_to_source_when_package_not_installed(
    scanner_module, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``PackageNotFoundError`` (running from a source checkout without ``pip install -e``)
    must surface the source version, not raise."""

    def _raise(_name: str) -> str:
        raise PackageNotFoundError("oss-policy-kit")

    monkeypatch.setattr(scanner_module, "_pkg_version", _raise)
    assert scanner_module._kit_version() == oss_policy_kit.__version__
