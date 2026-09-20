"""Three loaders refused an oversize document only after reading it whole.

Each already refuses a document that nests too deeply or fails to parse, and each did
that after the bytes were in memory, which is the wrong order for the failure the limit
exists to prevent. `--kit-root` lets an operator point all three at a directory this
package did not ship, so the bound is reachable rather than theoretical.

`MAX_CONFIG_BYTES` is 1 MiB against measured content: the largest shipped catalog is
57,825 bytes, the largest profile 2,983, and the OSPS coverage map 8,115. Eighteen times
the largest thing here.

Each test below blocks the read as well as oversizing the file, so a fix that produced
the right message after reading anyway would still fail. Asserting only on the message
would not tell those two apart.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.input_limits import MAX_CONFIG_BYTES
from oss_policy_kit.domain.errors import InvalidInputError, LoadError


def _oversize(path: Path) -> Path:
    """Write a file past the limit, cheaply, and confirm it really is past it."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# padding\n" * ((MAX_CONFIG_BYTES // 10) + 64), encoding="utf-8")
    assert path.stat().st_size > MAX_CONFIG_BYTES, path.stat().st_size
    return path


def _forbid_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any read of file content fail loudly, so ordering is what is under test."""

    def _boom(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("the file was read before its size was checked")

    monkeypatch.setattr(Path, "read_text", _boom)
    monkeypatch.setattr(Path, "read_bytes", _boom)


def test_an_oversize_catalog_is_refused_without_being_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oss_policy_kit.application import loader

    catalog = _oversize(tmp_path / "controls" / "catalog.yaml")
    _forbid_reads(monkeypatch)

    with pytest.raises(LoadError) as caught:
        loader._load_kit_yaml(catalog, label="Catalog")

    message = str(caught.value)
    assert "catalog.yaml" in message
    assert str(MAX_CONFIG_BYTES) in message
    assert str(tmp_path) not in message, "the message names the file, never the path (M-002)"


def test_an_oversize_coverage_map_is_refused_without_being_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oss_policy_kit.application import osps_coverage

    coverage_map = _oversize(tmp_path / "frameworks" / "osps-baseline-2026.yaml")
    _forbid_reads(monkeypatch)

    with pytest.raises(LoadError) as caught:
        osps_coverage._load_raw(coverage_map)

    message = str(caught.value)
    assert "osps-baseline-2026.yaml" in message
    assert str(MAX_CONFIG_BYTES) in message


def test_an_oversize_repo_local_workflow_template_is_refused_without_being_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback resolves against the working directory, so this file is the scanned
    repository's, not ours."""

    from oss_policy_kit.application import init_writer

    dest, source = next(iter(init_writer._WORKFLOW_SOURCE_BY_DEST.items()))
    _oversize(tmp_path / init_writer._WORKFLOW_TEMPLATE_REPO_PATH / source)
    monkeypatch.chdir(tmp_path)
    # Force the packaged lookup to miss, so the repo-local fallback is what runs.
    monkeypatch.setattr(init_writer.resources, "files", lambda _pkg: (_ for _ in ()).throw(FileNotFoundError()))
    _forbid_reads(monkeypatch)

    with pytest.raises(InvalidInputError) as caught:
        init_writer._resolve_workflow_template(dest)

    assert source in str(caught.value)
    assert str(MAX_CONFIG_BYTES) in str(caught.value)


def test_a_normal_sized_kit_file_still_loads(tmp_path: Path) -> None:
    """The bound must not be the thing that breaks ordinary use."""

    from oss_policy_kit.application import loader

    catalog = tmp_path / "catalog.yaml"
    catalog.write_text("controls:\n  - id: X-1\n    title: fine\n", encoding="utf-8")

    loaded = loader._load_kit_yaml(catalog, label="Catalog")

    assert loaded == {"controls": [{"id": "X-1", "title": "fine"}]}


def test_the_shipped_catalog_is_far_under_the_bound() -> None:
    """If this package ever ships something near the limit, the limit is wrong."""

    import oss_policy_kit

    data = Path(oss_policy_kit.__file__).parent / "data"
    largest = max((p.stat().st_size for p in data.rglob("*.yaml")), default=0)
    assert 0 < largest < MAX_CONFIG_BYTES // 4, f"largest shipped YAML is {largest} bytes"
