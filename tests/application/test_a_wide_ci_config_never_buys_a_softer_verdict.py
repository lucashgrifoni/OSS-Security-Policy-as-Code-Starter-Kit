"""A CI configuration in a wide encoding must not answer differently from the same bytes in UTF-8.

`aws_ci_parser` and `azure_pipeline_parser` decoded with ``errors="replace"``. On a UTF-16
buildspec that produced mojibake, and mojibake carries none of what a scan looks for: no
`AWS_SECRET_ACCESS_KEY`, no `pool:`.

Measured before the fix, on aws-level-1 with a buildspec holding a hardcoded key:

    utf-8    AWS-SECRET-038 = fail
    utf-16   AWS-SECRET-038 = manual-review-required

and the reason that flip was not worse is worth recording, because it was not a safety
mechanism. `parse_errors` came back EMPTY: the mojibake still loaded as YAML, so nothing
withdrew anything. The control simply answers manual-review when it finds neither an inline
secret nor a managed-secret reference, and that default was all that stood between a UTF-16
buildspec and a clean bill of health. A sibling control that answered `pass` on the same
absence would have given one.

Both readers now go through `decode_source_detail`, which honours the declared encoding, so
the file is READ rather than withdrawn. The assertions below are therefore equality, not
"no softer": a wide-encoded config must produce exactly the verdicts the narrow one produces.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.infrastructure import aws_ci_parser, azure_pipeline_parser
from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines
from oss_policy_kit.infrastructure.source_text import DecodedSource

_BUILDSPEC = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n"
    "      - curl https://example.test/x.sh | bash\n"
)
_PIPELINE = "trigger:\n  - main\npool:\n  name: SelfHosted\nsteps:\n  - script: echo $(PASSWORD)\n"

_CASES = [
    ("aws-level-1", "buildspec.yml", _BUILDSPEC),
    ("aws-level-3", "buildspec.yml", _BUILDSPEC),
    ("azure-level-1", "azure-pipelines.yml", _PIPELINE),
    ("azure-release-hardening-3", "azure-pipelines.yml", _PIPELINE),
]


def _verdicts(profile_id: str, relative: str, data: bytes) -> dict[str, str]:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        report = evaluate_repository(repo, profile, catalog, waiver_outcome=None, scorecard=None)
        return {r.control_id: r.status.value for r in report.results}


@pytest.mark.parametrize(("profile_id", "relative", "text"), _CASES)
@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16", "utf-32-le"])
def test_a_wide_ci_config_answers_exactly_as_the_narrow_one(
    profile_id: str, relative: str, text: str, encoding: str
) -> None:
    narrow = _verdicts(profile_id, relative, text.encode("utf-8"))
    wide = _verdicts(profile_id, relative, text.encode(encoding))

    differing = [
        f"{control}: utf-8={narrow[control]} {encoding}={wide.get(control)}"
        for control in sorted(narrow)
        if narrow[control] != wide.get(control)
    ]

    assert not differing, "the encoding changed a verdict:\n  " + "\n  ".join(differing)


def test_the_fixture_actually_reaches_a_control() -> None:
    """Anti-vacuum: two identical empty answers would satisfy every case above.

    The buildspec carries a hardcoded key, so the readable copy must FAIL. Without this, a
    fixture that quietly stopped being parsed would make the whole file pass.
    """

    narrow = _verdicts("aws-level-1", "buildspec.yml", _BUILDSPEC.encode("utf-8"))

    assert narrow["AWS-SECRET-038"] == "fail"


def test_the_wide_copy_is_read_rather_than_merely_not_softened() -> None:
    """The specific verdict the old behaviour lost, asserted by name.

    Equality across every control would also hold if both copies failed everywhere, so this
    names the one that used to move: a UTF-16 buildspec with a hardcoded key now FAILS, where
    it used to answer manual-review-required.
    """

    wide = _verdicts("aws-level-1", "buildspec.yml", _BUILDSPEC.encode("utf-16-le"))

    assert wide["AWS-SECRET-038"] == "fail"


def test_an_encoding_the_decoder_cannot_honour_is_recorded_rather_than_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The branch for a wide file `decode_source_detail` detects and cannot decode.

    Every wide encoding a buildspec is realistically written in -- UTF-16 either way round,
    UTF-32 -- is honoured, so this condition cannot be produced with bytes. Forced here
    instead, because the alternative is a branch that only runs in production.
    """

    (tmp_path / "buildspec.yml").write_text("version: 0.2\n", encoding="utf-8")
    monkeypatch.setattr(
        aws_ci_parser,
        "decode_source_detail",
        lambda _data: DecodedSource(text="", used_codec=None, wide_unhonoured=True),
    )

    analysis: Any = analyze_aws_ci(tmp_path)

    assert [p.name for p, _ in analysis.parse_errors] == ["buildspec.yml"]
    assert "cannot honour" in analysis.parse_errors[0][1]
    assert not analysis.inline_secret_risk_paths, "a file it could not read produced a content signal"


def test_the_azure_parser_records_an_encoding_it_cannot_honour_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same branch on the sibling reader, forced the same way and for the same reason."""

    pipeline = tmp_path / "azure-pipelines.yml"
    pipeline.write_text("trigger:\n  - main\n", encoding="utf-8")
    monkeypatch.setattr(
        azure_pipeline_parser,
        "decode_source_detail",
        lambda _data: DecodedSource(text="", used_codec=None, wide_unhonoured=True),
    )

    analysis: Any = analyze_azure_pipelines(tmp_path)

    assert [p.name for p, _ in analysis.parse_errors] == ["azure-pipelines.yml"]
    assert "cannot honour" in analysis.parse_errors[0][1]
