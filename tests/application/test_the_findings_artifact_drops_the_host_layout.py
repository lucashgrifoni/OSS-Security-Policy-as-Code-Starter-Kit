"""The findings artifact must not repeat the operator's directory chain.

`target_path` was the only field in findings/1.0 going through the privacy sanitizer.
Measured with a scanner drop carrying an absolute path, the published artifact repeated the
operator's account and directories in three more places: `location.file`, `message`, and
`sources[].message`.

"That is third-party SARIF, not ours" does not hold: the kit's own `scan-sast` writes an
absolute path into its evidence, and `correlate-findings` carries whatever it reads.

The rule applied is the one `reports/2.0` already follows -- only a ROOTED path loses its
directories. A repository-relative path is left alone, because `src/app.py` is not host layout,
it is the answer to "where is this". The first version of the fix used the target-path
sanitizer, which reduces anything to its basename, and turned `src/app.py` into `app.py` for
every ordinary finding. That is asserted below so it cannot come back.

`correlation.key` is a known and deliberate exception, asserted at the bottom so nobody reads
this file and concludes the artifact is fully redacted.

Paths are assembled rather than written out: `scripts/check_public_hygiene.py` forbids
home-shaped literals in public files.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from oss_policy_kit.application.finding_correlation import KEY_SPEC
from oss_policy_kit.application.findings_report import build_findings_report

_SAST = Path(".oss-policy-kit") / "evidence" / "sast"
_ACCOUNT = "CONTA-DO-OPERADOR"
_ABSOLUTE = "C:" + "/" + "Users" + f"/{_ACCOUNT}/projeto/src/app.py"
_RELATIVE = "src/app.py"


def _drop(repo: Path, tool: str, uri: str, rule: str, message: str) -> None:
    directory = repo / _SAST
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "version": "1.0"}},
                "results": [
                    {
                        "ruleId": rule,
                        "level": "error",
                        "message": {"text": message},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 7}}}
                        ],
                    }
                ],
            }
        ],
    }
    (directory / f"{tool}.sarif.json").write_text(json.dumps(document), encoding="utf-8")


def test_an_absolute_location_loses_its_directories(tmp_path: Path) -> None:
    _drop(tmp_path, "osv-scanner", _ABSOLUTE, "CVE-2026-0001", f"Vulnerable call reached from {_ABSOLUTE}")

    report = build_findings_report(tmp_path, kit_version="test")
    finding = report["findings"][0]

    assert _ACCOUNT not in json.dumps(report), (
        f"the account name survives somewhere in the artifact: {json.dumps(report)[:400]!r}"
    )
    assert finding["location"]["file"] == "app.py"
    assert _ACCOUNT not in finding["message"]
    assert _ACCOUNT not in finding["sources"][0]["message"]


def test_a_repository_relative_location_is_left_alone(tmp_path: Path) -> None:
    """The ordinary case, and the regression the first version of this fix introduced."""

    _drop(tmp_path, "osv-scanner", _RELATIVE, "CVE-2026-0002", f"issue in {_RELATIVE}")

    finding = build_findings_report(tmp_path, kit_version="test")["findings"][0]

    assert finding["location"]["file"] == _RELATIVE, (
        f"a repository-relative path was reduced to {finding['location']['file']!r}. The "
        "directory inside the repository is not the operator's layout; it is where the finding is."
    )
    assert _RELATIVE in finding["message"]


def test_include_absolute_path_still_returns_everything(tmp_path: Path) -> None:
    """The flag exists for operators who want the full path; redaction must not override it."""

    _drop(tmp_path, "osv-scanner", _ABSOLUTE, "CVE-2026-0003", f"Vulnerable call reached from {_ABSOLUTE}")

    report = build_findings_report(tmp_path, kit_version="test", include_absolute_path=True)

    assert _ACCOUNT in json.dumps(report), "the flag was ignored and the path was redacted anyway"


def test_the_correlation_key_loses_the_host_layout_too(tmp_path: Path) -> None:
    """The last field that repeated the operator's directory chain under the privacy default.

    This test was an xfail for as long as the limitation stood, and its reason said redacting
    a merge key would give two findings in different directories the same identity. That was
    wrong about where identity lives: correlate() groups on the canonical key in memory and
    `id` is the sha256 of that same string, both settled before serialization. Only the
    printed copy is redacted, which the two tests below hold in place.
    """

    _drop(tmp_path, "zizmor", _ABSOLUTE, "template-injection", "Template injection")

    finding = build_findings_report(tmp_path, kit_version="test")["findings"][0]

    assert _ACCOUNT not in finding["correlation"]["key"]
    assert _ACCOUNT not in json.dumps(finding), "some other field still carries the account"


def test_include_absolute_path_returns_the_key_verbatim(tmp_path: Path) -> None:
    """`id` is documented as the sha256 of the key, so the check has to stay possible.

    Under redaction it is not, and docs/findings-correlation.md says so. The operator who
    needs to reproduce an id asks for the absolute path and gets the whole key back.
    """

    _drop(tmp_path, "zizmor", _ABSOLUTE, "template-injection", "Template injection")

    finding = build_findings_report(tmp_path, kit_version="test", include_absolute_path=True)["findings"][0]

    key = finding["correlation"]["key"]
    assert _ACCOUNT in key
    assert finding["id"] == f"{KEY_SPEC}:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def test_redacting_the_printed_key_changes_no_identity(tmp_path: Path) -> None:
    """The property the old xfail reason was actually worried about, asserted directly.

    Same drop, serialized twice. The redacted artifact and the verbatim one must agree on
    `id`, because the id was computed from the in-memory key before either was written.
    """

    _drop(tmp_path, "zizmor", _ABSOLUTE, "template-injection", "Template injection")

    redacted = build_findings_report(tmp_path, kit_version="test")["findings"][0]
    verbatim = build_findings_report(tmp_path, kit_version="test", include_absolute_path=True)["findings"][0]

    assert redacted["id"] == verbatim["id"]
    assert redacted["correlation"]["key"] != verbatim["correlation"]["key"]


def _drop_two(repo: Path, tool: str, first: str, second: str, rule: str, message: str) -> None:
    """One SARIF run holding two results at two different absolute paths.

    Deliberately one file rather than two: `collect_normalized_findings` ingests by evidence
    filename, and a second tool dropped beside it is not necessarily read, so a two-file
    fixture would have measured the collector instead of the merge.
    """

    directory = repo / _SAST
    directory.mkdir(parents=True, exist_ok=True)

    def _result(uri: str) -> dict[str, object]:
        return {
            "ruleId": rule,
            "level": "error",
            "message": {"text": message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 7}}}],
        }

    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": tool, "version": "1.0"}},
                "results": [_result(first), _result(second)],
            }
        ],
    }
    (directory / f"{tool}.sarif.json").write_text(json.dumps(document), encoding="utf-8")


def test_two_directories_sharing_a_basename_still_do_not_merge(tmp_path: Path) -> None:
    """The over-merge the old xfail reason predicted, run rather than assumed.

    Two findings whose absolute paths differ only in their directory now print the SAME
    redacted key, exactly as they already printed the same `location.file`, and must still be
    two findings with two ids. Measured both ways on the same fixture: the verbatim keys
    differ, the redacted keys are identical, and both serializations return two findings with
    the same pair of ids. If redaction ever reached the merge, the redacted half collapses to
    one and this fails.
    """

    other = "C:" + "/" + "Users" + f"/{_ACCOUNT}/outro/src/app.py"
    _drop_two(tmp_path, "zizmor", _ABSOLUTE, other, "template-injection", "Template injection")

    redacted = build_findings_report(tmp_path, kit_version="test")["findings"]
    verbatim = build_findings_report(tmp_path, kit_version="test", include_absolute_path=True)["findings"]

    assert len(redacted) == 2, "the two findings merged; redaction reached the merge key"
    assert [f["id"] for f in redacted] == [f["id"] for f in verbatim]

    assert len({f["correlation"]["key"] for f in verbatim}) == 2, "fixture no longer has two distinct paths"
    assert len({f["correlation"]["key"] for f in redacted}) == 1, (
        "fixture no longer exercises the same-printed-key case"
    )
    assert _ACCOUNT not in json.dumps(redacted)
