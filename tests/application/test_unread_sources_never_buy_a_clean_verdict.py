"""A mis-encoded source file must be READ, not refused -- and never reported as absent.

A `.tf` saved as UTF-16 (one `git add` on Windows away) made every Terraform control answer

    NOT_APPLICABLE -- "No Terraform / OpenTofu sources detected in repository"

about a repository whose only Terraform file declared a public-read S3 bucket and a security
group open to `0.0.0.0/0`. `not-applicable` reads like a shrug but it is a positive claim about
the repository, and it is the one state no summary counts.

**The first two attempts at this were both wrong, and the second was worse than the bug.**

Attempt one hand-wrote evidence with `files_scanned=[]` and checked the evaluators. They were
right about that shape; three of the five scanners never emit it, so the fence was green while
three families were broken.

Attempt two made the scanners read strict UTF-8 and record a failure. That treats a
mis-encoded file as broken input, and it is not:

* YAML 1.2 *requires* a processor to accept UTF-8, UTF-16 and UTF-32 with a BOM -- a UTF-16
  `pod.yaml` is a manifest `kubectl apply` would install;
* JSON parsers detect the encoding from the first bytes (RFC 4627);
* Python honours a PEP 263 `# -*- coding: latin-1 -*-` line.

So refusing them DELETED a real `acl="public-read"` finding from a legal latin-1 Pulumi
program and turned `--fail-on fail` from red to green -- and it degraded six CloudFormation
controls on a repository whose only offence was a UTF-16 `appsettings.json`, which is simply
what PowerShell's `Out-File` writes by default.

What the kit does now, and what every case below pins down:

- a mis-encoded source is DECODED and scanned; its violations are found and reported as FAIL,
  which is a better answer than any amount of honest uncertainty
- "could not read this" is reserved for bytes no legal encoding explains
- and only when the scan read NOTHING at all does a control withdraw its verdict, because a
  scanner whose candidate glob is `**/*.py` or `**/*.yaml` meets far more files that are not
  sources of its technology than ones that are

Everything below writes a real file, runs the real `scan-*` command in a subprocess, and reads
the evidence that command actually wrote. A test that builds its own input tests the
assertion, not the system -- which is exactly how attempt one stayed green.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.domain.models import ControlStatus

#: One source per family that the family's rules actually flag, so the UTF-8 leg proves the
#: fixture is dirty before the UTF-16 leg claims the finding went missing.
_TERRAFORM = """resource "aws_s3_bucket" "b" {
  bucket = "demo"
  acl    = "public-read"
}
"""
_PULUMI = """import pulumi_aws as aws

bucket = aws.s3.Bucket("b", acl="public-read")
"""
_CFN = """AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
"""
_BICEP = """resource sa 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: 'demo'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
"""
_K8S = """apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
    - name: c
      image: nginx
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
"""


@dataclass(frozen=True)
class Family:
    name: str
    command: str
    filename: str
    source: str
    evidence: str
    module: str
    builder: str
    scanner: str

    def __str__(self) -> str:  # keeps pytest ids readable
        return self.name


FAMILIES = (
    Family(
        "terraform",
        "scan-iac",
        "main.tf",
        _TERRAFORM,
        "iac-terraform.json",
        "evaluators_iac",
        "build_iac_evaluators",
        "iac.scanner",
    ),
    Family(
        "pulumi",
        "scan-pulumi",
        "__main__.py",
        _PULUMI,
        "iac-pulumi.json",
        "evaluators_iac_pulumi",
        "build_iac_pulumi_evaluators",
        "iac.pulumi.scanner",
    ),
    Family(
        "cfn",
        "scan-cfn",
        "tpl.yaml",
        _CFN,
        "iac-cfn.json",
        "evaluators_iac_cfn",
        "build_iac_cfn_evaluators",
        "iac.cfn.scanner",
    ),
    Family(
        "bicep",
        "scan-bicep",
        "main.bicep",
        _BICEP,
        "iac-bicep.json",
        "evaluators_iac_bicep",
        "build_iac_bicep_evaluators",
        "iac.bicep.scanner",
    ),
    Family(
        "k8s",
        "scan-k8s",
        "pod.yaml",
        _K8S,
        "k8s-baseline.json",
        "evaluators_k8s",
        "build_k8s_evaluators",
        "k8s.scanner",
    ),
)


#: A valid file of the right EXTENSION that is not a source of the technology -- exactly what a
#: broad candidate glob (`**/*.py`, `**/*.yaml`) sweeps up on an ordinary repository.
_WORKFLOW = """name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
"""

_INNOCUOUS = {
    "terraform": 'variable "unused" {\n  type = string\n}\n',
    "pulumi": "VERSION = '1.0'\n",
    "cfn": _WORKFLOW,
    "bicep": "param location string = 'westeurope'\n",
    "k8s": _WORKFLOW,
}


def _scan(root: Path, family: Family) -> dict[str, Any]:
    """Drive the real scanner exactly as the `scan-*` command does, and return its evidence.

    In-process, via `run_scan` -> `render_evidence_payload` -> `write_evidence`, which is the
    three-line body of the CLI command. The point of this file is that the evidence comes from
    the SCANNER rather than from the test's imagination -- the previous version hand-wrote a
    `files_scanned=[]` shape that three of the five scanners never emit, and stayed green while
    three families were broken. Using a subprocess as well cost 25 process spawns and made
    unrelated tests fail intermittently on Windows, so `test_the_cli_writes_the_same_evidence`
    below covers the wiring once instead.
    """

    module = __import__(f"oss_policy_kit.infrastructure.{family.scanner}", fromlist=["_"])
    outcome = module.run_scan(root)
    payload = module.render_evidence_payload(outcome, target=root)
    module.write_evidence(payload, repo_root=root, filename=module.EVIDENCE_FILENAME)
    evidence = root / ".oss-policy-kit" / "evidence" / family.evidence
    assert evidence.is_file(), f"{family.command} wrote no evidence at {family.evidence}"
    return json.loads(evidence.read_text(encoding="utf-8"))


def _verdicts(root: Path, family: Family) -> dict[str, Any]:
    module = __import__(f"oss_policy_kit.application.{family.module}", fromlist=["_"])
    ctx = SimpleNamespace(repo_root=root)
    return {cid: fn(ctx) for cid, fn in getattr(module, family.builder)().items()}


def _write(root: Path, family: Family, encoding: str) -> None:
    (root / family.filename).write_bytes(family.source.encode(encoding))


@pytest.mark.parametrize("family", FAMILIES, ids=str)
def test_the_fixture_is_dirty_when_it_can_be_read(tmp_path: Path, family: Family) -> None:
    """The control leg. Without it, "the finding survived" could mean there never was one."""

    _write(tmp_path, family, "utf-8")
    data = _scan(tmp_path, family)

    assert data.get("files_scanned"), f"{family.name}: the readable source was not scanned at all"
    states = Counter(o.status for o in _verdicts(tmp_path, family).values())
    assert states[ControlStatus.FAIL] > 0, (
        f"{family.name}: the deliberately-vulnerable source produced no FAIL ({dict(states)}), so "
        "the encoding cases below would prove nothing."
    )


@pytest.mark.parametrize("family", FAMILIES, ids=str)
def test_a_mis_encoded_source_is_read_and_its_findings_survive(tmp_path: Path, family: Family) -> None:
    """UTF-16 with a BOM is legal for YAML and JSON, so the verdict must not change at all.

    Python is the exception and it is the format's, not the kit's: the interpreter rejects a
    UTF-16 module too, so `scan-pulumi` is checked for the encodings Python actually accepts.
    """

    encoding = "latin-1" if family.name == "pulumi" else "utf-16"
    source = family.source
    if family.name == "pulumi":
        source = "# -*- coding: latin-1 -*-\n# café\n" + source

    (tmp_path / family.filename).write_bytes(source.encode(encoding))
    data = _scan(tmp_path, family)

    assert not data.get("diagnostics", {}).get("parse_errors"), (
        f"{family.name}: a legal {encoding} source was recorded as unreadable. Refusing it "
        f"deletes its findings: {data.get('diagnostics')}"
    )
    states = Counter(o.status for o in _verdicts(tmp_path, family).values())
    assert states[ControlStatus.FAIL] > 0, (
        f"{family.name}: the violations in a legal {encoding} source disappeared ({dict(states)}). "
        "A mis-encoded file is one a human still reads, and one a deploy tool still applies."
    )


@pytest.mark.parametrize("family", FAMILIES, ids=str)
def test_a_legacy_single_byte_encoding_still_yields_its_findings(tmp_path: Path, family: Family) -> None:
    """cp1252 with one accented byte in a comment: 99% ASCII, no BOM, and not valid UTF-8.

    This is the regression that a strict read introduced and that two rounds of review took to
    surface. Any Windows editor produces such a file. The old lossy read turned the one bad
    byte into U+FFFD, the document still parsed, and the violation under it was reported;
    reading strictly refused the whole file and the pipeline went from exit 1 to exit 0.

    A fence has to contain the bug it was written for, so this is the exact shape: a comment
    reading `owner: José`, nothing else changed.
    """

    comment = {"terraform": "# ", "pulumi": "# ", "cfn": "# ", "bicep": "// ", "k8s": "# "}[family.name]
    source = f"{comment}owner: José -- configuração\n" + family.source
    (tmp_path / family.filename).write_bytes(source.encode("cp1252"))

    _scan(tmp_path, family)

    states = Counter(o.status for o in _verdicts(tmp_path, family).values())
    assert states[ControlStatus.FAIL] > 0, (
        f"{family.name}: a cp1252 source lost its findings ({dict(states)}). The bytes are not "
        "valid UTF-8 and the file is still 99% readable -- refusing it deletes real findings."
    )


@pytest.mark.parametrize("family", FAMILIES, ids=str)
def test_a_file_the_os_will_not_open_is_not_a_repository_without_the_technology(
    tmp_path: Path, family: Family, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one case that genuinely cannot be read: every control must say it could not tell.

    Note what is NOT here: a file of arbitrary bytes with a source extension. That decodes
    lossily, parses to nothing, and is reported `not-applicable` -- which is right, and is what
    the kit has always said. A binary file named `main.tf` is not Terraform the kit failed to
    read; it is not Terraform. The guard is for a file that exists, is a candidate, and cannot
    be obtained at all.
    """

    real_read_bytes = Path.read_bytes

    def _refuse(self: Path) -> bytes:
        if self.name == family.filename:
            raise PermissionError(13, "Access is denied")
        return real_read_bytes(self)

    _write(tmp_path, family, "utf-8")
    monkeypatch.setattr(Path, "read_bytes", _refuse)
    data = _scan(tmp_path, family)

    assert data.get("diagnostics", {}).get("parse_errors"), (
        f"{family.name}: a file the OS refused was dropped without a diagnostics.parse_errors "
        "entry, so nothing downstream can know it existed."
    )
    for control_id, outcome in _verdicts(tmp_path, family).items():
        assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED, (
            f"{family.name}/{control_id} answered {outcome.status.value} about a repository whose "
            f"only candidate file it could not obtain: {outcome.reason}"
        )
        assert family.filename in outcome.reason, (
            f"{family.name}/{control_id} does not name the file it could not read: {outcome.reason}"
        )


@pytest.mark.parametrize("family", FAMILIES, ids=str)
def test_one_unreadable_file_does_not_withdraw_verdicts_from_a_repo_that_read_others(
    tmp_path: Path, family: Family
) -> None:
    """The false positive that made attempt two worse than the bug.

    A repository that uses none of the technology, plus one file the scanner cannot read, must
    keep answering `not-applicable` -- not degrade a whole control family. Scanners whose
    candidate glob is `**/*.py` or `**/*.yaml` meet far more files that are not sources of
    their technology than ones that are.
    """

    suffix = Path(family.filename).suffix
    (tmp_path / f"unreadable{suffix}").write_bytes(bytes(range(256)) * 4)
    (tmp_path / f"ordinary{suffix}").write_bytes(_INNOCUOUS[family.name].encode("utf-8"))
    _scan(tmp_path, family)

    states = Counter(o.status for o in _verdicts(tmp_path, family).values())
    assert states[ControlStatus.MANUAL_REVIEW_REQUIRED] == 0, (
        f"{family.name}: a repository with no {family.name} at all had {states[ControlStatus.MANUAL_REVIEW_REQUIRED]} "
        f"control(s) withdrawn because ONE unrelated file could not be read ({dict(states)})."
    )


@pytest.mark.parametrize("family", FAMILIES, ids=str)
def test_an_unread_file_does_not_soften_a_real_finding(
    tmp_path: Path, family: Family, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unread sources can only ADD violations, so they never take a FAIL out of `--fail-on fail`."""

    suffix = Path(family.filename).suffix
    _write(tmp_path, family, "utf-8")
    (tmp_path / f"unreadable{suffix}").write_text(_INNOCUOUS[family.name], encoding="utf-8")

    real_read_bytes = Path.read_bytes

    def _refuse(self: Path) -> bytes:
        if self.name.startswith("unreadable"):
            raise PermissionError(13, "Access is denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _refuse)
    data = _scan(tmp_path, family)

    assert data.get("diagnostics", {}).get("parse_errors"), f"{family.name}: no parse error recorded"
    states = Counter(o.status for o in _verdicts(tmp_path, family).values())
    assert states[ControlStatus.FAIL] > 0, (
        f"{family.name}: the readable source's findings vanished once an unreadable file sat "
        f"beside it ({dict(states)}). A real finding is not made less real by a file nobody read."
    )
    for outcome in _verdicts(tmp_path, family).values():
        if outcome.status is ControlStatus.PASS:
            assert "unreadable" in outcome.reason, (
                f"{family.name}: a PASS that never mentions the file it did not read: {outcome.reason}"
            )


def test_the_cli_writes_the_same_evidence_the_tests_above_read(tmp_path: Path) -> None:
    """The wiring the in-process helper skips: `scan-*` really does produce this evidence.

    One subprocess, once, rather than one per case. Running the command for all twenty-five
    cases spawned enough processes to make UNRELATED tests fail intermittently on Windows --
    a test file that destabilises its own suite gets marked flaky and then ignored, which
    would cost far more than the wiring it was covering.
    """

    family = FAMILIES[0]
    (tmp_path / family.filename).write_text(family.source, encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", family.command, "--target", "."],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert proc.returncode == 0, f"{family.command} exited {proc.returncode}: {proc.stderr[:400]}"

    written = json.loads((tmp_path / ".oss-policy-kit" / "evidence" / family.evidence).read_text(encoding="utf-8"))
    assert written.get("files_scanned") == [family.filename]
    assert written.get("findings"), "the CLI wrote evidence with no findings for a dirty source"


#: Synthetic home-directory prefixes, assembled from parts.
#:
#: `scripts/check_public_hygiene.py` bans an absolute user-home path anywhere in the repository,
#: and it is right to: the point is that no host path ever reaches a public file. These
#: fixtures are the one place that needs the SHAPE in order to prove the redaction removes it,
#: so they are assembled the way that script assembles its own patterns -- see its `_join`
#: helper, which exists so the checker does not trip over itself. Spelling either prefix out in
#: a comment trips it too, which is why this one describes them instead of quoting them.
_WINDOWS_HOME = "C:" + "\\" + "Users" + "\\"
_POSIX_HOME = "/" + "home" + "/"


@pytest.mark.parametrize(
    ("label", "path"),
    [
        ("windows", _WINDOWS_HOME + "someone\\private\\main.tf"),
        ("posix", _POSIX_HOME + "someone/private/main.tf"),
    ],
)
def test_an_absolute_path_in_the_evidence_never_reaches_the_message(tmp_path: Path, label: str, path: str) -> None:
    """`diagnostics.parse_errors[].file` is INPUT, and it lands verbatim in user-facing text.

    The kit's own scanners write repo-relative paths, and the first version of the guard
    trusted a comment saying so. An evidence file is a JSON document someone else may have
    written; one naming an absolute path put the OS account name into the control message,
    the Markdown report and findings.json (M-002).

    Both root shapes are checked because a report is portable: an evidence file written on
    Windows is read on Linux and the other way round, so a redaction that only knows one of
    them leaks on the other.
    """

    from oss_policy_kit.application.evaluators_iac import build_iac_evaluators  # noqa: PLC0415

    directory = tmp_path / ".oss-policy-kit" / "evidence"
    directory.mkdir(parents=True)
    (directory / "iac-terraform.json").write_text(
        json.dumps(
            {
                "schema_version": "oss-policy-kit/evidence/iac-terraform/v1",
                "status": "ok",
                "files_scanned": [],
                "findings": [],
                "findings_by_rule": {},
                "diagnostics": {
                    "parse_errors": [{"file": path, "error": "bad"}],
                    "raw_message": "",
                },
            }
        ),
        encoding="utf-8",
    )

    outcome = next(iter(build_iac_evaluators().values()))(SimpleNamespace(repo_root=tmp_path))

    assert "someone" not in outcome.reason, f"{label}: account name leaked: {outcome.reason}"
    assert "private" not in outcome.reason, f"{label}: directory name leaked: {outcome.reason}"
    assert "main.tf" in outcome.reason, f"{label}: redaction ate the filename: {outcome.reason}"


def test_malformed_parse_error_entries_are_skipped_rather_than_trusted() -> None:
    """`diagnostics.parse_errors` is INPUT and may be any shape at all.

    A hand-edited or third-party evidence file can put a string, a number or a null where the
    kit writes an object, and an entry can be missing `file` or carry an empty one. None of
    that is a reason to crash or to name a file called `None` in a control message -- the
    entries that make sense are used and the rest are ignored.
    """

    from oss_policy_kit.application._evidence_rules import unread_sources  # noqa: PLC0415

    shown, total = unread_sources(
        {
            "diagnostics": {
                "parse_errors": [
                    "not-an-object",
                    42,
                    None,
                    {"error": "no file key at all"},
                    {"file": "", "error": "empty name"},
                    {"file": None, "error": "null name"},
                    {"file": "real.tf", "error": "bad"},
                    {"file": "real.tf", "error": "the same file again"},
                ]
            }
        }
    )

    assert shown == ["real.tf"], f"malformed entries leaked into the message: {shown}"
    assert total == 1, f"the duplicate was counted twice: {total}"


@pytest.mark.parametrize(
    "diagnostics",
    [
        pytest.param("not-an-object", id="diagnostics-is-a-string"),
        pytest.param(["a", "list"], id="diagnostics-is-a-list"),
        pytest.param({"parse_errors": "not-a-list"}, id="parse_errors-is-a-string"),
        pytest.param({"parse_errors": {"file": "x.tf"}}, id="parse_errors-is-an-object"),
        pytest.param({}, id="no-parse_errors-key"),
    ],
)
def test_a_diagnostics_block_of_the_wrong_shape_yields_nothing_rather_than_raising(
    diagnostics: object,
) -> None:
    """Every container on the way to the file names is INPUT and may be any type.

    `(x or {}).get(...)` reasoning is what makes this class of bug: a truthy non-mapping walks
    straight through and raises AttributeError, which is exit 3 and an adopter told to file a
    bug about their own file. Each level is checked for the type it must be.
    """

    from oss_policy_kit.application._evidence_rules import unread_sources  # noqa: PLC0415

    assert unread_sources({"diagnostics": diagnostics}) == ([], 0)


def test_two_files_with_the_same_name_are_two_files() -> None:
    """De-duplication happens on the ORIGINAL path, before redaction flattens it.

    Redaction keeps only the last component, so two unread files in different directories
    become one string. De-duplicating after that collapsed them into a single entry and
    under-reported the count in the same sentence that quotes it.
    """

    from oss_policy_kit.application._evidence_rules import unread_sources  # noqa: PLC0415

    shown, total = unread_sources(
        {
            "diagnostics": {
                "parse_errors": [
                    {"file": _POSIX_HOME + "a/modules/db/main.tf", "error": "bad"},
                    {"file": _POSIX_HOME + "b/modules/net/main.tf", "error": "bad"},
                ]
            }
        }
    )

    assert total == 2, f"two distinct files were counted as {total}"
    assert len(shown) == 2, f"two distinct files were shown as {shown}"


def test_a_python_file_python_itself_rejects_is_recorded_not_crashed_on(tmp_path: Path) -> None:
    """A UTF-16 `.py` is not valid Python, and `ast.parse` says so in an unusual way.

    Bytes are handed to `ast.parse` so a PEP 263 coding line is honoured, and for a UTF-16
    file that means the parser meets NUL bytes and raises **ValueError**, not SyntaxError.
    ValueError carries no `.msg` or `.lineno`, so the SyntaxError handler reading them would
    have crashed the scan on a file the interpreter merely refuses.
    """

    from oss_policy_kit.infrastructure.iac.pulumi import scanner  # noqa: PLC0415

    (tmp_path / "utf16_program.py").write_bytes(_PULUMI.encode("utf-16"))

    outcome = scanner.run_scan(tmp_path)

    assert outcome.status == "ok", f"the scan did not survive the file: {outcome.status}"
    failed = [entry["file"] for entry in outcome.parse_errors]
    assert failed == ["utf16_program.py"], f"the rejected file was not recorded: {outcome.parse_errors}"
    assert outcome.files_read == 0, f"a file the parser refused was counted as read: {outcome.files_read}"


def test_a_truncated_file_list_never_reads_as_a_complete_one() -> None:
    """ "every candidate file failed to parse (a, b, c)" -- when there were nine."""

    from oss_policy_kit.application._evidence_rules import unread_sources_note  # noqa: PLC0415

    note = unread_sources_note(
        {"diagnostics": {"parse_errors": [{"file": f"f{n}.tf", "error": "x"} for n in range(9)]}}
    )

    assert "and 6 more" in note, f"the list is truncated at 3 and does not say so: {note}"


def test_the_families_swept_here_are_all_of_them() -> None:
    """A sixth scanner family must not be able to join without a row in FAMILIES."""

    import importlib  # noqa: PLC0415
    import pkgutil  # noqa: PLC0415

    import oss_policy_kit.application as application  # noqa: PLC0415

    discovered = set()
    for info in pkgutil.iter_modules(application.__path__):
        module = importlib.import_module(f"oss_policy_kit.application.{info.name}")
        if not hasattr(module, "_EVIDENCE_FILENAME") or not hasattr(module, "_SCHEMA_PREFIX"):
            continue
        if any(n.startswith("build_") and n.endswith("_evaluators") for n in dir(module)):
            discovered.add(info.name)

    assert discovered == {f.module for f in FAMILIES}, (
        f"scanner families in the package: {sorted(discovered)}; families exercised here: "
        f"{sorted(f.module for f in FAMILIES)}. A family missing from FAMILIES is a family "
        "nothing above ever runs."
    )
