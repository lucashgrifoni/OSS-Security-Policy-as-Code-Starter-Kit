"""`files_scanned` is a claim that a Kubernetes manifest was examined, not a count of files opened.

Downstream a non-empty `files_scanned` with no findings reads as "there was Kubernetes here and
it was clean". The list was built as discovery minus parse failures, so any YAML that parsed
landed in it -- including documents `_manifest_from_doc` had already rejected for having no
`apiVersion` and no `kind`.

Measured against the built wheel in a clean room, on a repository whose only YAML is the
workflow `init --with-workflow` writes:

    scan-k8s   files_scanned = [".github/workflows/ci.yml"], findings = []
    evaluate   kubernetes-baseline-1 -> 17 of 17 PASS
    --fail-on fail -> exit 0

Seventeen controls stating a Kubernetes posture for a repository with no Kubernetes in it, and
a green gate. After: `files_scanned = []` and sixteen `not-applicable`, which is a true statement
about that repository.

This is the second round of the same defect. The list was once the DISCOVERED files, so a
manifest saved as UTF-16 that failed to parse counted as scanned; that round removed parse
failures. What it left was the much larger set -- every file that parses perfectly and is not a
manifest, which in a real repository means every workflow, every compose file, every CI config.

The tests below therefore fix both halves: nothing that is not a manifest may enter the list,
and everything that is one still must.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.k8s.scanner import run_scan

_PRIVILEGED_POD = """apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
"""

#: Every one of these parses as YAML and none of them is a Kubernetes manifest. They are the
#: ordinary contents of a repository, not exotic inputs.
NOT_MANIFESTS = {
    "workflow": (
        ".github/workflows/ci.yml",
        "name: ci\non:\n  push:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    ),
    "compose": ("docker-compose.yml", "services:\n  web:\n    image: nginx\n    ports:\n      - '80:80'\n"),
    "dependabot": (
        ".github/dependabot.yml",
        "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n    schedule:\n      interval: weekly\n",
    ),
    "openapi": ("api.yaml", "openapi: 3.0.0\ninfo:\n  title: x\n  version: '1'\npaths: {}\n"),
    "kind but no apiVersion": ("half.yaml", "kind: Pod\nmetadata:\n  name: x\n"),
    "apiVersion but no kind": ("other-half.yaml", "apiVersion: v1\nmetadata:\n  name: x\n"),
    "a bare list": ("list.yaml", "- one\n- two\n"),
    "a bare scalar": ("scalar.yaml", "just a string\n"),
}


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(("label", "pair"), sorted(NOT_MANIFESTS.items()), ids=sorted(NOT_MANIFESTS))
def test_a_file_that_is_not_a_manifest_is_not_reported_as_scanned(
    label: str, pair: tuple[str, str], tmp_path: Path
) -> None:
    """Each of these parses cleanly and carries no Kubernetes. None may be claimed as scanned."""

    rel, body = pair
    outcome = run_scan(_repo(tmp_path, {rel: body}))

    assert outcome.files_scanned == [], f"{label} was reported as a scanned manifest"
    assert outcome.findings == []
    assert outcome.parse_errors == [], "it parsed fine, so it is not a parse failure either"


def test_a_repository_of_nothing_but_non_manifests_claims_nothing(tmp_path: Path) -> None:
    """The shape that shipped: every ordinary YAML at once, and not one of them Kubernetes."""

    outcome = run_scan(_repo(tmp_path, dict(NOT_MANIFESTS.values())))

    assert outcome.files_scanned == []
    assert outcome.status == "ok", "answering nothing is not the same as failing"


# --- the half that must not be lost -------------------------------------------------------------


def test_a_real_manifest_is_still_scanned_and_still_reported(tmp_path: Path) -> None:
    """The regression this fix could have caused, and the reason the rule is `apiVersion` + `kind`."""

    outcome = run_scan(_repo(tmp_path, {"k8s/pod.yaml": _PRIVILEGED_POD}))

    assert outcome.files_scanned == ["k8s/pod.yaml"]
    assert outcome.findings, "a pod declaring privileged: true must still be found"


def test_a_manifest_beside_a_workflow_is_found_and_the_workflow_is_not_claimed(tmp_path: Path) -> None:
    """The realistic repository: a little Kubernetes and a lot of other YAML."""

    files = dict(NOT_MANIFESTS.values())
    files["k8s/pod.yaml"] = _PRIVILEGED_POD
    outcome = run_scan(_repo(tmp_path, files))

    assert outcome.files_scanned == ["k8s/pod.yaml"]
    assert outcome.findings


def test_several_manifests_in_one_file_count_that_file_once(tmp_path: Path) -> None:
    """A multi-document YAML is one file, however many manifests it carries."""

    two = _PRIVILEGED_POD + "---\n" + _PRIVILEGED_POD.replace("name: bad", "name: alsobad")
    outcome = run_scan(_repo(tmp_path, {"k8s/both.yaml": two}))

    assert outcome.files_scanned == ["k8s/both.yaml"]


def test_a_manifest_among_documents_that_are_not_manifests_still_counts(tmp_path: Path) -> None:
    """One real manifest in a multi-document file is enough to have scanned that file."""

    mixed = "just: a mapping\n---\n" + _PRIVILEGED_POD + "---\n- a list\n"
    outcome = run_scan(_repo(tmp_path, {"k8s/mixed.yaml": mixed}))

    assert outcome.files_scanned == ["k8s/mixed.yaml"]
    assert outcome.findings


def test_an_unreadable_manifest_is_a_parse_error_and_not_a_scan(tmp_path: Path) -> None:
    """The first round of this defect, kept as a test so it cannot come back.

    A file that fails to parse is neither scanned nor absent: it is a recorded failure, and the
    distinction is what stops sixteen controls going clean over a manifest nobody could read.
    """

    outcome = run_scan(_repo(tmp_path, {"k8s/broken.yaml": "a:\n  - b\n c: broken indent\n"}))

    assert outcome.files_scanned == []
    assert outcome.parse_errors, "an unreadable file must be recorded, not silently dropped"


# --- the fact narrowing the list took away ------------------------------------------------------
#
# `files_scanned` was answering two questions: "is there Kubernetes here" and "did I manage to
# look at anything". Once it means only the first, `absent_technology_outcome` loses its basis
# for the second and withdraws sixteen controls from a repository that simply has no Kubernetes
# -- the over-withdrawal that guard's own docstring records from its first attempt.
#
# `scan-cfn` and `scan-pulumi` already emit `diagnostics.files_read` for exactly this reason,
# because their `files_scanned` is narrowed the same way. This scanner now agrees with them.


def test_files_read_counts_what_parsed_not_what_held_a_manifest(tmp_path: Path) -> None:
    outcome = run_scan(_repo(tmp_path, dict(NOT_MANIFESTS.values())))

    assert outcome.files_scanned == [], "none of them is Kubernetes"
    assert outcome.files_read == len(NOT_MANIFESTS), "but every one of them was read"


def test_files_read_excludes_what_could_not_be_parsed(tmp_path: Path) -> None:
    files = {"ordinary.yaml": "services:\n  web:\n    image: nginx\n"}
    _repo(tmp_path, files)
    (tmp_path / "broken.yaml").write_bytes(bytes(range(256)) * 4)

    outcome = run_scan(tmp_path)

    assert outcome.files_read == 1, "one parsed, one did not"
    assert outcome.parse_errors


def test_files_read_is_zero_when_the_only_candidate_is_unreadable(tmp_path: Path) -> None:
    """The case that MUST still withdraw: nothing legible is not the same as nothing here."""

    (tmp_path / "only.yaml").write_bytes(bytes(range(256)) * 4)

    outcome = run_scan(tmp_path)

    assert outcome.files_read == 0
    assert outcome.files_scanned == []
    assert outcome.parse_errors


def test_the_evidence_carries_files_read_where_the_siblings_carry_it(tmp_path: Path) -> None:
    """Under `diagnostics`, the key `_files_read` reads, and the one cfn and pulumi write."""

    from oss_policy_kit.infrastructure.k8s.scanner import render_evidence_payload

    outcome = run_scan(_repo(tmp_path, {"docker-compose.yml": "services:\n  web:\n    image: nginx\n"}))
    payload = render_evidence_payload(outcome, target=tmp_path)

    assert payload["diagnostics"]["files_read"] == 1
    assert payload["files_scanned"] == []
