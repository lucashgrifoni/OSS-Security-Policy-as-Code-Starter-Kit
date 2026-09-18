"""The release SBOM listed a vulnerability count that belonged to its own scaffolding.

`cyclonedx_py environment` inventories a virtualenv, and `python -m venv` puts pip inside one.
The SBOM published with v10.0.23 therefore carried `pip==25.0.1` as a second ROOT of its
dependency graph, beside `oss-policy-kit==10.0.23`, and `trivy sbom` on that published asset
reported six CVEs, all six against that pip and none against anything the wheel depends on.
Measured on the downloaded asset: `metadata.component` absent, 17 components, graph roots
`['oss-policy-kit==10.0.23', 'pip==25.0.1']`.

Two consequences, and the second is the worse one. An adopter who scans the SBOM has to
disprove six findings before trusting any of it. And the document declared no subject at all,
so nothing in the file said what it was an inventory OF; the release appeared as one library
among the others.

The project had already closed this exact leak in the runtime image, which ships no pip. The
workflow comment beside the step even records an earlier round of the same fight, 61 components
down to 18. It was reduced, not closed.

This guard reads the RECIPE rather than an artifact, because the SBOM is generated during
publication and never committed. That is a weaker check than inspecting the document, and it
is the strongest one available before a tag exists. The three flags below are each load
bearing, and each was verified locally against a real generated SBOM before being required
here: with them, the inventory has one root, no pip, and a declared subject.
"""

from __future__ import annotations

import re

import yaml
from tests.conftest import ROOT

PUBLISH = ROOT / ".github" / "workflows" / "publish-pypi.yml"


def _sbom_step() -> str:
    """The COMMANDS of the step that generates the release SBOM, with its comments removed.

    Comments are stripped because the first version of this guard did not strip them, and the
    step carries a comment block explaining why each flag is there. Deleting `--pyproject` and
    `--mc-type` from the command left the guard green: it was matching the sentence that names
    them. Only a mutation test showed it, and a check satisfied by its own rationale is worth
    nothing -- the same shape that let a documented `--build-arg` outlive the argument, and
    that a docs guard hit again the same afternoon.
    """

    data = yaml.safe_load(PUBLISH.read_text(encoding="utf-8")) or {}
    for job in (data.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            body = step.get("run")
            if isinstance(body, str) and "cyclonedx_py" in body:
                return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
    raise AssertionError("no step in publish-pypi.yml generates an SBOM")


def test_the_sbom_environment_does_not_bundle_pip() -> None:
    """Without this, pip is inventoried as part of the release and carries its own CVEs."""

    body = _sbom_step()

    assert re.search(r"venv\s+--without-pip\b", body), (
        "the SBOM venv is created with pip inside it, which puts pip in the published inventory "
        "as a second dependency-graph root; that is what made v10.0.23's SBOM report six CVEs "
        "that belong to no dependency of the wheel"
    )


def test_the_wheel_is_installed_from_outside_that_environment() -> None:
    """The other half: a pip-free venv cannot install into itself."""

    body = _sbom_step()

    assert re.search(r"pip\s+--python\s+\S*\.sbom-env\S*\s+install", body), (
        "nothing installs the distribution into the pip-free SBOM environment; "
        "`python -m pip --python <interpreter> install` drives it from the outer pip"
    )


def test_the_sbom_declares_what_it_is_an_inventory_of() -> None:
    """`metadata.component`. Absent on the published 10.0.23 document."""

    body = _sbom_step()

    assert "--pyproject" in body and "--mc-type" in body, (
        "the SBOM is generated without a main component, so `metadata.component` is absent and "
        "the document names no subject; the release then appears as one library among its own "
        "dependencies"
    )


def test_the_step_this_guard_reads_is_the_real_one() -> None:
    """Anti-vacuum: every assertion above passes against an empty string."""

    body = _sbom_step()

    assert "cyclonedx_py environment" in body, "the parsed step does not generate an SBOM"
    assert "artifacts/sbom.cyclonedx.json" in body, (
        "the parsed step does not write the release asset this guard is about"
    )
