"""An SBOM shipped with a release has to be an inventory of the release.

`publish-pypi.yml` uploads `artifacts/sbom.cyclonedx.json` as a release asset. The step that
produces it does this:

    pip install --require-hashes -r .github/requirements/build-tools.txt
    python -m cyclonedx_py environment --of JSON -o artifacts/sbom.cyclonedx.json

`cyclonedx_py environment` inventories the environment it is pointed at, and with no path it takes
the current one -- which the preceding line just filled with the build tools. Measured against the
SBOM actually published with v10.0.15:

    61 components, all publishing toolchain (twine, build, keyring, SecretStorage, arrow, certifi)
    `oss-policy-kit` itself: absent
    `metadata.component`: absent, so the document never states what it is an inventory OF
    the wheel's real runtime closure (click, jsonschema, pyyaml, typer): absent

An adopter matching CVEs against that file scans the machine that did the publishing. The four
dependencies the wheel actually carries are not in it, and the product is not in it.

Measured alternative, which is what the fix does: run the same generator against a throwaway
environment that has the built wheel installed, from outside that environment so the generator's
own dependencies do not leak in. That yields 18 components -- `oss-policy-kit` plus its real
closure and their transitive dependencies. `syft` was also measured and rejected as the sole
answer: it binds `metadata.component` to the wheel with a sha256 digest, which is the better
subject declaration, but reports 0 components for a `.whl` it cannot resolve dependencies from.

The provenance leg is not affected and is sound: `actions/attest-build-provenance` already binds
to `dist/*`. This is specifically the SBOM.

Every workflow that generates an SBOM is held to the rule, not just the publishing one, so a
second generator cannot be added with the same defect.
"""

from __future__ import annotations

import re

import pytest
import yaml

from tests.conftest import ROOT

_WORKFLOWS = ROOT / ".github" / "workflows"

#: `python -m cyclonedx_py environment ...` in a `run:` block.
_GENERATOR = re.compile(r"cyclonedx_py\s+environment(?P<rest>[^\n]*)")


def _sbom_steps() -> list[tuple[str, str]]:
    """(workflow name, run script) for every step that generates a CycloneDX SBOM."""

    found: list[tuple[str, str]] = []
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (document.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                script = str(step.get("run", ""))
                if _GENERATOR.search(script):
                    found.append((path.name, script))
    return found


def test_at_least_one_workflow_generates_an_sbom() -> None:
    """A guard over an empty set passes for the wrong reason."""

    assert _sbom_steps(), "no workflow generates a CycloneDX SBOM any more; this guard proves nothing"


@pytest.mark.parametrize(
    "workflow,script", _sbom_steps(), ids=lambda v: v if isinstance(v, str) and v.endswith(".yml") else ""
)
def test_an_sbom_step_inventories_the_distribution_not_the_build_tools(workflow: str, script: str) -> None:
    """The generator must be pointed at an environment that holds the built distribution."""

    match = _GENERATOR.search(script)
    assert match is not None

    # The environment path is whatever sits between `environment` and the first flag. Stopping at
    # the first `-` matters: a first version filtered on `not token.startswith("-")` across the
    # whole argument list, which counted the VALUES of `--of JSON -o artifacts/…` as positional
    # arguments. A mutation deleting the real path sailed through it, because `JSON` looked like
    # a path to that check.
    arguments = match.group("rest").strip()
    positional: list[str] = []
    for token in arguments.split():
        if token.startswith("-"):
            break
        positional.append(token)
    assert positional, (
        f"{workflow}: `cyclonedx_py environment` is called with no environment path, so it "
        "inventories the current environment -- on this runner that is the build-tools install "
        "immediately above, not the artifact being released."
    )

    assert re.search(r"\bpip install\b[^\n]*dist/", script), (
        f"{workflow}: nothing installs the built distribution before the SBOM is generated, so "
        "whatever environment is inventoried cannot contain the artifact this SBOM claims to "
        "describe."
    )
