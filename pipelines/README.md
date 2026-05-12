# pipelines/

This directory holds CI configurations that the project itself runs on platforms other than GitHub Actions. It is **not** a folder of examples or templates for consumers of the kit — those live under `examples/` (functional repos) and `templates/` (drop-in YAML).

## What is here

### `azure/azure-pipelines.yml`

The project's own Azure DevOps pipeline. It mirrors a subset of the GitHub Actions self-check so the same repo can be built, tested, scanned, and packaged from a self-hosted Azure DevOps agent. Stages: `quality` (ruff, mypy, pytest, bandit, pip-audit, hardened-example evaluate, self-check evaluate) and `package` (build sdist+wheel, twine check, CycloneDX SBOM, wheel-install smoke).

The Azure DevOps build definition references this exact path (`pipelines/azure/azure-pipelines.yml`). Do not move or rename it without first updating the build definition in Azure DevOps.

## What is NOT here

- Templates you would drop into your own repository to evaluate it with the kit — see `templates/workflows/`.
- Examples of fully-hardened or intentionally-vulnerable repos — see `examples/hardened-repo/` and `examples/vulnerable-repo/`.
