"""Adapters that orchestrate external scanners (SAST, SCA, secrets, IaC).

Each adapter is a thin process boundary around a third-party tool that
normalizes the tool's native output into the kit's evidence shape. The
adapters are intentionally optional dependencies: missing tools degrade
gracefully (status ``not_available``) instead of crashing the CLI.
"""
