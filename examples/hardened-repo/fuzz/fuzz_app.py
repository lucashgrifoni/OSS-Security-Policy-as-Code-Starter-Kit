"""Minimal atheris fuzz harness for the synthetic hardened-repo fixture.

Demonstrates SEC-FUZZ-001 posture: a fuzz harness is committed under
``fuzz/`` so the kit's clone-visible signal can detect it.
"""

from __future__ import annotations

import sys

import atheris


def TestOneInput(data: bytes) -> None:
    # Real harnesses exercise the SUT; this stub keeps the fixture cheap.
    if len(data) > 0 and data[0] == 0xFF:
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
