"""Redaction must never turn a token from an evidence file into a network operation.

`_sanitize_target_path_for_payload` resolved every rooted token it was handed, and on Windows
`Path.resolve()` on `\\\\server\\share` asks the network for that share. Two of the strings
reaching it are not the operator's own: a finding `message` and a finding `location.file` come
out of an ingested SARIF, so the destination was chosen by the evidence rather than by the
person running the audit.

Measured on this tree through `correlate-findings`, with a SARIF holding one crafted message:

    clean message          1.0s
    one UNC token         22.0s
    five UNC tokens      190.4s

Linear, about 38 seconds per distinct destination, and the command still exits 0. Pointing a
token at a literal IP -- no name lookup in play -- blocked for 21 seconds, which is what pins
the cost on an outbound connection attempt rather than on slow resolution.

The assertions here are deliberately NOT timed. A wall-clock ceiling is the same shape of
guard that made this suite flake in the first place, and it would fail for the wrong reason on
a loaded runner. The oracle is stronger and deterministic instead: `Path.resolve` is made to
raise, and the sanitizer must still answer. A guard that only measured seconds could not tell
"we did not dial" from "the machine was fast today".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.reporting import (
    _sanitize_embedded_path_in_text,
    _sanitize_target_path_for_payload,
)

B = "\\"

#: Every spelling a document can carry that Windows reads as a UNC drive. `//a/b`, `\\a\b`,
#: `/\a/b` and `\/a/b` all parse to the drive `\\a\b`, so covering only the `//` form would
#: leave three quarters of the reachable inputs uncovered.
UNC_FORMS = (
    "//servidor/partilha/evidence.json",
    B + B + "servidor" + B + "partilha" + B + "evidence.json",
    "/" + B + "servidor/partilha/evidence.json",
    B + "/servidor/partilha/evidence.json",
    "//192.0.2.1/partilha/evidence.json",
)


@pytest.fixture
def resolve_is_a_trap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any filesystem resolution loud, so reaching one fails the test by name."""

    def trap(self: Path, *args: object, **kwargs: object) -> Path:
        raise AssertionError(f"Path.resolve() was called on {str(self)!r}; redaction must stay lexical")

    monkeypatch.setattr(Path, "resolve", trap)


@pytest.mark.parametrize("token", UNC_FORMS)
def test_a_unc_token_is_redacted_without_resolving_it(token: str, resolve_is_a_trap: None) -> None:
    """The whole finding: a UNC-shaped token must never reach the filesystem."""

    assert _sanitize_target_path_for_payload(token, include_absolute=False) == "evidence.json"


@pytest.mark.parametrize("token", UNC_FORMS)
def test_a_unc_token_inside_prose_is_redacted_without_resolving_it(token: str, resolve_is_a_trap: None) -> None:
    """The reachable path is prose, not a bare token: a SARIF `message` is a sentence."""

    text = f"Hardcoded credential detected in {token} line 1."

    out = _sanitize_embedded_path_in_text(text, include_absolute=False)

    assert out == "Hardcoded credential detected in evidence.json line 1."


@pytest.mark.parametrize("token", UNC_FORMS)
def test_the_server_name_does_not_survive_into_the_report(token: str, resolve_is_a_trap: None) -> None:
    """Not dialling is half of it; the other half is that the destination is not published.

    A UNC path names a host. That is the same class of internal detail M-002 keeps out of a
    shareable report, so the redaction has to hold as well as the guard.
    """

    out = _sanitize_embedded_path_in_text(f"seen at {token} today", include_absolute=False)

    assert "servidor" not in out
    assert "192.0.2.1" not in out
    assert "partilha" not in out


def test_an_ordinary_path_is_still_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard must not quietly switch every path to the lexical branch.

    Without this, deleting the `try` block entirely would pass every test above -- and the
    `cwd` case, which is the reason the resolution exists at all, would be gone.
    """

    chamadas: list[str] = []
    real = Path.resolve

    def spy(self: Path, *args: object, **kwargs: object) -> Path:
        chamadas.append(str(self))
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", spy)

    _sanitize_target_path_for_payload("/usr/local/share/evidence.json", include_absolute=False)

    assert chamadas, "an ordinary rooted path must still go through resolution"


def test_the_current_directory_still_collapses_to_a_dot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The behaviour the resolution exists for, held against the guard."""

    monkeypatch.chdir(tmp_path)

    assert _sanitize_target_path_for_payload(str(tmp_path), include_absolute=False) == "."


def test_a_unc_token_is_untouched_when_the_operator_asked_for_absolute_paths() -> None:
    """`--include-absolute-path` is an explicit opt-in and keeps meaning what it says."""

    token = "//servidor/partilha/evidence.json"

    assert _sanitize_target_path_for_payload(token, include_absolute=True) == token


@pytest.mark.parametrize(
    "token",
    [
        "/usr/local/share/evidence.json",
        "C:/temp/evidence.json",
        "C:" + B + "temp" + B + "evidence.json",
        "~/docs/evidence.json",
    ],
)
def test_an_ordinary_path_is_not_mistaken_for_a_network_location(token: str) -> None:
    """A guard that fired on everything would be indistinguishable from one that fired here."""

    assert _sanitize_target_path_for_payload(token, include_absolute=False) == "evidence.json"
