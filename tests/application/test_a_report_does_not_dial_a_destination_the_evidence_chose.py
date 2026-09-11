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
a loaded runner. The oracle is stronger and deterministic instead: `Path.resolve` is spied on,
and it must not be called at all. A guard that only measured seconds could not tell "we did not
dial" from "the machine was fast today".

SECOND PASS, and the reason the rule here reversed direction. The first version of this guard
refused to resolve tokens matching the UNC SHAPE, and this file asserted that an ordinary
rooted path must still be resolved -- which kept the dangerous call alive one branch further
down. A drive letter mapped to a share (`Z:` -> `\\\\host\\share`) and a path crossing a
junction are both network destinations that no UNC pattern matches, and both reached
`Path.resolve()` under that rule. The mistake was scoping the guard to what the token looked
like instead of to where the value came from; these strings are written by whoever the audited
repository lets write them, so no shape among them is trustworthy.

The property is now the one that needs no taxonomy: **this code never touches the filesystem.**
`os.path.abspath` is normpath composed with a join against the working directory and answers
the `cwd` question lexically, so the behaviour the resolution existed for is kept -- see
`test_the_current_directory_still_collapses_to_a_dot`, which is unchanged and still passes.
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


@pytest.mark.parametrize(
    "token",
    [
        "/usr/local/share/evidence.json",  # ordinary rooted path
        "//servidor/partilha/evidence.json",  # UNC
        "Z:\\mapped\\evidence.json",  # a drive letter that may be a share
        "D:\\builds\\out\\evidence.json",  # ordinary Windows path, deliberately not under a home
        # directory: the public-hygiene check forbids home-shaped literals in shipped files, and
        # it is right to -- one of those is how an account name reaches a published report.
        "relative/evidence.json",
        ".",
        "",
    ],
)
def test_no_input_is_ever_resolved(token: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing reaching this function goes through the filesystem, whatever it looks like.

    This replaces a test that asserted the opposite -- that an ordinary rooted path must still
    be resolved -- and the replacement is deliberate, because that assertion encoded a mistake.

    The first version of this guard refused to resolve tokens that LOOKED like UNC, and left
    the branch after it resolving the same string. What makes resolving dangerous here is not
    the shape of the token but where it came from: a finding `message` and a finding
    `location.file` are written by whoever the audited repository let write them. A drive
    letter mapped to a share, and a path crossing a junction, are both network destinations
    with no UNC in sight, and both went to `Path.resolve()` under the old rule.

    So the property is now the stronger one, and it needs no taxonomy of dangerous shapes:
    **this function never touches the filesystem.** `os.path.abspath` is normpath composed with
    a join against the working directory, which answers the same question lexically.
    """

    chamadas: list[str] = []
    real = Path.resolve

    def spy(self: Path, *args: object, **kwargs: object) -> Path:
        chamadas.append(str(self))
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", spy)

    _sanitize_target_path_for_payload(token, include_absolute=False)

    assert not chamadas, f"resolution reached the filesystem for {token!r}: {chamadas}"


def test_the_embedded_text_path_does_not_resolve_either(monkeypatch: pytest.MonkeyPatch) -> None:
    """The free-text sanitizer feeds the same function, so it inherits the same property.

    Worth its own test: this is the surface an ingested SARIF actually arrives through, and a
    future change could give it a resolving path of its own without touching the function above.
    """

    chamadas: list[str] = []
    real = Path.resolve

    def spy(self: Path, *args: object, **kwargs: object) -> Path:
        chamadas.append(str(self))
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", spy)

    _sanitize_embedded_path_in_text(
        "found at //servidor/partilha/x.json and at Z:\\mapped\\y.json and /tmp/z.json",
        include_absolute=False,
    )

    assert not chamadas, f"resolution reached the filesystem: {chamadas}"


def test_the_sanitizer_still_answers_when_the_working_directory_is_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fallback branch, which is reachable through `os.getcwd` rather than through the path.

    `os.path.abspath` does not raise on the inputs `Path.resolve` used to choke on -- a NUL byte
    goes straight through it -- so the only way into the fallback is the working directory
    itself failing, which happens when the directory a process is running in has been removed.
    A report should still be written in that case rather than the run dying inside a redactor.
    """

    def gone() -> str:
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr("oss_policy_kit.application.reporting.os.getcwd", gone)

    assert (
        _sanitize_target_path_for_payload("/usr/local/share/evidence.json", include_absolute=False) == "evidence.json"
    )


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
