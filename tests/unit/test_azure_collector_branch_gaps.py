"""Branch-coverage gaps for azure_collector posture helpers (no httpx; tiny fake client)."""

from __future__ import annotations

from typing import Any

from oss_policy_kit.infrastructure.collectors import azure_collector as az


class _Resp:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return self._payload


class _Client:
    """Returns queued responses in order for successive .get() calls."""

    def __init__(self, responses: list[_Resp]) -> None:
        self._responses = responses
        self.base_url = "https://dev.azure.com/acme"

    def get(self, _url: str) -> _Resp:
        return self._responses.pop(0)


# --------------------------------------------------------------------------- #
# _service_endpoint_auth_kind scheme mapping
# --------------------------------------------------------------------------- #


def test_service_endpoint_auth_kind_variants() -> None:
    assert az._service_endpoint_auth_kind({"authorization": {"scheme": "ManagedServiceIdentity"}}) == "managed_identity"
    assert az._service_endpoint_auth_kind({"authorization": {"scheme": "Token"}}) == "secret"
    assert az._service_endpoint_auth_kind({"authorization": {"scheme": "Certificate"}}) == "certificate"
    assert az._service_endpoint_auth_kind({"authorization": {"scheme": "weird"}}) == "unknown"


# --------------------------------------------------------------------------- #
# _environment_has_approval_check (lines 175, 179)
# --------------------------------------------------------------------------- #


def test_environment_approval_check_unexpected_status_returns_none() -> None:
    client = _Client([_Resp(500)])
    assert az._environment_has_approval_check(client, "Proj", "5") is None


def test_environment_approval_check_value_not_list_returns_false() -> None:
    client = _Client([_Resp(200, {"value": "not-a-list"})])
    assert az._environment_has_approval_check(client, "Proj", "5") is False


def test_environment_approval_check_detects_approval() -> None:
    client = _Client([_Resp(200, {"value": [{"type": {"name": "Approval"}}]})])
    assert az._environment_has_approval_check(client, "Proj", "5") is True


# --------------------------------------------------------------------------- #
# _azure_service_connection_posture (lines 210, 222)
# --------------------------------------------------------------------------- #


def test_service_connection_posture_skips_non_dict_endpoint() -> None:
    client = _Client([_Resp(200, {"value": [123, "nope"]})])
    conns, posture, _note, status = az._azure_service_connection_posture(client, "Proj")
    assert conns == [] and posture["service_connection_restricted"] is False and status == 200


def test_service_connection_posture_no_endpoints() -> None:
    client = _Client([_Resp(200, {"value": []})])
    conns, posture, _note, _status = az._azure_service_connection_posture(client, "Proj")
    assert conns == [] and posture["service_connection_restricted"] is False


def test_service_connection_posture_non_200_status() -> None:
    client = _Client([_Resp(503)])
    conns, posture, note, status = az._azure_service_connection_posture(client, "Proj")
    assert conns == [] and status == 503 and "503" in note
