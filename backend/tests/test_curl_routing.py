"""curl_request must hit the scoped endpoint through the transport alias."""

import pytest

from app.actions import catalogue
from app.domain.models import Assessment


def _assessment(ports: list[int] | None = None) -> Assessment:
    return Assessment(title="Lab", targets=["127.0.0.1"], ports=ports or [3000])


def _args(params: dict, assessment: Assessment | None = None) -> dict:
    _, arguments = catalogue.mcp_tool_call(
        "curl_request", assessment or _assessment(), "127.0.0.1", params=params
    )
    return arguments


def test_relative_path_uses_transport_alias():
    alias = catalogue.transport_target("127.0.0.1")

    assert _args({"url": "/basket/1"})["url"] == f"http://{alias}:3000/basket/1"


def test_bare_path_gets_leading_slash():
    alias = catalogue.transport_target("127.0.0.1")

    assert _args({"path": "rest/products"})["url"] == (
        f"http://{alias}:3000/rest/products"
    )


def test_absolute_url_is_rebuilt_on_scoped_host():
    alias = catalogue.transport_target("127.0.0.1")

    args = _args({"url": "http://localhost:3000/rest/user/login?email=a@b.c"})

    assert args["url"] == f"http://{alias}:3000/rest/user/login?email=a@b.c"


def test_absolute_url_rejects_out_of_scope_host():
    with pytest.raises(catalogue.ScopeError):
        _args({"url": "http://evil.example/basket/1"})


def test_absolute_url_keeps_assessed_port():
    args = _args(
        {"url": "http://127.0.0.1:8080/admin"},
        _assessment(ports=[3000, 8080]),
    )

    assert args["url"].endswith(":8080/admin")
