import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.main import app


@pytest.fixture(autouse=True)
def _local_transport(monkeypatch):
    """Unit tests never dial a live gateway, even if .env enables MCP."""
    monkeypatch.setattr(settings, "mcp_enabled", False)
    monkeypatch.setattr(settings, "mcp_transport", "local")


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open"/>
        <service name="ppp"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NIKTO_JSON = """{
  "host": "127.0.0.1",
  "port": 3000,
  "vulnerabilities": [
    {
      "id": "999957",
      "msg": "The anti-clickjacking X-Frame-Options header is not present.",
      "url": "/",
      "method": "GET"
    },
    {
      "id": "999103",
      "msg": "The X-Content-Type-Options header is not set.",
      "url": "/",
      "method": "GET"
    }
  ]
}"""

SQLMAP_OUTPUT = """sqlmap identified the following injection point(s) with a total of 91 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=apple' AND 1=1--
---
[INFO] the back-end DBMS is SQLite
"""

ZAP_JSON = """{
  "site": [
    {
      "name": "http://127.0.0.1:3000",
      "alerts": [
        {
          "pluginid": "10038",
          "alert": "CSP Header Not Set",
          "riskcode": "2",
          "confidence": "3",
          "desc": "Content Security Policy header is missing.",
          "solution": "Set a Content-Security-Policy header.",
          "instances": [
            {
              "uri": "http://127.0.0.1:3000/",
              "method": "GET",
              "param": "",
              "evidence": "Content-Security-Policy"
            }
          ]
        }
      ]
    }
  ]
}"""


@pytest.fixture
def nmap_xml() -> str:
    return NMAP_XML


@pytest.fixture
def sample_nmap_xml() -> str:
    return NMAP_XML


@pytest.fixture
def sample_nikto_json() -> str:
    return NIKTO_JSON


@pytest.fixture
def sample_sqlmap_output() -> str:
    return SQLMAP_OUTPUT


@pytest.fixture
def sample_zap_json() -> str:
    return ZAP_JSON


@pytest.fixture
def engine(tmp_path):
    test_engine = make_engine(f"sqlite:///{tmp_path / 'api.db'}")
    asyncio.run(init_db(test_engine))
    set_engine(test_engine)
    return test_engine


@pytest.fixture
async def db_session(engine):
    async with get_async_session_ctx() as session:
        yield session


@pytest.fixture
def client(engine):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def test_client(client):
    return client
