import asyncio

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.db import init_db, make_engine, set_engine
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


@pytest.fixture
def nmap_xml() -> str:
    return NMAP_XML


@pytest.fixture
def engine(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'api.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    return engine


@pytest.fixture
def client(engine):
    with TestClient(app) as test_client:
        yield test_client
