import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.db import get_engine, get_session, init_db, make_engine
from app.main import app

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
    init_db(engine)
    return engine


@pytest.fixture
def client(engine):
    def session_override():
        with Session(engine, expire_on_commit=False) as session:
            yield session

    def engine_override():
        return engine

    app.dependency_overrides[get_session] = session_override
    app.dependency_overrides[get_engine] = engine_override
    yield TestClient(app)
    app.dependency_overrides.clear()
