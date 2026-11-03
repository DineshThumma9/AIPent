import pytest

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
