"""Verify Docker MCP Gateway selective tool catalog and startup whitelist."""

from pathlib import Path
import yaml

GATEWAY_DIR = Path(__file__).resolve().parents[3] / "gateway"


def test_gateway_catalog_selective_registration():
    with open(GATEWAY_DIR / "aipent.yaml", "r") as f:
        config = yaml.safe_load(f)
    kali_tools = {t["name"] for t in config["registry"]["kali"]["tools"]}
    assert "ffuf_scan" in kali_tools
    assert "katana_crawl" in kali_tools
    assert "nuclei_scan" in kali_tools


def test_gateway_start_script_tools_whitelist():
    content = (GATEWAY_DIR / "start.sh").read_text()
    for tool_name in ["ffuf_scan", "katana_crawl", "nuclei_scan"]:
        assert tool_name in content
