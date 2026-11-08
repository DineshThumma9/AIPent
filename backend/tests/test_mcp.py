import asyncio
import json

import pytest

from app import actions
from app.actions import executor
from app.adapters import nikto, nmap
from app.core.config import settings
from app.integrations import zap_guided
from app.integrations.mcp_client import normalise_text
from app.domain.models import Assessment, Step


def test_normalise_unwraps_spring_ai_strings_only():
    assert normalise_text(json.dumps("line one\nline two")) == "line one\nline two"
    assert normalise_text('{"site": []}') == '{"site": []}'
    assert normalise_text("plain nikto text") == "plain nikto text"


def test_zap_accepts_queue_and_direct_identifiers():
    assert zap_guided._job_id("Job ID: 42\nStatus: QUEUED") == "42"
    assert zap_guided._job_id("Operation ID: zop_123\nStrategy: http") == "zop_123"


def test_zap_status_understands_direct_mode():
    assert (
        zap_guided._status("Direct spider scan status:\nProgress: 100%\nCompleted: yes")
        == "SUCCEEDED"
    )
    assert (
        zap_guided._status("Direct spider scan status:\nProgress: 40%\nCompleted: no")
        == "RUNNING"
    )
    assert zap_guided._status("Status: SUCCEEDED\nJob ID: 1") == "SUCCEEDED"
    assert zap_guided._status("nothing useful") == "UNKNOWN"


def test_mcp_tool_call_is_the_approved_descriptor(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", True)
    monkeypatch.setattr(settings, "mcp_transport", "gateway")
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])

    tool, arguments = actions.mcp_tool_call(
        "recon_services", assessment, "127.0.0.1"
    )
    assert tool == "nmap_scan"
    assert arguments == {
        "target": "host.docker.internal",
        "flags": "-sV -Pn -T4 --top-ports 100 -oX -",
    }

    descriptor = actions.mcp_command("nikto_scan", assessment, "127.0.0.1")
    assert descriptor == [
        "mcp",
        "nikto_scan",
        json.dumps(
            {"target_url": "http://host.docker.internal:3000"}, sort_keys=True
        ),
    ]


def test_nmap_strips_leading_banner_and_trailing_stderr(nmap_xml):
    text = "Starting Nmap\n" + nmap_xml + "\n[Standard Error/Warnings]:\nwarning\n"
    drafts = nmap.scan(text, host_override="127.0.0.1")
    assert drafts
    assert all(draft.asset == "127.0.0.1" for draft in drafts)


def test_nikto_scan_handles_json_and_text():
    payload = json.dumps(
        {
            "host": "127.0.0.1",
            "port": 3000,
            "vulnerabilities": [{"id": "1", "msg": "Missing header", "url": "/"}],
        }
    )
    assert len(nikto.scan(payload, "127.0.0.1", 3000)) == 1

    text = (
        "- Nikto v2.6.0\n"
        "+ Target IP: 172.17.0.1\n"
        "+ Platform:           Unknown\n"
        "+ ERROR: Failed to check for updates: 403\n"
        "+ /: The anti-clickjacking X-Frame-Options header is not present.\n"
    )
    drafts = nikto.scan(text, "127.0.0.1", 3000)
    assert len(drafts) == 1
    assert "anti-clickjacking" in drafts[0].title


def test_zap_crawl_is_stopped_when_polling_times_out(monkeypatch):
    monkeypatch.setattr(zap_guided, "MAX_POLLS", 2)
    monkeypatch.setattr(zap_guided, "POLL_SECONDS", 0)

    calls = []

    class FakeGateway:
        async def call(self, name, arguments):
            calls.append(name)
            if name == "zap_crawl_start":
                return "Guided crawl started.\nOperation ID: op-1\nStrategy: http"
            if name == "zap_crawl_status":
                return (
                    "Direct spider scan status:\n"
                    "Progress: 10%\n"
                    "Completed: no\n"
                )
            if name == "zap_crawl_stop":
                return "Direct spider scan stopped.\nScan ID: op-1"
            raise AssertionError(f"unexpected call {name}")

    with pytest.raises(zap_guided.ZapWorkflowError, match="did not finish"):
        asyncio.run(
            zap_guided.run_zap_baseline(
                FakeGateway(), "http://127.0.0.1:3000", "test-key"
            )
        )

    assert calls.count("zap_crawl_status") == 2
    assert calls[-1] == "zap_crawl_stop"


def test_zap_start_failure_propagates():
    class FailingGateway:
        async def call(self, name, arguments):
            raise zap_guided.ZapWorkflowError("connection refused")

    with pytest.raises(zap_guided.ZapWorkflowError, match="connection refused"):
        asyncio.run(
            zap_guided.run_zap_baseline(
                FailingGateway(), "http://127.0.0.1:3000", "test-key"
            )
        )


def test_gateway_mapping_uses_fixed_arguments(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", True)
    monkeypatch.setattr(settings, "mcp_transport", "gateway")

    calls = []

    class FakeGateway:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def call(self, name, arguments):
            calls.append((name, arguments))
            return "<nmaprun/>"

    monkeypatch.setattr(executor, "GatewayClient", FakeGateway)
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
    argv = actions.mcp_command(
        "recon_services",
        assessment,
        "127.0.0.1",
        params={"ports": [3000], "timing": 3},
    )
    step = Step(
        assessment_id=1,
        seq=1,
        action="recon_services",
        target="127.0.0.1",
        argv=argv,
    )

    result = asyncio.run(
        executor._run_gateway("recon_services", assessment, "127.0.0.1", step)
    )

    assert result.text == "<nmaprun/>"
    assert calls == [
        (
            "nmap_scan",
            {
                "target": "host.docker.internal",
                "flags": "-sV -Pn -T3 -p 3000 -oX -",
            },
        )
    ]
    assert result.calls[0]["tool"] == "nmap_scan"
