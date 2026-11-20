"""Batched curl_request: descriptor, execution, budget, and observation."""

from __future__ import annotations

import asyncio
import json

import pytest
from sqlmodel import select

from app.actions import executor, mcp_command
from app.actions.evidence import excerpt_for, locator_for
from app.agents.loop.observations import observation_from_step
from app.agents.loop.tool_specs import CurlArgs
from app.cli import _argv_preview, _curl_batch_requests
from app.core.config import settings
from app.core.db import get_async_session_ctx, init_db, make_engine, set_engine
from app.domain.models import Assessment, Audit, Step, StepStatus
from app.persistence import StepRepo
from app.persistence.step_repo import _step_matches


@pytest.fixture
def engine(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'curl-batch.db'}")
    asyncio.run(init_db(engine))
    set_engine(engine)
    return engine


def _run_with_session(coro_fn):
    async def runner():
        async with get_async_session_ctx() as session:
            return await coro_fn(session)

    return asyncio.run(runner())


async def _assessment(session) -> Assessment:
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
    session.add(assessment)
    await session.commit()
    await session.refresh(assessment)
    return assessment


def test_curl_args_accept_three_requests_and_reject_four():
    three = CurlArgs(
        target="127.0.0.1",
        rationale="probe independent endpoints",
        requests=[
            {"path": "/login", "method": "GET"},
            {"path": "/admin", "method": "HEAD"},
            {"path": "/search?q=x", "method": "GET"},
        ],
    )
    assert len(three.requests) == 3

    with pytest.raises(ValueError):
        CurlArgs(
            target="127.0.0.1",
            rationale="too many",
            requests=[
                {"path": "/a"},
                {"path": "/b"},
                {"path": "/c"},
                {"path": "/d"},
            ],
        )


def test_batch_descriptor_builds_three_gateway_requests(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", True)
    monkeypatch.setattr(settings, "mcp_transport", "gateway")
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])

    argv = mcp_command(
        "curl_request",
        assessment,
        "127.0.0.1",
        params={
            "requests": [
                {"path": "/login", "method": "GET"},
                {"path": "/admin", "method": "HEAD"},
                {"path": "/search?q=x", "method": "GET"},
            ]
        },
    )

    assert argv[0] == "mcp"
    assert argv[1] == "curl_request"
    args = json.loads(argv[2])
    assert [item["method"] for item in args["batch"]] == ["GET", "HEAD", "GET"]
    assert [item["url"].split(":3000", 1)[1] for item in args["batch"]] == [
        "/login",
        "/admin",
        "/search?q=x",
    ]


def test_batch_descriptor_rejects_unsafe_method_and_too_many(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", True)
    monkeypatch.setattr(settings, "mcp_transport", "gateway")
    assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])

    with pytest.raises(ValueError, match="GET, HEAD, or OPTIONS"):
        mcp_command(
            "curl_request",
            assessment,
            "127.0.0.1",
            params={"requests": [{"path": "/login", "method": "POST"}]},
        )

    with pytest.raises(ValueError, match="at most 3"):
        mcp_command(
            "curl_request",
            assessment,
            "127.0.0.1",
            params={"requests": [{"path": f"/{i}"} for i in range(4)]},
        )


def test_batch_execution_preserves_order_and_partial_failure(monkeypatch):
    class FakeGateway:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def call(self, name, arguments):
            if arguments["url"].endswith("/bad"):
                raise RuntimeError("gateway timed out")
            return json.dumps(
                {
                    "ok": True,
                    "code": 200,
                    "response": {"status_code": 200, "body": "ok"},
                }
            )

    monkeypatch.setattr(executor, "GatewayClient", FakeGateway)

    result = asyncio.run(
        executor._run_curl_batch(
            [
                {"url": "http://127.0.0.1:3000/one", "method": "GET"},
                {"url": "http://127.0.0.1:3000/bad", "method": "GET"},
                {"url": "http://127.0.0.1:3000/three", "method": "GET"},
            ]
        )
    )

    payload = json.loads(result.text)
    assert [entry["index"] for entry in payload["results"]] == [0, 1, 2]
    assert payload["results"][0]["result"]["code"] == 200
    assert "gateway timed out" in payload["results"][1]["error"]
    assert payload["results"][2]["result"]["code"] == 200
    assert len(result.calls) == 3
    assert executor._curl_tool_error(result.text) is None


def test_batch_execution_fails_only_when_every_request_fails(monkeypatch):
    class FailingGateway:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def call(self, name, arguments):
            raise RuntimeError("no route to host")

    monkeypatch.setattr(executor, "GatewayClient", FailingGateway)

    result = asyncio.run(
        executor._run_curl_batch(
            [
                {"url": "http://127.0.0.1:3000/one", "method": "GET"},
                {"url": "http://127.0.0.1:3000/two", "method": "GET"},
            ]
        )
    )

    assert "all batch requests failed" in (executor._curl_tool_error(result.text) or "")


def test_batch_observation_summarises_each_result(engine, tmp_path):
    async def body(session):
        assessment = await _assessment(session)
        path = tmp_path / "batch.curl.json"
        path.write_text(
            json.dumps(
                {
                    "batch": True,
                    "results": [
                        {
                            "index": 0,
                            "request": {
                                "url": "http://127.0.0.1:3000/login",
                                "method": "GET",
                            },
                            "result": {
                                "ok": True,
                                "code": 401,
                                "response": {
                                    "status_code": 401,
                                    "headers": {},
                                    "body": "denied",
                                },
                            },
                        },
                        {
                            "index": 1,
                            "request": {
                                "url": "http://127.0.0.1:3000/search?q=x",
                                "method": "GET",
                            },
                            "result": {
                                "ok": True,
                                "code": 200,
                                "response": {
                                    "status_code": 200,
                                    "headers": {},
                                    "body": json.dumps(
                                        {"data": [{"id": i} for i in range(3)]}
                                    ),
                                },
                            },
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        step = Step(
            assessment_id=assessment.id,
            seq=1,
            action="curl_request",
            target="127.0.0.1",
            status=StepStatus.SUCCEEDED.value,
            output_path=str(path),
        )
        session.add(step)
        await session.commit()
        await session.refresh(step)

        obs = await observation_from_step(session, step)

        assert obs.facts is not None
        results = obs.facts["results"]
        assert [item["status_code"] for item in results] == [401, 200]
        assert results[1]["json_items"] == 3
        assert "#0" in obs.summary and "#1" in obs.summary
        assert "authentication" in (obs.next_hint or "")

    _run_with_session(body)


def test_batch_evidence_locator_prefers_a_successful_result(tmp_path):
    path = tmp_path / "batch.curl.json"
    path.write_text(
        json.dumps(
            {
                "batch": True,
                "results": [
                    {
                        "index": 0,
                        "request": {
                            "url": "http://127.0.0.1:3000/admin",
                            "method": "GET",
                        },
                        "result": {
                            "ok": True,
                            "code": 403,
                            "response": {"status_code": 403, "body": "denied"},
                        },
                    },
                    {
                        "index": 1,
                        "request": {
                            "url": "http://127.0.0.1:3000/search?q=x",
                            "method": "GET",
                        },
                        "result": {
                            "ok": True,
                            "code": 200,
                            "response": {"status_code": 200, "body": "ok"},
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    step = Step(
        assessment_id=1,
        seq=1,
        action="curl_request",
        target="127.0.0.1",
        output_path=str(path),
    )

    locator = locator_for(step, path.read_text(encoding="utf-8"))

    assert locator["http_status"] == 200
    assert locator["url"].endswith("/search?q=x")
    assert locator["method"] == "GET"
    assert excerpt_for(step, path.read_text(encoding="utf-8")) == "ok"


def test_cli_summarizes_batch_argv():
    argv = [
        "mcp",
        "curl_request",
        json.dumps(
            {
                "batch": [
                    {"url": "http://127.0.0.1:3000/login", "method": "GET"},
                    {"url": "http://127.0.0.1:3000/admin?tab=1", "method": "HEAD"},
                ]
            }
        ),
    ]

    assert _curl_batch_requests(argv) == [
        ("GET", "/login"),
        ("HEAD", "/admin?tab=1"),
    ]
    preview = _argv_preview(argv)
    assert preview.startswith("2 requests")
    assert "GET /login" in preview
    assert "HEAD /admin?tab=1" in preview


def test_cli_preview_keeps_a_single_command():
    assert _argv_preview(["nmap", "-sV", "127.0.0.1"]) == "nmap -sV 127.0.0.1"
    assert _argv_preview([]) == "-"


def test_step_matches_batch_signatures():
    step = Step(
        assessment_id=1,
        seq=1,
        action="curl_request",
        target="127.0.0.1",
        argv=[
            "mcp",
            "curl_request",
            json.dumps(
                {
                    "batch": [
                        {"url": "http://127.0.0.1:3000/a", "method": "GET"},
                        {"url": "http://127.0.0.1:3000/b", "method": "HEAD"},
                    ]
                }
            ),
        ],
    )
    params = {
        "requests": [
            {"path": "/a", "method": "GET"},
            {"path": "/b", "method": "HEAD"},
        ]
    }

    assert _step_matches(step, "127.0.0.1", params)
    assert not _step_matches(
        step,
        "127.0.0.1",
        {
            "requests": [
                {"path": "/b", "method": "HEAD"},
                {"path": "/a", "method": "GET"},
            ]
        },
    )


def test_batch_counts_each_request_against_probe_budget(engine, monkeypatch):
    monkeypatch.setattr(settings, "max_validation_probes", 4)

    async def body(session):
        assessment = await _assessment(session)
        for index in range(2):
            session.add(
                Audit(
                    assessment_id=assessment.id,
                    event_type="action.requested",
                    payload={
                        "run_id": "run-1",
                        "step_id": 900 + index,
                        "action": "curl_request",
                        "probe_count": 1,
                    },
                )
            )
        await session.commit()

        repo = StepRepo(session)
        rejected = await repo.create_step(
            assessment=assessment,
            run_id="run-1",
            role="validation",
            action="curl_request",
            target="127.0.0.1",
            rationale="three probes would exceed the budget",
            params={
                "requests": [
                    {"path": "/a", "method": "GET"},
                    {"path": "/b", "method": "GET"},
                    {"path": "/c", "method": "GET"},
                ]
            },
        )
        assert "error" in rejected
        assert "validation probe budget" in rejected["error"]

        accepted = await repo.create_step(
            assessment=assessment,
            run_id="run-1",
            role="validation",
            action="curl_request",
            target="127.0.0.1",
            rationale="single probe fits",
            params={"path": "/a", "method": "GET"},
        )
        assert accepted.get("step_id")

        result = await session.execute(
            select(Audit).where(
                Audit.assessment_id == assessment.id,
                Audit.event_type == "action.requested",
            )
        )
        events = [
            event
            for event in result.scalars().all()
            if (event.payload or {}).get("step_id") == accepted["step_id"]
        ]
        assert len(events) == 1
        assert events[0].payload["probe_count"] == 1

    _run_with_session(body)
