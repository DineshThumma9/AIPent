"""Supervisor agent must use its read-only tools and return a RouteDecision."""

from __future__ import annotations

import asyncio
import json

from langchain_core.messages import AIMessage, ToolMessage

from app.agents.contracts import RouteDecision
from app.agents.mission_brain import MissionDigest, run_supervisor_agent


class _FakeModel:
    def __init__(self, replies: list[AIMessage]):
        self.replies = list(replies)
        self.bound_tools = None
        self.structured_messages = None

    def bind_tools(self, tools):
        self.bound_tools = tools
        return self

    async def ainvoke(self, messages, config=None):
        return self.replies.pop(0)

    def with_structured_output(self, schema):
        outer = self

        class _Structured:
            async def ainvoke(self, messages, config=None):
                outer.structured_messages = messages
                return RouteDecision(next_role="review", why="done")

        return _Structured()


def test_supervisor_binds_tools_then_returns_structured_route():
    digest = MissionDigest(
        assessment_id=1,
        run_id="run-1",
        services=[{"port": 3000}],
        budget={"turns": {"recon": 1}, "supervisor_calls": 2},
    )
    model = _FakeModel(
        [
            AIMessage(
                content="",
                tool_calls=[{"id": "c1", "name": "get_budget", "args": {}}],
            ),
            AIMessage(content="Review the assessment."),
        ]
    )

    decision = asyncio.run(run_supervisor_agent(digest, chat_model=model))

    assert decision.next_role == "review"
    assert {t.name for t in model.bound_tools} >= {"get_budget", "get_steps"}
    tool_messages = [
        m for m in model.structured_messages if isinstance(m, ToolMessage)
    ]
    assert len(tool_messages) == 1
    assert json.loads(tool_messages[0].content)["supervisor_calls"] == 2
    assert not isinstance(model.structured_messages[-1], AIMessage)


def test_supervisor_recovers_route_when_tool_call_args_empty_but_content_has_json():
    digest = MissionDigest(
        assessment_id=29,
        run_id="run-29",
        services=[{"port": 3000}],
        budget={"turns": {"discovery": 20}, "supervisor_calls": 5},
    )

    class _CerebrasLikeModel:
        def bind_tools(self, tools):
            return self

        async def ainvoke(self, messages, config=None):
            return AIMessage(
                content='{\n  "next_role": "validation",\n  "why": "Concrete endpoint observed; test login bypass.",\n  "confidence": 0.86,\n  "directive": {"tool": "curl_request", "action": "test"}\n}',
                tool_calls=[{"id": "call-1", "name": "RouteDecision", "args": {}}],
            )

        def with_structured_output(self, schema, include_raw=False):
            outer = self

            class _Structured:
                async def ainvoke(self, messages, config=None):
                    # Simulate failure / returning raw with empty args
                    if include_raw:
                        raw_msg = await outer.ainvoke(messages, config=config)
                        return {"raw": raw_msg, "parsed": None, "parsing_error": ValueError("Field required: next_role")}
                    raise ValueError("Field required: next_role")

            return _Structured()

    decision = asyncio.run(run_supervisor_agent(digest, chat_model=_CerebrasLikeModel()))
    assert decision.next_role == "validation"
    assert decision.confidence == 0.86
    assert "Concrete endpoint" in decision.why
    assert "deterministic fallback" not in decision.why
