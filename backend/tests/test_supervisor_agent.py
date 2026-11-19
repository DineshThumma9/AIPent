"""Supervisor agent must use its read-only tools and return a RouteDecision."""

from __future__ import annotations

import asyncio
import json

from langchain_core.messages import AIMessage, ToolMessage

from app.agents.loop.contracts import RouteDecision
from app.agents.loop.mission_brain import MissionDigest, run_supervisor_agent


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
