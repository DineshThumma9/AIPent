"""Unit and invariant tests for role message synchronization and tool protocol safety."""

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from app.agents.contracts import Handoff
from app.agents.nodes.specialist import extract_text_handoff
from app.agents.state import (
    close_dangling_tool_calls,
    get_role_key,
    get_role_messages,
    initial_state,
    update_role_messages,
)


def test_get_role_key():
    assert get_role_key("recon") == "recon_messages"
    assert get_role_key("discovery") == "discovery_messages"
    assert get_role_key("validation") == "validation_messages"
    assert get_role_key("review") is None
    assert get_role_key(None) is None


def test_update_and_get_role_messages_synchronization():
    state = initial_state(1)
    state["role"] = "recon"

    msg1 = HumanMessage(content="Start recon")
    msg2 = AIMessage(content="Running nmap")
    res = update_role_messages(state, [msg1, msg2], role="recon")

    assert "messages" in res
    assert "recon_messages" in res
    assert res["messages"] == [msg1, msg2]
    assert res["recon_messages"] == [msg1, msg2]

    # Apply to state
    state.update(res)
    assert get_role_messages(state, "recon") == [msg1, msg2]

    # Switch to discovery before any discovery messages exist
    state["role"] = "discovery"
    assert get_role_messages(state, "discovery") == []  # Must NOT inherit recon messages!

    msg3 = HumanMessage(content="Start discovery")
    res_disc = update_role_messages(state, [msg3], role="discovery")
    state.update(res_disc)

    # Verify isolation
    assert get_role_messages(state, "discovery") == [msg3]
    assert get_role_messages(state, "recon") == [msg1, msg2]
    assert state["messages"] == [msg3]


def test_close_dangling_tool_calls():
    # 1. Clean messages with no tool calls remain unchanged
    clean_msgs = [HumanMessage(content="hello"), AIMessage(content="hi")]
    assert close_dangling_tool_calls(clean_msgs) == clean_msgs

    # 2. Answered tool calls remain unchanged
    answered = [
        AIMessage(
            content="",
            tool_calls=[{"id": "call_1", "name": "nmap", "args": {}}],
        ),
        ToolMessage(tool_call_id="call_1", name="nmap", content="ok"),
    ]
    assert close_dangling_tool_calls(answered) == answered

    # 3. Dangling tool call gets closed with synthesized ToolMessage
    dangling = [
        AIMessage(
            content="",
            tool_calls=[{"id": "call_bad", "name": "curl_request", "args": {}}],
        ),
    ]
    closed = close_dangling_tool_calls(dangling)
    assert len(closed) == 2
    assert isinstance(closed[1], ToolMessage)
    assert closed[1].tool_call_id == "call_bad"
    assert closed[1].name == "curl_request"
    assert closed[1].status == "error"

    # 4. Partial tool calls (2 generated, only 1 answered)
    partial = [
        AIMessage(
            content="",
            tool_calls=[
                {"id": "call_a", "name": "nmap", "args": {}},
                {"id": "call_b", "name": "ffuf", "args": {}},
            ],
        ),
        ToolMessage(tool_call_id="call_a", name="nmap", content="ok"),
    ]
    closed_partial = close_dangling_tool_calls(partial)
    assert len(closed_partial) == 3
    tool_msgs = [m for m in closed_partial if isinstance(m, ToolMessage)]
    assert len(tool_msgs) == 2
    assert {m.tool_call_id for m in tool_msgs} == {"call_a", "call_b"}


def test_extract_text_handoff_json_block():
    text = (
        "I have completed reconnaissance.\n"
        "```json\n"
        "{\n"
        '  "next_role": "discovery",\n'
        '  "why": "Port 3000 Juice Shop found",\n'
        '  "confidence": 0.95,\n'
        '  "stop_reason": "surface_mapped"\n'
        "}\n"
        "```"
    )
    call = extract_text_handoff(text, "recon")
    assert call is not None
    assert call["name"] == "handoff"
    assert call["args"]["next_role"] == "discovery"
    assert "Juice Shop" in call["args"]["why"]
    # Check it validates as Handoff contract
    handoff = Handoff.model_validate(call["args"])
    assert handoff.next_role == "discovery"


def test_extract_text_handoff_bare_json():
    text = '{"next_role": "validation", "why": "Found high severity SQLi", "confidence": 0.9}'
    call = extract_text_handoff(text, "discovery")
    assert call is not None
    assert call["name"] == "handoff"
    assert call["args"]["next_role"] == "validation"
    assert call["args"]["stop_reason"] == "hypotheses_tested"


def test_extract_text_handoff_python_syntax():
    text = 'I will now handoff(next_role="discovery", why="Surface is mapped and open ports identified")'
    call = extract_text_handoff(text, "recon")
    assert call is not None
    assert call["name"] == "handoff"
    assert call["args"]["next_role"] == "discovery"
    assert "Surface is mapped" in call["args"]["why"]


def test_extract_text_handoff_keyword_phrase():
    text = "**handoff** to discovery: all services and ports identified on target."
    call = extract_text_handoff(text, "recon")
    assert call is not None
    assert call["name"] == "handoff"
    assert call["args"]["next_role"] == "discovery"


def test_extract_text_handoff_no_handoff():
    assert extract_text_handoff("Running curl on /api/whoami", "recon") is None
    assert extract_text_handoff("", "recon") is None
    assert extract_text_handoff(None, "recon") is None


@pytest.mark.asyncio
async def test_brief_node_auto_closes_dangling_tool_calls(engine):
    """Verify that brief_node never appends HumanMessage after an unclosed tool call."""
    from app.agents.nodes.specialist import brief_node
    from app.core.db import get_async_session_ctx
    from app.domain.models import Assessment

    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Dangling Test",
            request="Test dangling closure",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)
        aid = assessment.id

    state = initial_state(aid)
    state["role"] = "validation"
    state["run_id"] = "run-dangling-1"

    # Simulate dirty state: validation_messages ends on an unclosed AIMessage with tool_calls
    dirty_call = AIMessage(
        content="",
        tool_calls=[{"id": "call_dirty_8b03", "name": "curl_request", "args": {"url": "http://127.0.0.1"}}],
    )
    state["validation_messages"] = [dirty_call]

    cmd = await brief_node(state)
    assert cmd.goto == "model"

    validation_msgs = cmd.update.get("validation_messages", [])
    assert len(validation_msgs) == 3
    # Msg 0: dirty_call (AIMessage)
    assert validation_msgs[0] == dirty_call
    # Msg 1: Synthesized ToolMessage closing call_dirty_8b03
    assert isinstance(validation_msgs[1], ToolMessage)
    assert validation_msgs[1].tool_call_id == "call_dirty_8b03"
    assert validation_msgs[1].status == "error"
    # Msg 2: HumanMessage with directive
    assert isinstance(validation_msgs[2], HumanMessage)

    # Invariant: Any assistant message with tool calls must be followed immediately by tool message
    ai_idx = 0
    assert isinstance(validation_msgs[ai_idx + 1], ToolMessage)
    assert validation_msgs[ai_idx + 1].tool_call_id == dirty_call.tool_calls[0]["id"]


def test_text_handoff_mutates_ai_message_tool_calls():
    from app.agents.nodes.specialist import _last_tool_call

    ai = AIMessage(content="Finished recon. Handoff to discovery.")
    recovered = extract_text_handoff(ai.content, "recon")
    assert recovered is not None

    # Simulate what model_node does
    tool_calls = [recovered]
    ai.tool_calls = [recovered]
    messages = [HumanMessage(content="brief"), ai]

    found = _last_tool_call(messages)
    assert found["name"] == "handoff"
    assert found["args"]["next_role"] == "discovery"


def test_plan_step_normalization_defaults():
    from app.agents.mission_brain import normalize_plan_steps

    raw_steps = [
        # 1. Fully specified
        {"role": "recon", "action": "nmap_scan", "target": "127.0.0.1", "rationale": "map ports"},
        # 2. Blank action (should default to probe action)
        {"role": "discovery", "action": "", "target": "127.0.0.1", "rationale": "spider web surface"},
        # 3. Blank target with rationale (should default to in-scope target)
        {"role": "validation", "action": "curl_request", "target": "", "rationale": "verify SQLi"},
        # 4. Empty step (should be dropped)
        {"role": "recon", "action": "", "target": "", "rationale": ""},
    ]

    normalized = normalize_plan_steps(raw_steps)
    assert len(normalized) == 3

    assert normalized[0]["action"] == "nmap_scan"
    assert normalized[0]["target"] == "127.0.0.1"

    assert normalized[1]["action"] == "curl_request"
    assert normalized[1]["target"] == "127.0.0.1"

    assert normalized[2]["action"] == "curl_request"
    assert normalized[2]["target"] == "in-scope target"


