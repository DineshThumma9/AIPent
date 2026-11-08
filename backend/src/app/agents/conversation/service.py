"""Conversation service: context loading, background worker, and coordinator execution."""

from __future__ import annotations

import asyncio
from typing import Any
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from sqlmodel import select

from app.agents.control import audit
from app.agents.conversation.agent import build_coordinator_agent
from app.agents.conversation.tools import set_conversation_assessment_id
from app.api.queries import load_assessment_detail
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import Assessment, Message

log = get_logger("conversation.service")

_queues: dict[int, asyncio.Queue] = {}
_workers: dict[int, asyncio.Task] = {}


async def build_assessment_context(assessment_id: int) -> str:
    """Build a compact, grounded context block for the coordinator."""
    async with get_async_session_ctx() as session:
        detail = await load_assessment_detail(session, assessment_id)
        if detail is None:
            return f"ASSESSMENT CONTEXT: id={assessment_id} (not found)"

        from app.runtime import runner

        view = await runner.get_view(assessment_id, session=session)

        targets_str = ", ".join(detail.targets) or "none"
        ports_str = ", ".join(str(p) for p in detail.ports) or "default"
        confirmed = sum(1 for f in detail.findings if f.status == "confirmed")
        suspected = sum(1 for f in detail.findings if f.status != "confirmed")

        board = detail.reasoning
        open_questions = board.open_questions if board else []
        questions_str = (
            "; ".join(open_questions[:3]) if open_questions else "none"
        )

        lines = [
            "ASSESSMENT CONTEXT",
            f"id={detail.id} status={detail.status} active_role={view.active_role or 'none'} pending_gate={'yes' if view.gate_open else 'none'}",
            f"scope: {targets_str} ports {ports_str}",
            f"request: {detail.request!r}",
            f"findings: {confirmed} confirmed, {suspected} suspected",
            f"open questions: {questions_str}",
        ]
        return "\n".join(lines)


async def answer(
    assessment_id: int,
    text: str,
    coordinator_agent: Any | None = None,
) -> str:
    """Run the coordinator agent for one operator turn and return its reply text."""
    set_conversation_assessment_id(assessment_id)
    context_block = await build_assessment_context(assessment_id)

    # Fetch recent message history (last 6 messages)
    history: list[BaseMessage] = []
    async with get_async_session_ctx() as session:
        res = await session.execute(
            select(Message)
            .where(Message.assessment_id == assessment_id)
            .order_by(Message.id.desc())
            .limit(6)
        )
        recent_messages = list(reversed(res.scalars().all()))

    for msg in recent_messages[:-1]:  # exclude the current operator message just added
        if msg.role == "operator":
            history.append(HumanMessage(content=msg.text))
        elif msg.role == "assistant":
            history.append(AIMessage(content=msg.text))

    current_prompt = f"{context_block}\n\nOPERATOR: {text}"
    history.append(HumanMessage(content=current_prompt))

    agent = coordinator_agent or build_coordinator_agent()
    result = await agent.ainvoke({"messages": history})

    reply = ""
    messages = result.get("messages") or []
    for m in reversed(messages):
        if isinstance(m, AIMessage):
            content = m.content
            if isinstance(content, str) and content.strip():
                reply = content.strip()
                break
            if isinstance(content, list):
                text_parts = [
                    b.get("text", "")
                    for b in content
                    if isinstance(b, dict) and b.get("type") == "text"
                ]
                if text_parts:
                    reply = " ".join(text_parts).strip()
                    break

    if not reply:
        async with get_async_session_ctx() as session:
            assessment = await session.get(Assessment, assessment_id)
            status = assessment.status if assessment else "running"
        reply = f"I don't have enough evidence to answer that yet. The run is currently {status}."

    return reply


async def enqueue(assessment_id: int, message_id: int, text: str) -> None:
    """Enqueue an operator message for asynchronous processing by the coordinator worker."""
    queue = _queues.setdefault(assessment_id, asyncio.Queue())
    await queue.put((message_id, text))
    if assessment_id not in _workers or _workers[assessment_id].done():
        _workers[assessment_id] = asyncio.create_task(_worker(assessment_id))


async def _worker(assessment_id: int) -> None:
    """Background worker draining operator messages sequentially for one assessment."""
    queue = _queues[assessment_id]
    try:
        while not queue.empty():
            message_id, text = await queue.get()
            try:
                reply = await answer(assessment_id, text)
            except Exception as exc:
                log.exception("coordinator failed assessment=%s", assessment_id)
                reply = (
                    "I could not reach the coordinator just now. "
                    f"The run is unchanged. Error: {str(exc)[:200]}"
                )
                async with get_async_session_ctx() as session:
                    audit(
                        session,
                        assessment_id,
                        "conversation.error",
                        {
                            "message_id": message_id,
                            "error": str(exc),
                        },
                    )
                    await session.commit()

            async with get_async_session_ctx() as session:
                session.add(
                    Message(
                        assessment_id=assessment_id,
                        role="assistant",
                        text=reply[:4000],
                    )
                )
                await session.commit()

            queue.task_done()
    except Exception as exc:
        log.exception("fatal worker error assessment=%s: %s", assessment_id, exc)
