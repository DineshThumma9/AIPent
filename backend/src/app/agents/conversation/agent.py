"""Coordinator agent graph builder."""

from __future__ import annotations

from typing import Any
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel

from app.agents.conversation.prompt import COORDINATOR_PROMPT
from app.agents.conversation.tools import COORDINATOR_TOOLS
from app.agents.model import _build_model
from app.core.log import get_logger

log = get_logger("conversation.agent")


def build_coordinator_agent(
    model: BaseChatModel | None = None,
    tools: list[Any] | None = None,
):
    """Build the conversational coordinator agent.

    The coordinator is a lightweight agent with read tools and run steering/control.
    It does not own a checkpointer or gate interrupts.
    """
    selected_model = model or _build_model()
    selected_tools = tools or COORDINATOR_TOOLS

    log.info(
        "building coordinator agent with %d tools",
        len(selected_tools),
    )

    return create_agent(
        model=selected_model,
        tools=selected_tools,
        system_prompt=COORDINATOR_PROMPT,
    )
