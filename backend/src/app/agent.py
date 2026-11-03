"""LangGraph lifecycle: intake -> plan -> approval -> execute/analyze loop ->
review -> report. Nodes are stubs; the shape, state and caps are real.
"""

import asyncio
import sqlite3
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage, AnyMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from app.config import settings
from app.log import get_logger

log = get_logger("agent")
MAX_STEPS = settings.max_steps
GRAPH_DB = settings.graph_path


class AgentState(TypedDict):
    assessment_id: int
    messages: Annotated[list[AnyMessage], add_messages]
    steps: int
    plan_approved: bool
    review_approved: bool


def intake(state: AgentState) -> dict:
    # TODO: load Assessment, re-check scope, set status=planning.
    log.info("intake assessment=%s: stub", state["assessment_id"])
    return {}


def plan(state: AgentState) -> dict:
    # TODO: LLM picks actions from the closed action catalogue.
    log.info("plan: stub")
    return {"messages": [AIMessage(content="[stub] plan")], "steps": 0}


def approve_plan(state: AgentState) -> dict:
    # TODO: interrupt() and resume with the analyst's decision.
    log.info("approve_plan: stub")
    return {"plan_approved": True, "messages": [AIMessage(content="[stub] approve_plan")]}


def execute(state: AgentState) -> dict:
    # TODO: scope guard -> adapter/MCP call -> persist Step/Finding/Evidence.
    log.info("execute %s/%s: stub", state["steps"] + 1, MAX_STEPS)
    return {
        "steps": state["steps"] + 1,
        "messages": [AIMessage(content=f"[stub] execute {state['steps'] + 1}")],
    }


def analyze(state: AgentState) -> dict:
    # TODO: normalise, correlate across tools, recalculate risk.
    log.info("analyze step %s: stub", state["steps"])
    return {"messages": [AIMessage(content=f"[stub] analyze {state['steps']}")]}


def review(state: AgentState) -> dict:
    # TODO: interrupt() for final analyst review before the report.
    log.info("review: stub")
    return {"review_approved": True, "messages": [AIMessage(content="[stub] review")]}


def report(state: AgentState) -> dict:
    # TODO: narrate from DB, render with typst.
    log.info("report: stub")
    return {"messages": [AIMessage(content="[stub] report")]}


def _after_analyze(state: AgentState) -> str:
    return "review" if state["steps"] >= MAX_STEPS else "execute"


def build_graph(checkpointer=None):
    graph = StateGraph(AgentState)
    graph.add_node("intake", intake)
    graph.add_node("plan", plan)
    graph.add_node("approve_plan", approve_plan)
    graph.add_node("execute", execute)
    graph.add_node("analyze", analyze)
    graph.add_node("review", review)
    graph.add_node("report", report)
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "plan")
    graph.add_edge("plan", "approve_plan")
    graph.add_edge("approve_plan", "execute")
    graph.add_edge("execute", "analyze")
    graph.add_conditional_edges(
        "analyze",
        _after_analyze,
        {"execute": "execute", "review": "review"},
    )
    graph.add_edge("review", "report")
    graph.add_edge("report", END)
    return graph.compile(checkpointer=checkpointer)


_graph = None


def get_graph():
    """Compiled graph with a SQLite checkpointer for durable threads."""
    global _graph
    if _graph is None:
        GRAPH_DB.parent.mkdir(parents=True, exist_ok=True)
        saver = SqliteSaver(sqlite3.connect(GRAPH_DB, check_same_thread=False))
        saver.setup()
        _graph = build_graph(saver)
    return _graph


async def run_graph(assessment_id: int, thread_id: str | None = None) -> dict:
    """Invoke off the event loop; the sync checkpointer is not async-safe."""
    return await asyncio.to_thread(
        get_graph().invoke,
        {
            "assessment_id": assessment_id,
            "messages": [],
            "steps": 0,
            "plan_approved": False,
            "review_approved": False,
        },
        {"configurable": {"thread_id": thread_id or str(assessment_id)}},
    )
