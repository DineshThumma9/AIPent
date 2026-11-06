"""Per-run context variables shared between the agent loop and its tools."""

from contextvars import ContextVar

current_assessment_id: ContextVar[int | None] = ContextVar(
    "current_assessment_id", default=None
)
current_run_id: ContextVar[str | None] = ContextVar("current_run_id", default=None)
current_role: ContextVar[str | None] = ContextVar("current_role", default=None)
