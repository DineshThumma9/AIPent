"""Manual scan wrapper around the shared action executor."""

from sqlmodel import Session

from app.actions import ScopeError, execute_action
from app.models import Step

__all__ = ["ScopeError", "run_scan"]


async def run_scan(
    session: Session,
    assessment_id: int,
    target: str | None = None,
    timeout: int | None = None,
) -> Step:
    return await execute_action(
        session,
        assessment_id,
        "recon_services",
        target=target,
        rationale="Manual nmap service scan of in-scope target",
        timeout=timeout,
    )
