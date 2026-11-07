"""Manual scan wrapper around the shared action executor."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.actions import ScopeError, execute_action
from app.domain.models import Step

__all__ = ["ScopeError", "run_scan"]


async def run_scan(
    session: AsyncSession,
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
