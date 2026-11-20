import pytest
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment
from app.persistence.context_loader import load_mission_context

@pytest.mark.asyncio
async def test_load_mission_context_returns_typed_snapshot(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Preloader Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80, 443],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        ctx = await load_mission_context(session, assessment.id, run_id="run-1")
        assert ctx.assessment.id == assessment.id
        assert isinstance(ctx.services, list)
        assert isinstance(ctx.candidates, list)
        assert ctx.evidence_board is not None
