import pytest
from app.core.db import get_async_session_ctx
from app.persistence.step_repo import StepRepo
from app.domain.models import Assessment, StepStatus, Decision

@pytest.mark.asyncio
async def test_step_repo_planned_and_approval_flow(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Step Lifecycle Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = StepRepo(session)
        step, approval = await repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="validation",
            action="sqlmap_scan",
            target="127.0.0.1",
            argv=["sqlmap", "-u", "http://127.0.0.1/"],
            risk="high",
            requires_approval=True,
        )
        await session.commit()

        assert step.status == StepStatus.PLANNED.value
        assert approval is not None
        assert approval.decision == Decision.PENDING.value

        # Reject step
        rejected_step = await repo.reject_step(step.id, reason="Dangerous payload")
        await session.commit()

        assert rejected_step.status == StepStatus.REJECTED.value
        assert "Dangerous payload" in (rejected_step.error or "")

        # Verify approval is also rejected
        refreshed_approval = await session.get(type(approval), approval.id)
        assert refreshed_approval.decision == Decision.REJECTED.value


@pytest.mark.asyncio
async def test_step_repo_complete_step(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Step Completion Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = StepRepo(session)
        step, _ = await repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="recon",
            action="curl_request",
            target="127.0.0.1",
            argv=["curl", "-s", "http://127.0.0.1/"],
            risk="low",
            requires_approval=False,
        )
        await session.commit()

        completed_step = await repo.complete_step(
            step_id=step.id,
            status=StepStatus.SUCCEEDED.value,
            exit_code=0,
            output_path="/tmp/output.txt",
        )
        await session.commit()

        assert completed_step.status == StepStatus.SUCCEEDED.value
        assert completed_step.exit_code == 0
        assert completed_step.output_path == "/tmp/output.txt"
        assert completed_step.ended_at is not None
