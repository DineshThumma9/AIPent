from __future__ import annotations

import pytest
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, AssessmentStatus
from app.persistence.audit_repo import AuditRepo
from app.agents import control


@pytest.mark.asyncio
async def test_audit_repo_role_and_handoff_lifecycle(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Control Test Target",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        repo = AuditRepo(session)

        # 1. Default role when none recorded
        initial_role = await repo.current_role(assessment.id, run_id="run-1")
        assert initial_role == "recon"

        # 2. Record role transitions
        await repo.record_role(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            reason="recon completed initial port scan",
            from_role="recon",
        )
        await session.commit()

        curr = await repo.current_role(assessment.id, run_id="run-1")
        assert curr == "discovery"

        # Invalid role raises ValueError
        with pytest.raises(ValueError, match="unknown role"):
            await repo.record_role(
                assessment_id=assessment.id,
                run_id="run-1",
                role="invalid_role",
                reason="testing",
            )

        # 3. Role history
        history = await repo.role_history(assessment.id, run_id="run-1")
        assert len(history) == 1
        assert history[0]["role"] == "discovery"
        assert history[0]["from"] == "recon"

        # 4. Record turns
        turn1 = await repo.record_turn(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            reason="first discovery turn",
        )
        assert turn1 == 1

        turn2 = await repo.record_turn(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            reason="second discovery turn",
        )
        assert turn2 == 2
        await session.commit()

        count = await repo.role_event_count(assessment.id, "run-1", "discovery", "role.turn")
        assert count == 2

        # 5. Record handoffs
        body = await repo.record_handoff(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            payload={
                "summary": "Discovered exposed git repo",
                "finding_ids": [1],
                "next_recommendation": "validation",
                "open_questions": ["Is .git accessible?"],
            },
        )
        assert body["summary"] == "Discovered exposed git repo"
        await session.commit()

        handoffs = await repo.handoff_history(assessment.id, run_id="run-1")
        assert len(handoffs) == 1
        assert handoffs[0]["role"] == "discovery"

        latest = await repo.latest_handoff(assessment.id, run_id="run-1")
        assert latest is not None
        assert latest["summary"] == "Discovered exposed git repo"


@pytest.mark.asyncio
async def test_control_module_compatibility_wrappers(engine):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Control Compatibility Test",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            status=AssessmentStatus.RUNNING.value,
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # Synchronous record_role
        payload = control.record_role(
            session=session,
            assessment_id=assessment.id,
            run_id="run-compat",
            role="validation",
            reason="handoff from discovery",
            from_role="discovery",
        )
        assert payload["role"] == "validation"
        await session.commit()

        curr = await control.current_role(session, assessment.id, "run-compat")
        assert curr == "validation"

        turn = await control.record_turn(session, assessment.id, "run-compat", "validation")
        assert turn == 1
        await session.commit()

        handoff = control.record_handoff(
            session=session,
            assessment_id=assessment.id,
            run_id="run-compat",
            role="validation",
            payload={"summary": "Validation complete"},
        )
        assert handoff["summary"] == "Validation complete"
        await session.commit()

        latest = await control.latest_handoff(session, assessment.id, "run-compat")
        assert latest is not None
        assert latest["summary"] == "Validation complete"
