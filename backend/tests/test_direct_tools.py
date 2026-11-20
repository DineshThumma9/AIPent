import pytest
from app.core.db import get_async_session_ctx
from app.domain.models import Assessment, Step, StepStatus
from app.persistence.finding_repo import FindingRepo
from app.persistence.step_repo import StepRepo
from app.agents.loop.direct_tools import record_finding, read_artifact

@pytest.mark.asyncio
async def test_finding_repo_record_agent_finding_create_and_extend(engine, tmp_path):
    async with get_async_session_ctx() as session:
        assessment = Assessment(
            title="Direct Tools Assessment",
            request="Evaluate target security posture",
            targets=["127.0.0.1"],
            ports=[80],
        )
        session.add(assessment)
        await session.commit()
        await session.refresh(assessment)

        # Create a successful step for evidence
        art_path = tmp_path / "curl.json"
        art_path.write_text('{"status_code": 200, "body": "secret data"}', encoding="utf-8")
        step_repo = StepRepo(session)
        step, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="curl_request",
            target="127.0.0.1",
            argv=["curl", "-s", "http://127.0.0.1/api/data"],
            risk="low",
            requires_approval=False,
        )
        await step_repo.complete_step(step.id, status=StepStatus.SUCCEEDED.value, output_path=str(art_path))
        await session.commit()

        finding_repo = FindingRepo(session)
        # 1. Create a new agent finding
        res1 = await finding_repo.record_agent_finding(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            title="Exposed Data Endpoint",
            asset="127.0.0.1",
            endpoint="/api/data",
            severity="high",
            description="API returns secret data without auth",
            evidence_step_ids=[step.id],
        )
        await session.commit()

        assert res1["ok"] is True
        assert res1["created"] is True
        assert res1["finding"].title == "Exposed Data Endpoint"
        assert res1["finding"].severity == "high"
        assert len(res1["evidence_ids"]) == 1

        # 2. Extend existing finding with same endpoint/title
        res2 = await finding_repo.record_agent_finding(
            assessment_id=assessment.id,
            run_id="run-1",
            role="validation",
            finding_id=res1["finding"].id,
            severity="critical",
            evidence_step_ids=[step.id],
        )
        await session.commit()

        assert res2["ok"] is True
        assert res2["created"] is False
        assert res2["finding"].id == res1["finding"].id
        assert res2["finding"].severity == "critical"

        # 3. Test get_artifact_path on step_repo
        path = await step_repo.get_artifact_path(step.id)
        assert path == str(art_path)

        # 4. Test read_artifact tool
        obs = await read_artifact(session, assessment.id, step.id)
        assert obs.ok is True
        assert "secret data" in obs.summary

        # 5. Test hash_identify_direct
        from app.agents.loop.direct_tools import hash_identify_direct
        hash_file = tmp_path / "hash.txt"
        hash_file.write_text("user:$1$abcdef12$1234567890123456789012:1000:1000", encoding="utf-8")
        step_hash, _ = await step_repo.create_planned_step(
            assessment_id=assessment.id,
            run_id="run-1",
            role="discovery",
            action="read_file",
            target="127.0.0.1",
            argv=[],
            risk="low",
            requires_approval=False,
        )
        await step_repo.complete_step(step_hash.id, status=StepStatus.SUCCEEDED.value, output_path=str(hash_file))
        await session.commit()

        hash_obs = await hash_identify_direct(
            session=session,
            assessment_id=assessment.id,
            hash_value="$1$abcdef12$1234567890123456789012",
            source_step_id=step_hash.id,
        )
        assert hash_obs.ok is True
        assert hash_obs.facts["candidates"][0]["name"] == "md5crypt"
