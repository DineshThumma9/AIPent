import pytest
from app.agents.loop.observations import observation_from_step
from app.domain.models import Step, StepStatus

def test_observation_from_step_pure():
    step = Step(
        id=42,
        assessment_id=1,
        action="curl_request",
        status=StepStatus.SUCCEEDED.value,
        target="http://test",
    )
    obs = observation_from_step(step, finding_ids=[10], evidence_ids=[100])
    assert obs.ok is True
    assert obs.action == "curl_request"
    assert obs.findings_created == [10]
    assert obs.evidence_ids == [100]

def test_observation_from_step_failed_pure():
    step = Step(
        id=43,
        assessment_id=1,
        action="sqlmap_scan",
        status=StepStatus.FAILED.value,
        target="http://test",
        error="Connection refused",
    )
    obs = observation_from_step(step)
    assert obs.ok is False
    assert obs.status == "failed"
    assert obs.action == "sqlmap_scan"
    assert "Connection refused" in obs.summary
