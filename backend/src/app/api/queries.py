"""Read models shared by the REST detail endpoint and the event stream."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import (
    AssessmentStatus,
    Decision,
)
from app.api.schema import AssessmentDetail, MessageOut
from app.persistence import AuditRepo, AssessmentRepo, FindingRepo, StepRepo


async def load_assessment_detail(
    session: AsyncSession, assessment_id: int
) -> AssessmentDetail | None:
    repo = AssessmentRepo(session)
    assessment = await repo.get(assessment_id)
    if assessment is None:
        return None

    step_repo = StepRepo(session)
    steps = await step_repo.get_all(assessment_id)

    finding_repo = FindingRepo(session)
    findings = await finding_repo.get_all(assessment_id, limit=10000)

    audit_repo = AuditRepo(session)
    evidence = await finding_repo.get_all_evidence(assessment_id)
    approvals = await step_repo.get_all_approvals(assessment_id)

    # The conversation thread reconstructs role cards and handoffs from the
    # audit trail. A run easily produces more than 100 rows, so the window has
    # to be large enough to keep the start of the latest run in view.
    audit = await audit_repo.get_all_for_assessment(assessment_id, limit=1000)

    messages_db = await repo.get_messages(assessment_id)
    messages = [MessageOut.model_validate(m) for m in messages_db]

    pending_approval = next(
        (row for row in approvals if row.decision == Decision.PENDING.value),
        None,
    )
    requires_approval = True
    if pending_approval is not None:
        requires_approval = (
            (pending_approval.detail or {}).get("requires_approval", True) is not False
        )
    gate_open = (
        assessment.status == AssessmentStatus.AWAITING_APPROVAL.value
        and requires_approval
    )

    from app.agents.loop.reasoning import build_evidence_board

    board = await build_evidence_board(session, assessment_id)

    active_role: str | None = None
    run_id: str | None = None
    try:
        from app.runtime.runner import _values, is_running

        if is_running(assessment_id):
            _, values = await _values(assessment_id)
            active_role = values.get("role")
            run_id = values.get("run_id")
    except Exception:
        pass

    # A paused run is not "running", so fall back to the newest audit row that
    # carries a run_id. The stream keeps this stable even when the oldest audit
    # rows have already fallen out of the capped window.
    if not run_id:
        for row in audit:
            candidate = (row.payload or {}).get("run_id")
            if candidate:
                run_id = candidate
                break

    if not active_role:
        for row in reversed(audit):
            if row.event_type == "supervisor.route":
                active_role = (row.payload or {}).get("accepted_role")
                if active_role:
                    break

    return AssessmentDetail(
        **assessment.model_dump(),
        steps=steps,
        findings=findings,
        evidence=evidence,
        approvals=approvals,
        audit=audit,
        messages=messages,
        gate_open=gate_open,
        active_role=active_role,
        run_id=run_id,
        reasoning=board,
    )
