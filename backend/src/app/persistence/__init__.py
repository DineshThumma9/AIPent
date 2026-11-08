"""Persistence layer — every SQL operation lives here.

Repositories are thin: they own ``session.get``, ``session.execute``,
``session.add`` and ``session.commit``. No business rules beyond what the
schema enforces. Callers (services, agents, routes) depend on repositories,
never on raw SQL or ``get_async_session_ctx`` directly.
"""

from app.persistence.assessment_repo import AssessmentRepo
from app.persistence.audit_repo import AuditRepo
from app.persistence.finding_repo import FindingRepo
from app.persistence.role_repo import RoleRepo
from app.persistence.steering_repo import SteeringRepo
from app.persistence.step_repo import StepRepo

__all__ = [
    "AssessmentRepo",
    "AuditRepo",
    "FindingRepo",
    "RoleRepo",
    "SteeringRepo",
    "StepRepo",
]
