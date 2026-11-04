import json

from app.events import EventType, StreamState
from app.queries import load_assessment_detail
from app.schema import AssessmentDetail
from sqlmodel import Session

from app.models import Assessment


def _create(client, title="Lab"):
    response = client.post(
        "/api/assessments",
        json={
            "title": title,
            "request": "Full web VAPT",
            "targets": ["127.0.0.1"],
            "ports": [3000],
        },
    )
    assert response.status_code == 201
    return response.json()


def _parse_sse(body: str) -> list[dict]:
    events = []
    for block in body.strip().split("\n\n"):
        data = [
            line.removeprefix("data: ")
            for line in block.splitlines()
            if line.startswith("data: ")
        ]
        if data:
            events.append(json.loads("\n".join(data)))
    return events


def test_stream_replays_snapshot_first(client):
    assessment = _create(client)

    response = client.get(f"/api/assessments/{assessment['id']}/events?once=true")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"].startswith("no-cache")

    events = _parse_sse(response.text)
    assert len(events) == 1
    snapshot = events[0]
    assert snapshot["type"] == EventType.SNAPSHOT.value
    assert snapshot["assessment_id"] == assessment["id"]
    assert snapshot["data"]["assessment"]["id"] == assessment["id"]
    assert snapshot["data"]["assessment"]["evidence"] == []


def test_stream_missing_assessment_is_404(client):
    assert client.get("/api/assessments/999/events?once=true").status_code == 404


def test_stream_state_emits_only_changes(engine):
    with Session(engine, expire_on_commit=False) as session:
        assessment = Assessment(title="Lab", targets=["127.0.0.1"], ports=[3000])
        session.add(assessment)
        session.commit()
        session.refresh(assessment)
        detail = load_assessment_detail(session, assessment.id)

    assert detail is not None
    state = StreamState(detail)

    snapshot = state.event(assessment.id, EventType.SNAPSHOT, {"assessment": detail.model_dump()})
    assert snapshot.assessment_id == assessment.id
    assert snapshot.data["assessment"]["id"] == assessment.id

    assert state.diff(detail) == []


def test_detail_includes_evidence_key(client):
    assessment = _create(client)
    detail = client.get(f"/api/assessments/{assessment['id']}").json()
    assert isinstance(detail["evidence"], list)
