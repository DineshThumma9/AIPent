import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.db import get_session, init_db, make_engine
from app.main import app


@pytest.fixture
def client(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'api.db'}")
    init_db(engine)

    def override():
        with Session(engine, expire_on_commit=False) as session:
            yield session

    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_create_list_and_detail(client):
    created = client.post(
        "/api/assessments",
        json={
            "title": "Lab",
            "request": "Full web VAPT",
            "targets": ["127.0.0.1"],
            "ports": [3000, 8080],
        },
    )
    assert created.status_code == 201
    assessment = created.json()
    assert assessment["status"] == "draft"

    listed = client.get("/api/assessments").json()
    assert [item["id"] for item in listed] == [assessment["id"]]

    detail = client.get(f"/api/assessments/{assessment['id']}").json()
    assert detail["steps"] == []
    assert detail["audit"][0]["event_type"] == "assessment.created"


def test_rejects_empty_scope(client):
    response = client.post("/api/assessments", json={"title": "x", "targets": []})
    assert response.status_code == 422


def test_missing_assessment_is_404(client):
    assert client.get("/api/assessments/999").status_code == 404
