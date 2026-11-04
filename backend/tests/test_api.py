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
    assert detail["evidence"] == []
    assert detail["audit"][0]["event_type"] == "assessment.created"


def test_rejects_empty_scope(client):
    response = client.post("/api/assessments", json={"title": "x", "targets": []})
    assert response.status_code == 422


def test_missing_assessment_is_404(client):
    assert client.get("/api/assessments/999").status_code == 404


def test_scan_route_marks_assessment_completed(client, monkeypatch):
    created = client.post(
        "/api/assessments",
        json={"title": "Lab", "targets": ["127.0.0.1"], "ports": [3000]},
    ).json()

    async def fake_run_scan(session, assessment_id, target=None, timeout=None):
        from app.models import Step

        step = Step(
            assessment_id=assessment_id,
            seq=1,
            action="recon_services",
            status="succeeded",
            exit_code=0,
        )
        session.add(step)
        session.commit()
        session.refresh(step)
        return step

    monkeypatch.setattr("app.routes.run_scan", fake_run_scan)
    response = client.post(f"/api/assessments/{created['id']}/scan")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["finished_at"] is not None
    assert len(body["steps"]) == 1
