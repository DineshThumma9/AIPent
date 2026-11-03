from app.agent import MAX_STEPS, build_graph


def test_graph_runs_full_lifecycle_and_stops_at_cap():
    result = build_graph().invoke(
        {
            "assessment_id": 1,
            "messages": [],
            "steps": 0,
            "plan_approved": False,
            "review_approved": False,
        }
    )

    assert result["steps"] == MAX_STEPS
    assert result["plan_approved"] is True
    assert result["review_approved"] is True
    assert result["messages"][0].content == "[stub] plan"
    assert result["messages"][-1].content == "[stub] report"
