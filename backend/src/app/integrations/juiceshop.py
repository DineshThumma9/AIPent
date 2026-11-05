"""Juice Shop challenge tracking (ground-truth benchmark).

At intake we snapshot solved challenges; at review we compute the delta and
link solved challenges back to the audit trail. Broken lab connectivity must
never fail the run — every call degrades to unknown/None.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import httpx

from app.core.config import settings
from app.core.log import get_logger
from app.domain.models import Assessment, Audit, utcnow

log = get_logger("juiceshop")

ARTIFACT_KEY = "juice_shop_challenges.json"


def _base_url() -> str:
    # Workers inside containers cannot use 127.0.0.1; the lab publishes the
    # bridge alias. The backend process itself talks to 127.0.0.1.
    host = settings.lab_target_alias if settings.mcp_enabled else "127.0.0.1"
    port = 3000
    return f"http://{host}:{port}/api/Challenges"


def fetch_solved_challenges(timeout: int = 15) -> dict[str, Any] | None:
    """Return {'solved_ids': [...], 'total': N} or None when unreachable."""
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(_base_url())
            response.raise_for_status()
            data = response.json()
        rows = data.get("data") or data.get("challenges") or []
        solved = [row.get("key") or row.get("name") for row in rows if row.get("solved")]
        return {"solved_ids": sorted(solved), "total": len(rows)}
    except Exception as exc:  # noqa: BLE001
        log.debug("challenge fetch unreachable: %s", exc)
        return None


def capture_baseline(session, assessment_id: int) -> None:
    snapshot = fetch_solved_challenges()
    if snapshot is None:
        return
    audit = Audit(
        assessment_id=assessment_id,
        event_type="benchmark.juice_shop_baseline",
        payload={"solved_ids": snapshot["solved_ids"], "total": snapshot["total"]},
    )
    session.add(audit)
    session.commit()


def compute_delta(session, assessment_id: int) -> dict[str, Any] | None:
    """Return {baseline_n, current_n, delta, newly_solved} or None."""
    from sqlmodel import select
    from app.domain.models import Assessment

    baseline_rows = session.exec(
        select(Audit)
        .where(Audit.assessment_id == assessment_id)
        .order_by(Audit.id)
    ).all()
    baseline_payload = None
    for row in baseline_rows:
        if row.event_type == "benchmark.juice_shop_baseline":
            baseline_payload = row.payload

    current = fetch_solved_challenges()
    if current is None:
        return None
    if not baseline_payload:
        return {
            "baseline_n": 0,
            "current_n": len(current["solved_ids"]),
            "delta": 0,
            "newly_solved": [],
            "note": "no baseline captured",
        }

    baseline = set(baseline_payload.get("solved_ids", []))
    current_ids = set(current["solved_ids"])
    newly = sorted(current_ids - baseline)
    return {
        "baseline_n": len(baseline),
        "current_n": len(current_ids),
        "delta": len(newly),
        "newly_solved": newly,
    }


def latest_delta(assessment_id: int) -> dict[str, Any] | None:
    """Lift the delta for the supervisor review gate; read-only."""
    from app.core.db import get_engine

    engine = get_engine()
    from sqlmodel import Session

    with Session(engine, expire_on_commit=False) as session:
        return compute_delta(session, assessment_id)


def snapshot_to_artifact(session, assessment_id: int, delta: dict) -> Path | None:
    """Persist the delta JSON to artifacts for the report's Juice Shop card."""
    directory = settings.artifacts_path / str(assessment_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ARTIFACT_KEY
    path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
    audit = Audit(
        assessment_id=assessment_id,
        event_type="benchmark.juice_shop_delta",
        payload=delta,
    )
    session.add(audit)
    session.commit()
    return path