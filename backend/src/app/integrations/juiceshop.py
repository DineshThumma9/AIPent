"""Juice Shop challenge tracking (ground-truth benchmark).

At intake we snapshot solved challenges; at review we compute the delta and
link solved challenges back to the audit trail. Broken lab connectivity must
never fail the run — every call degrades to unknown/None.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.config import settings
from app.core.db import get_async_session_ctx
from app.core.log import get_logger
from app.domain.models import Audit

log = get_logger("juiceshop")

ARTIFACT_KEY = "juice_shop_challenges.json"


def _base_url() -> str:
    # The backend talks to Juice Shop directly on the host; only MCP scanner
    # containers need the bridge alias (from app.agents.gate). Using the alias
    # here breaks challenge tracking on a host-run backend.
    return f"{settings.juiceshop_url.rstrip('/')}/api/Challenges"


async def fetch_solved_challenges(timeout: int = 15) -> dict[str, Any] | None:
    """Return {'solved_ids': [...], 'total': N} or None when unreachable."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(_base_url())
            response.raise_for_status()
            data = response.json()
        rows = data.get("data") or data.get("challenges") or []
        solved = [row.get("key") or row.get("name") for row in rows if row.get("solved")]
        return {"solved_ids": sorted(solved), "total": len(rows)}
    except Exception as exc:  # noqa: BLE001
        log.debug("challenge fetch unreachable: %s", exc)
        return None


async def capture_baseline(session: AsyncSession, assessment_id: int) -> None:
    snapshot = await fetch_solved_challenges()
    if snapshot is None:
        return
    session.add(
        Audit(
            assessment_id=assessment_id,
            event_type="benchmark.juice_shop_baseline",
            payload={"solved_ids": snapshot["solved_ids"], "total": snapshot["total"]},
        )
    )
    await session.commit()


async def compute_delta(
    session: AsyncSession, assessment_id: int
) -> dict[str, Any] | None:
    """Return {baseline_n, current_n, delta, newly_solved} or None."""
    result = await session.execute(
        select(Audit)
        .where(Audit.assessment_id == assessment_id)
        .order_by(Audit.id)
    )
    baseline_payload = None
    for row in result.scalars().all():
        if row.event_type == "benchmark.juice_shop_baseline":
            baseline_payload = row.payload

    current = await fetch_solved_challenges()
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


async def latest_delta(assessment_id: int) -> dict[str, Any] | None:
    """Lift the delta for the supervisor review gate; read-only."""
    async with get_async_session_ctx() as session:
        return await compute_delta(session, assessment_id)


async def snapshot_to_artifact(
    session: AsyncSession, assessment_id: int, delta: dict
) -> Path | None:
    """Persist the delta JSON to artifacts for the report's Juice Shop card."""
    directory = settings.artifacts_path / str(assessment_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ARTIFACT_KEY
    path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
    session.add(
        Audit(
            assessment_id=assessment_id,
            event_type="benchmark.juice_shop_delta",
            payload=delta,
        )
    )
    await session.commit()
    return path
