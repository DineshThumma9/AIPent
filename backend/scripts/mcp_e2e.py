"""Live end-to-end rehearsal against a running backend and MCP gateway.

Creates an assessment, walks the plan/action/review gates, downloads the PDF
and prints the audit trail. This is a manual rehearsal, not a pytest test.

Prerequisites:

    docker compose -f lab.lvl1.yml up -d
    docker compose -f deploy/mcp-zap/compose.yaml up -d
    ./deploy/mcp-gateway/start.sh
    cd backend && uv run uvicorn app.main:app --host 127.0.0.1 --port 8010

Run:

    cd backend && uv run python scripts/mcp_e2e.py

Override the backend with ``AIPENT_API`` (default ``http://127.0.0.1:8010/api``).
"""

import asyncio
import json
import os
import sys

import httpx

BASE = os.getenv("AIPENT_API", "http://127.0.0.1:8010/api")
TIMEOUT = float(os.getenv("AIPENT_E2E_TIMEOUT", "900"))


async def wait_for(
    client: httpx.AsyncClient, aid: int, want: str, timeout: float = TIMEOUT
) -> dict:
    deadline = asyncio.get_event_loop().time() + timeout
    seen = None
    while asyncio.get_event_loop().time() < deadline:
        view = (await client.get(f"{BASE}/assessments/{aid}/agent")).json()
        state = (view["status"], view["running"], view["paused"], view["next"])
        if state != seen:
            print("agent:", json.dumps(state), "| steps:", view["steps"])
            seen = state
        if want in {"plan", "action", "review"}:
            pending = view["pending"] or {}
            if view["paused"] and pending.get("gate") == want:
                return view
        if want == "done" and not view["running"] and not view["paused"]:
            return view
        await asyncio.sleep(1)
    raise TimeoutError(f"never reached {want}; last={seen}")


async def resume(
    client: httpx.AsyncClient, aid: int, decision: str, reason: str
) -> None:
    response = await client.post(
        f"{BASE}/assessments/{aid}/resume",
        json={"decision": decision, "actor": "dinesh", "reason": reason},
    )
    response.raise_for_status()
    print("resume:", decision, "->", response.json()["message"])


async def main() -> None:
    async with httpx.AsyncClient(timeout=60) as client:
        created = await client.post(
            f"{BASE}/assessments",
            json={
                "title": "E2E MCP rehearsal",
                "request": "Assess the Juice Shop lab on port 3000.",
                "targets": ["127.0.0.1"],
                "ports": [3000],
            },
        )
        created.raise_for_status()
        aid = created.json()["id"]
        print("assessment:", aid)

        accepted = await client.post(f"{BASE}/assessments/{aid}/run")
        accepted.raise_for_status()

        plan = await wait_for(client, aid, "plan")
        print("PLAN GATE:", json.dumps(plan["pending"], indent=2)[:1200])
        if not plan["pending"].get("plan"):
            raise AssertionError("empty plan")
        await resume(client, aid, "approved", "Authorized lab scope; proceed.")

        action = await wait_for(client, aid, "action")
        print("ACTION GATE:", json.dumps(action["pending"], indent=2)[:1200])
        if action["pending"].get("argv", [None])[0] != "mcp":
            raise AssertionError(f"not an MCP descriptor: {action['pending']}")
        await resume(client, aid, "approved", "Active web probe is within scope.")

        review = await wait_for(client, aid, "review")
        print("REVIEW GATE:", json.dumps(review["pending"], indent=2)[:1200])
        await resume(client, aid, "approved", "Findings reviewed; publish report.")

        done = await wait_for(client, aid, "done")
        detail = (await client.get(f"{BASE}/assessments/{aid}")).json()
        print("DONE:", done["status"], "risk:", done["risk_score"])
        print(
            "steps:",
            [(s["seq"], s["action"], s["status"], s["argv"][0]) for s in detail["steps"]],
        )
        print("findings:", len(detail["findings"]), "evidence:", len(detail["evidence"]))
        print("assets:", sorted({f["asset"] for f in detail["findings"]}))
        print("audit:", sorted({row["event_type"] for row in detail["audit"]}))
        print(
            "mcp calls:",
            [
                (row["payload"]["tool"], sorted(row["payload"]["arguments"]))
                for row in detail["audit"]
                if row["event_type"] == "mcp.call"
            ],
        )
        print(
            "approvals:",
            [
                (a["action"], a["decision"], a["actor"], a["argv"][:2])
                for a in detail["approvals"]
            ],
        )

        report = await client.get(f"{BASE}/assessments/{aid}/report")
        report.raise_for_status()
        if not report.headers["content-type"].startswith("application/pdf"):
            raise AssertionError(report.headers["content-type"])
        if not report.content.startswith(b"%PDF"):
            raise AssertionError("report is not a PDF")
        print("report bytes:", len(report.content), "sha:", detail["report_sha256"][:12])

        events = await client.get(
            f"{BASE}/assessments/{aid}/events", params={"once": "true"}
        )
        events.raise_for_status()
        first = next(
            line for line in events.text.splitlines() if line.startswith("event:")
        )
        print("sse first event:", first)
        print("sse bytes:", len(events.text))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        print("E2E FAILED:", type(exc).__name__, exc)
        sys.exit(1)
