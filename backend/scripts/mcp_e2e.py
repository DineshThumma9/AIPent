"""Live end-to-end rehearsal against a running backend and MCP gateway.

Creates an assessment, approves each action gate and the final review,
downloads the PDF and prints the audit trail. This is a manual rehearsal,
not a pytest test.

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
TIMEOUT = float(os.getenv("AIPENT_E2E_TIMEOUT", "1200"))
MAX_DECISIONS = int(os.getenv("AIPENT_E2E_MAX_DECISIONS", "20"))


async def wait_for_pause(
    client: httpx.AsyncClient, aid: int, timeout: float = TIMEOUT
) -> dict:
    """Wait for a human gate or a terminal run state.

    Only return when the run is NOT actively executing (running=False) and is
    genuinely paused at a gate. While a resume task executes a step (e.g.
    nmap via MCP), the checkpoint can be stale and still show paused=True;
    we must not send a second resume while the first task is still running.
    """
    deadline = asyncio.get_event_loop().time() + timeout
    seen = None
    while asyncio.get_event_loop().time() < deadline:
        view = (await client.get(f"{BASE}/assessments/{aid}/agent")).json()
        state = (view["status"], view["running"], view["paused"], view["next"])
        if state != seen:
            print("agent:", json.dumps(state), "| steps:", view["steps"])
            seen = state
        if not view["running"] and view["paused"]:
            return view
        if not view["running"] and not view["paused"] and view["status"] in {
            "completed",
            "failed",
            "cancelled",
        }:
            return view
        await asyncio.sleep(1)
    raise TimeoutError(f"run did not pause or finish; last={seen}")


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
                "title": "Juice Shop agent run",
                "request": (
                    "Authorised non-destructive assessment of the local Juice "
                    "Shop lab on port 3000. Find and verify real exposures."
                ),
                "targets": ["127.0.0.1"],
                "ports": [3000],
            },
        )
        created.raise_for_status()
        aid = created.json()["id"]
        print("assessment:", aid)

        accepted = await client.post(f"{BASE}/assessments/{aid}/run")
        accepted.raise_for_status()

        decisions = 0
        while True:
            view = await wait_for_pause(client, aid)
            pending = view["pending"] or {}
            if not view["paused"]:
                break

            gate = pending.get("gate")
            print(f"\n{str(gate).upper()} GATE:")
            print(json.dumps(pending, indent=2)[:2000])
            if view.get("last_message"):
                print("agent says:", view["last_message"][:600])

            if gate == "action":
                if not pending.get("argv"):
                    raise AssertionError(f"action gate without argv: {pending}")
                reason = "Authorized Juice Shop lab; action is within scope."
            elif gate == "review":
                reason = "Findings reviewed; publish the report."
            else:
                raise AssertionError(f"unknown gate: {pending}")

            await resume(client, aid, "approved", reason)
            decisions += 1
            if decisions > MAX_DECISIONS:
                raise AssertionError(f"more than {MAX_DECISIONS} gate decisions")

        detail = (await client.get(f"{BASE}/assessments/{aid}")).json()
        print("\nDONE:", view["status"], "risk:", view["risk_score"])
        print("agent says:", (view.get("last_message") or "")[:1000])
        print(
            "steps:",
            [
                (step["seq"], step["action"], step["status"], step["argv"][:2])
                for step in detail["steps"]
            ],
        )
        print("findings:", len(detail["findings"]), "evidence:", len(detail["evidence"]))
        for finding in detail["findings"]:
            print(
                "  finding:",
                finding["severity"],
                finding["status"],
                finding["title"],
                "|",
                finding["canonical_key"],
            )
        print("assets:", sorted({row["asset"] for row in detail["findings"]}))
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
                (row["action"], row["decision"], row["actor"], row["argv"][:2])
                for row in detail["approvals"]
            ],
        )

        if view["status"] != "completed":
            raise AssertionError(f"run ended as {view['status']}")

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
