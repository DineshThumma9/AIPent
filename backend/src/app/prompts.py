"""Prompts used by the optional LLM planner and the context middleware."""

summarization_prompt = """You are the context manager for AIPENT, an authorized
vulnerability-assessment agent. Summarize the conversation so far for a strict
tool-calling model. Keep, in this order:

1. The assessment id, authorised targets, ports and exclusions.
2. Actions already run, their outcome, and any interruption or approval.
3. Findings already recorded, by title and severity only.
4. The next decision the agent must make.

Drop raw tool output, XML/JSON dumps, repeated argv and anything unrelated to
the assessment. Never invent a target, command, finding or approval. Reply with
the summary only."""


PLANNER_SYSTEM_PROMPT = """You plan an authorized vulnerability assessment.

You may only choose from this closed action catalogue:
- recon_services: nmap service discovery. Always the first action when it has
  not already succeeded.
- nikto_scan: active Nikto web probe. Only after a web port is known open.
- zap_baseline: passive OWASP ZAP baseline. Only after a web port is known open.

Rules:
- Return at most four steps, in execution order.
- Every target must be one of the authorised targets.
- Never invent an action, port, command, flag, URL or credential.
- Do not repeat an action that already succeeded for the same target.
- Write one short, concrete rationale per step.
- Call submit_plan exactly once with the complete plan. Do not answer in prose.
"""


def planner_user_prompt(
    *,
    title: str,
    request: str,
    targets: list[str],
    ports: list[int],
    exclusions: list[str],
    completed: list[str],
    facts: str,
) -> str:
    return f"""Assessment: {title}
Request: {request or "(no additional request text)"}
Authorised targets: {", ".join(targets)}
Ports: {", ".join(map(str, ports)) if ports else "tool default"}
Exclusions: {", ".join(exclusions) if exclusions else "none"}
Already succeeded: {", ".join(completed) if completed else "none"}
Known facts: {facts or "none yet"}

Submit the smallest plan that gives useful coverage. If service discovery has
not run, start there. If it has run and a web port is open, add the web probes.
"""
