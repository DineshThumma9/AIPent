"""Run-start runtime manifest: models, budgets and tool surfaces.

The manifest is built once per run, logged as a banner, attached to the
``run.requested`` audit event, and copied into graph state so the CLI/UI can
show exactly what the run is allowed to do.
"""

from __future__ import annotations

from typing import Any

from app.agents.mission_brain import ROLE_TURN_CAPS
from app.agents.model import role_model_config, thinkings_levels
from app.agents.tool_specs import ROLE_TOOLS
from app.core.config import settings
from app.core.log import get_logger

log = get_logger("agent.run")


def build_run_manifest(assessment_id: int | None = None) -> dict[str, Any]:
    """Resolve the complete, current runtime configuration for a run."""
    tools: dict[str, list[str]] = {}
    for role, specs in ROLE_TOOLS.items():
        names: list[str] = []
        for spec in specs:
            for value in (getattr(spec, "name", None), getattr(spec, "action", None)):
                if value and value not in names:
                    names.append(value)
        tools[role] = names

    return {
        "assessment_id": assessment_id,
        "models": role_model_config(),
        "thinking": {role: level.name for role, level in thinkings_levels.items()},
        "tool_limits": {
            role: {
                "tool_thread_limit": level.value.tool_thread_limit,
                "tool_run_limit": level.value.tool_run_limit,
                "model_thread_limit": level.value.model_thread_limit,
                "model_run_limit": level.value.model_run_limit,
            }
            for role, level in thinkings_levels.items()
        },
        "budgets": {
            "role_turn_caps": dict(ROLE_TURN_CAPS),
            "max_agent_turns": settings.max_agent_turns,
            "max_steps": settings.max_steps,
            "supervisor_calls_per_run": settings.supervisor_calls_per_run,
            "max_no_progress": settings.max_no_progress,
            "max_role_retries": settings.max_role_retries,
            "max_validation_probes": settings.max_validation_probes,
            "agent_recursion_limit": settings.agent_recursion_limit,
            "scan_timeout": settings.scan_timeout,
            "run_timeout": settings.run_timeout,
            "llm_timeout": settings.llm_timeout,
            "llm_max_tokens": settings.llm_max_tokens,
        },
        "tools": tools,
        "tool_counts": {role: len(names) for role, names in tools.items()},
        "notes": [
            "Supervisor routing is one structured RouteDecision call per handoff (no tool loop).",
            "Explorer actions pass through the policy layer and human approval before execution.",
        ],
    }


def log_run_manifest(manifest: dict[str, Any]) -> None:
    """Write the manifest as a readable, greppable run-start banner."""
    assessment_id = manifest.get("assessment_id")
    log.info("run %s runtime configuration:", assessment_id)
    for role, cfg in (manifest.get("models") or {}).items():
        log.info(
            "  model %-12s %-12s %-45s thinking=%s",
            role,
            cfg.get("provider", "?"),
            cfg.get("model", "?"),
            (manifest.get("thinking") or {}).get(role, "-"),
        )
    for role, limits in (manifest.get("tool_limits") or {}).items():
        log.info(
            "  call  %-12s tool_thread=%s tool_run=%s model_thread=%s model_run=%s",
            role,
            limits.get("tool_thread_limit"),
            limits.get("tool_run_limit"),
            limits.get("model_thread_limit"),
            limits.get("model_run_limit"),
        )
    for role, count in (manifest.get("tool_counts") or {}).items():
        log.info(
            "  tools %-12s %-3s %s",
            role,
            count,
            ", ".join((manifest.get("tools") or {}).get(role, [])),
        )
    for key, value in (manifest.get("budgets") or {}).items():
        log.info("  limit %-28s %s", key, value)
