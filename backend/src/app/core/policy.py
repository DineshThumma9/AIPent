"""Action policy engine.

Decides, per action, whether the human gate must interrupt or the action can
execute on its own authority. Policies are loaded from settings and can be
overridden without touching code:

    AIPENT_ACTION_POLICIES='{"sqlmap_scan":{"risk":"high","approve":true},"nmap_scan":{"risk":"low","approve":false}}'

Keys are action names (recon_services, nmap_scan, nikto_scan, dirb_scan,
zap_baseline, sqlmap_scan, http_probe). Values:

- risk: "low" | "medium" | "high"  (display only, for the UI)
- approve: true  -> human must approve at the gate
- approve: false -> execute automatically (agent authority)

Default policy: reconnaissance is free, sqlmap and destructive verbs require
approval, everything else is medium and requires approval.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ActionPolicy:
    risk: str = "medium"
    approve: bool = True

    @property
    def requires_approval(self) -> bool:
        return self.approve


# Sensible defaults: recon is low-risk and free, sqlmap is high-risk and gated.
DEFAULT_ACTION_POLICIES: dict[str, ActionPolicy] = {
    "recon_services": ActionPolicy(risk="low", approve=False),
    "nmap_scan": ActionPolicy(risk="low", approve=False),
    "nikto_scan": ActionPolicy(risk="low", approve=False),
    "dirb_scan": ActionPolicy(risk="low", approve=False),
    "zap_baseline": ActionPolicy(risk="medium", approve=True),
    "http_probe": ActionPolicy(risk="medium", approve=True),
    "sqlmap_scan": ActionPolicy(risk="high", approve=True),
}


def load_policies(overrides: dict[str, Any] | None = None) -> dict[str, ActionPolicy]:
    """Merge default policies with overrides from settings/env.

    Override entries are partial: {"nmap_scan": {"approve": false}} flips only
    the approve flag, keeping the default risk.
    """
    policies = dict(DEFAULT_ACTION_POLICIES)

    if overrides:
        for name, override in overrides.items():
            if not isinstance(override, dict):
                continue
            base = policies.get(name, ActionPolicy())
            policies[name] = ActionPolicy(
                risk=override.get("risk", base.risk),
                approve=override.get("approve", base.approve),
            )

    return policies


def load_policies_from_json(json_text: str | None) -> dict[str, ActionPolicy]:
    if not json_text:
        return dict(DEFAULT_ACTION_POLICIES)
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return dict(DEFAULT_ACTION_POLICIES)
    if not isinstance(data, dict):
        return dict(DEFAULT_ACTION_POLICIES)
    return load_policies(data)
