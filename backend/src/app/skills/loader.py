"""Base skill interface and registry."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json
import importlib.util
import sys


@dataclass
class SkillMetadata:
    name: str
    title: str
    description: str  # ≤240 chars, includes "Use when"
    version: str = "1.0.0"
    category: str = "verification"
    tags: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)  # Finding patterns that activate this skill


@dataclass
class ProbeSpec:
    action: str = "curl_tool"
    target: str = ""
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    expected_status: int = 200
    rationale: str = ""


@dataclass
class SkillInvocationResult:
    skill_name: str
    finding_id: int
    hypothesis: str
    probes: list[ProbeSpec] = field(default_factory=list)
    reasoning: str = ""
    error: str | None = None


class Skill(ABC):
    """Base class for verification skills."""

    @property
    @abstractmethod
    def metadata(self) -> SkillMetadata:
        pass

    @abstractmethod
    def generate_probes(self, finding: dict, hypothesis: str, assessment: dict) -> SkillInvocationResult:
        """Generate verification probes for a finding.
        
        Args:
            finding: Finding dict with canonical_key, title, description, endpoint, evidence
            hypothesis: LLM's testable hypothesis
            assessment: Assessment context (targets, ports, etc.)
        Returns:
            SkillInvocationResult with probes and reasoning
        """
        pass

    @abstractmethod
    def evaluate(self, probe_results: list[dict], finding: dict) -> tuple[str, str]:
        """Evaluate probe results and return (status, reasoning).
        
        Args:
            probe_results: List of {probe: ProbeSpec, response: {status_code, headers, body, timing}}
            finding: Original finding
        Returns:
            (status, reasoning) where status ∈ {"confirmed", "false_positive", "suspected"}
        """
        pass


class SkillRegistry:
    """Loads and manages all skill packages."""

    def __init__(self, skills_dir: Path | None = None):
        self._skills: dict[str, Skill] = {}
        self._metadata: dict[str, SkillMetadata] = {}
        self._skills_dir = skills_dir or Path(__file__).parent
        self._load_all()

    def _load_all(self):
        for skill_dir in self._skills_dir.iterdir():
            if skill_dir.is_dir() and skill_dir.name.startswith("skill-"):
                try:
                    skill = self._load_skill(skill_dir)
                    self._skills[skill.metadata.name] = skill
                    self._metadata[skill.metadata.name] = skill.metadata
                except Exception as e:
                    print(f"Failed to load skill {skill_dir.name}: {e}")

    def _load_skill(self, skill_dir: Path) -> Skill:
        # Load SKILL.md metadata from frontmatter or scripts/__init__.py
        init_file = skill_dir / "scripts" / "__init__.py"
        if not init_file.exists():
            raise ValueError(f"No scripts/__init__.py in {skill_dir}")

        spec = importlib.util.spec_from_file_location(f"skill_{skill_dir.name}", init_file)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        # Expect module to export `skill` instance
        if not hasattr(module, "skill"):
            raise ValueError(f"Skill module must export 'skill' instance")
        return module.skill

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def get_metadata(self, name: str) -> SkillMetadata | None:
        return self._metadata.get(name)

    def get_allowed_for_agent(self, agent_name: str) -> list[SkillMetadata]:
        """Return metadata for skills allowed for a specific agent."""
        agent_skills = AGENT_SKILL_MAP.get(agent_name, [])
        return [self._metadata[name] for name in agent_skills if name in self._metadata]

    def list_all(self) -> list[SkillMetadata]:
        return list(self._metadata.values())


# Agent → Allowed Skills Mapping
AGENT_SKILL_MAP = {
    "recon_agent": ["header_misconfig_triage"],
    "discovery_agent": ["header_misconfig_triage", "sensitive_storage"],
    "validation_agent": [
        "spa_route_discovery",
        "sensitive_storage",
        "header_misconfig_triage",
        "sqli_safe_verification",
    ],
}

# Global registry instance
SKILL_REGISTRY = SkillRegistry()