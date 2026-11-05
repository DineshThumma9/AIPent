"""Skill package root. Exports the loader and registry."""
from app.skills.loader import SkillRegistry, SkillRegistry as get_registry

__all__ = ["SkillRegistry", "get_registry"]