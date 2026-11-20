"""Data models for extracted entities and artifact manifests."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FormField:
    name: str
    type: str = "text"


@dataclass
class FormEntity:
    action: str
    method: str = "GET"
    inputs: list[FormField] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": [{"name": f.name, "type": f.type} for f in self.inputs],
        }


@dataclass
class ParsedEntities:
    routes: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    forms: list[FormEntity] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "routes": self.routes,
            "files": self.files,
            "forms": [f.to_dict() for f in self.forms],
            "keys": self.keys,
            "secrets": self.secrets,
            "comments": self.comments,
        }

    def merge(self, other: ParsedEntities) -> None:
        """Merge another ParsedEntities into self without duplicates."""
        existing_routes = set(self.routes)
        for r in other.routes:
            if r not in existing_routes:
                self.routes.append(r)
                existing_routes.add(r)

        existing_files = set(self.files)
        for f in other.files:
            if f not in existing_files:
                self.files.append(f)
                existing_files.add(f)

        existing_forms = {(f.action, f.method) for f in self.forms}
        for f in other.forms:
            if (f.action, f.method) not in existing_forms:
                self.forms.append(f)
                existing_forms.add((f.action, f.method))

        existing_keys = set(self.keys)
        for k in other.keys:
            if k not in existing_keys:
                self.keys.append(k)
                existing_keys.add(k)

        existing_secrets = set(self.secrets)
        for s in other.secrets:
            if s not in existing_secrets:
                self.secrets.append(s)
                existing_secrets.add(s)

        existing_comments = set(self.comments)
        for c in other.comments:
            if c not in existing_comments:
                self.comments.append(c)
                existing_comments.add(c)
