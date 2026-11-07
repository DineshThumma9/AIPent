"""One place for every path, limit and model setting. Env vars use AIPENT_."""

import os
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# src/app/core/config.py -> backend/
BACKEND_DIR = Path(__file__).resolve().parents[3]
# Conventional provider keys live in .env without the AIPENT_ prefix. Loading
# the file here lets LangChain clients see them without exporting them twice.
load_dotenv(BACKEND_DIR / ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AIPENT_",
        env_file=BACKEND_DIR / ".env",
        extra="ignore",
    )

    data_dir: Path = BACKEND_DIR / "data"
    db: str | None = None
    artifacts_dir: Path | None = None
    graph_db: Path | None = None

    log_level: str = "INFO"
    log_file: Path | None = None

    max_steps: int = 12
    max_agent_turns: int = 12
    agent_recursion_limit: int = 30
    scan_timeout: int = 300
    run_timeout: int = 900

    nikto_bin: str = ""
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable"

    llm_provider: str = "ollama"
    llm_model: str = "beam:cloud"
    summarization_llm: str = "openai/gpt-oss-20b"
    llm_base_url: str | None = None
    llm_timeout: int = 120
    llm_max_tokens: int = 4000
    model_exit_behavior: Literal["end", "error"] = "end"
    tool_exit_behaviour: Literal["continue", "error", "end"] = "continue"

    # Per-provider models (used as fallback when primary hits token limits).
    # Populated from AIPENT_*_MODEL env vars (e.g. AIPENT_GROQ_MODEL).
    groq_model: str | None = None
    mistral_model: str | None = None
    ollama_model: str | None = None
    gemini_model: str | None = None
    openrouter_model: str | None = None
    huggingface_model: str | None = None

    # Ollama Cloud base URL (e.g. https://ollama.com). If unset, uses local Ollama.
    ollama_base_url: str | None = os.getenv("OLLAMA_BASE_URL")

    # Action policy: per-action gate requirements. JSON string or dict.
    # Example: AIPENT_ACTION_POLICIES='{"sqlmap_scan":{"approve":true},"nmap_scan":{"approve":false}}'
    action_policies_json: str | None = None

    mcp_enabled: bool = False
    mcp_transport: Literal["local", "gateway"] = "local"
    mcp_gateway_url: str = "http://127.0.0.1:8812/sse"
    mcp_timeout: int = 600
    mcp_handshake_timeout: int = 30
    lab_target_alias: str = "host.docker.internal"
    juiceshop_url: str = "http://127.0.0.1:3000"

    # Per-run agent budgets. The LLM chooses actions; these bounds stop a loop.
    max_validation_probes: int = 10

    @property
    def database_url(self) -> str:
        return self.db or f"sqlite:///{self.data_dir / 'aipent.db'}"

    @property
    def artifacts_path(self) -> Path:
        return self.artifacts_dir or self.data_dir / "artifacts"

    @property
    def graph_path(self) -> Path:
        return self.graph_db or self.data_dir / "graph.sqlite"

    @property
    def log_path(self) -> Path:
        return self.log_file or self.data_dir / "aipent.log"

    @property
    def groq_api_key(self) -> str | None:
        return os.getenv("AIPENT_GROQ_API_KEY") or os.getenv("GROQ_API_KEY")

    @property
    def mistral_api_key(self) -> str | None:
        return os.getenv("AIPENT_MISTRAL_API_KEY") or os.getenv("MISTRALAI_API_KEY")

    @property
    def ollama_api_key(self) -> str | None:
        return os.getenv("AIPENT_OLLAMA_API_KEY") or os.getenv("OLLAMA_API_KEY")

    @property
    def gemini_api_key(self) -> str | None:
        return os.getenv("AIPENT_GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY")

    @property
    def openrouter_api_key(self) -> str | None:
        return os.getenv("AIPENT_OPENROUTER_API_KEY") or os.getenv("OPENROUTER_API_KEY")

    @property
    def huggingface_api_key(self) -> str | None:
        return os.getenv("AIPENT_HUGGINGFACE_API_KEY") or os.getenv("HUGGINGFACE_API_KEY")


settings = Settings()
