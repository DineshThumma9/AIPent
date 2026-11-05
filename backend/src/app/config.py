"""One place for every path, limit and model setting. Env vars use AIPENT_."""

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
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

    max_steps: int = 8
    scan_timeout: int = 300
    run_timeout: int = 900

    nikto_bin: str = ""
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable"

    llm_provider: str = "groq"
    llm_model: str = "openai/gpt-oss-120b"
    summarization_llm: str = "openai/gpt-oss-20b"
    llm_base_url: str | None = None
    llm_timeout: int = 30
    llm_max_tokens: int = 900
    model_exit_behavior: Literal["end", "error"] = "end"
    tool_exit_behaviour: Literal["continue", "error", "end"] = "continue"

    mcp_enabled: bool = False
    mcp_transport: Literal["local", "gateway"] = "local"
    mcp_gateway_url: str = "http://127.0.0.1:8812/sse"
    mcp_timeout: int = 600
    mcp_handshake_timeout: int = 30
    lab_target_alias: str = "host.docker.internal"

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


settings = Settings()
