"""One place for every path, limit and model setting. Env vars use AIPENT_."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


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
    scan_timeout: int = 180

    llm_provider: str = "gemini"
    llm_model: str = "gemini-2.5-flash"
    llm_api_key: str | None = None
    llm_base_url: str | None = None

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


settings = Settings()
