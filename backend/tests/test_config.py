from pathlib import Path

from app.core.config import BACKEND_DIR, settings


def test_backend_paths_point_at_the_backend_root():
    """A wrong parents[] index silently loads no .env and uses src/data."""
    assert BACKEND_DIR == Path(__file__).resolve().parents[1]
    assert BACKEND_DIR.name == "backend"
    assert settings.data_dir == BACKEND_DIR / "data"
    assert settings.database_url == f"sqlite:///{BACKEND_DIR / 'data' / 'aipent.db'}"
    assert settings.graph_path == BACKEND_DIR / "data" / "graph.sqlite"
