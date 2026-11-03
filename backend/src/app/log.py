"""One logger for the app: stdout stream plus a rotating file."""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import settings

_root = logging.getLogger("aipent")
_configured = False


def setup_logging(
    level: str | None = None,
    log_file: str | Path | None = None,
    force: bool = False,
) -> Path:
    """Configure the `aipent` logger. Safe to call repeatedly."""
    global _configured
    path = Path(log_file or settings.log_path)
    if _configured and not force:
        return path

    for handler in _root.handlers:
        handler.close()
    _root.handlers.clear()

    path.parent.mkdir(parents=True, exist_ok=True)
    _root.setLevel((level or settings.log_level).upper())
    _root.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s [%(threadName)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    for handler in (
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3, encoding="utf-8"),
    ):
        handler.setFormatter(fmt)
        _root.addHandler(handler)

    _configured = True
    return path


def get_logger(name: str = "") -> logging.Logger:
    setup_logging()
    return _root.getChild(name) if name else _root
