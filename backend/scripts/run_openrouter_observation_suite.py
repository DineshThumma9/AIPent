"""AIPENT Observation Suite: 5 Distinct OWASP Juice Shop Challenges with OpenRouter.

Delegates to the unified observation suite with mode="openrouter".
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR / "src"))
sys.path.insert(0, str(BACKEND_DIR / "scripts"))

from run_hybrid_observation_suite import get_challenges, main, run_single_challenge

CHALLENGES = get_challenges("openrouter")

if __name__ == "__main__":
    asyncio.run(main(mode="openrouter"))
