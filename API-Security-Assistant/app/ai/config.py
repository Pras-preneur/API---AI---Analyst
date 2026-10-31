"""AI/ML Configuration and environment variable loading."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR.parent.parent / ".env"

try:
    from dotenv import load_dotenv
    if ENV_FILE.exists():
        load_dotenv(dotenv_path=ENV_FILE)
except ImportError:
    if ENV_FILE.exists():
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v

# NVIDIA Nemotron LLM Configuration (Optional; defensive offline fallback if missing)
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "").strip()
NVIDIA_BASE_URL = os.getenv(
    "NVIDIA_BASE_URL",
    "https://integrate.api.nvidia.com/v1"
).strip().rstrip("/")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3.5-bolt-e4b").strip()

# Path to trained Random Forest model
MODEL_PATH = Path(__file__).resolve().parent / "models" / "priority_model.joblib"


def has_llm_config() -> bool:
    """Return True if an external LLM API key and model are configured."""
    return bool(NVIDIA_API_KEY and NVIDIA_MODEL)
