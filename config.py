"""Application configuration and environment variable loading."""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

load_dotenv(dotenv_path=ENV_FILE)

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "").strip()
NVIDIA_BASE_URL = os.getenv(
    "NVIDIA_BASE_URL",
    "https://integrate.api.nvidia.com/v1"
).strip().rstrip("/")
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "").strip()

APP_NAME = "API Security Analyst"
APP_VERSION = "1.0.0"
DEBUG = os.getenv("DEBUG", "false").lower() == "true"


def validate_llm_config():
    missing = []

    if not NVIDIA_API_KEY:
        missing.append("NVIDIA_API_KEY")

    if not NVIDIA_MODEL:
        missing.append("NVIDIA_MODEL")

    if missing:
        raise ValueError(
            "Missing environment variables: " + ", ".join(missing)
        )
