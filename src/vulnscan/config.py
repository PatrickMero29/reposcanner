"""Central configuration, loaded from environment variables (.env supported via python-dotenv)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str = os.environ.get("GEMINI_API_KEY", "")

    # Reasoning-heavy model for the analyzer. Override with a cheaper/faster
    # model (e.g. "gemini-3.5-flash") to cut cost during development.
    analyzer_model: str = os.environ.get("GEMINI_ANALYZER_MODEL", "gemini-3.1-pro-preview")

    # Separate, typically cheaper, model for the verification-agent pass.
    verifier_model: str = os.environ.get("GEMINI_VERIFIER_MODEL", "gemini-3.5-flash")

    max_output_tokens: int = int(os.environ.get("GEMINI_MAX_OUTPUT_TOKENS", "8192"))
    temperature: float = float(os.environ.get("GEMINI_TEMPERATURE", "0.0"))

    # Retries for transient API errors (rate limits, 5xx).
    max_retries: int = int(os.environ.get("VULNSCAN_MAX_RETRIES", "5"))

    # Concurrency for scanning/benchmark runs.
    max_concurrency: int = int(os.environ.get("VULNSCAN_MAX_CONCURRENCY", "4"))

    dataset_db_path: str = os.environ.get("VULNSCAN_DATASET_DB", "data/cvefixes.duckdb")
    output_dir: str = os.environ.get("VULNSCAN_OUTPUT_DIR", "data/experiments")


settings = Settings()


def require_api_key() -> str:
    if not settings.gemini_api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Export it or put it in a .env file "
            "(see .env.example)."
        )
    return settings.gemini_api_key
