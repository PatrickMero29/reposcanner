"""Central configuration, loaded from environment variables (.env supported via python-dotenv)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str = os.environ.get("ANTHROPIC_API_KEY", "")

    # Reasoning-heavy model for the analyzer. Override with a cheaper/faster
    # model to cut cost during development.
    analyzer_model: str = os.environ.get("ANALYZER_MODEL", "claude-sonnet-5")

    # Separate, typically cheaper/faster, model for the verification-agent
    # pass and the benchmark's CVE judge.
    verifier_model: str = os.environ.get("VERIFIER_MODEL", "claude-haiku-4-5-20251001")

    max_output_tokens: int = int(os.environ.get("MAX_OUTPUT_TOKENS", "8192"))
    temperature: float = float(os.environ.get("MODEL_TEMPERATURE", "0.0"))

    # Retries for transient API errors (rate limits, 5xx).
    max_retries: int = int(os.environ.get("VULNSCAN_MAX_RETRIES", "5"))

    # Concurrency for scanning/benchmark runs.
    max_concurrency: int = int(os.environ.get("VULNSCAN_MAX_CONCURRENCY", "4"))

    dataset_db_path: str = os.environ.get("VULNSCAN_DATASET_DB", "data/cvefixes.duckdb")
    output_dir: str = os.environ.get("VULNSCAN_OUTPUT_DIR", "data/experiments")

    # CVE retrieval (optional — see src/vulnscan/embedding/). Requires the
    # `embeddings` install extra; if that's not installed, retrieval just
    # quietly no-ops rather than failing analysis.
    enable_retrieval: bool = os.environ.get("ENABLE_RETRIEVAL", "true").strip().lower() in ("1", "true", "yes")
    embedding_model: str = os.environ.get(
        "EMBEDDING_MODEL", "flax-sentence-embeddings/st-codesearch-distilroberta-base"
    )
    embedding_index_dir: str = os.environ.get("EMBEDDING_INDEX_DIR", "data/cve_index")
    retrieval_top_k: int = int(os.environ.get("RETRIEVAL_TOP_K", "5"))

    # Semgrep static-analysis pre-filter (optional — see src/vulnscan/rules/).
    # Requires the `semgrep` CLI on PATH; if it's not installed, this quietly
    # no-ops and every function goes straight to the AI engine, same as before
    # this feature existed.
    enable_semgrep_prefilter: bool = os.environ.get("ENABLE_SEMGREP_PREFILTER", "true").strip().lower() in ("1", "true", "yes")
    semgrep_config: str = os.environ.get("SEMGREP_CONFIG", "auto")
    semgrep_timeout: int = int(os.environ.get("SEMGREP_TIMEOUT", "300"))


settings = Settings()


def require_api_key() -> str:
    if not settings.anthropic_api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Export it or put it in a .env file "
            "(see .env.example)."
        )
    return settings.anthropic_api_key
