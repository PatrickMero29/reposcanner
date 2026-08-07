"""Central configuration, loaded from environment variables (.env supported via python-dotenv)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    # Concurrency for scanning runs (local model inference — bounded by your
    # GPU, not an API rate limit; keep this modest unless you know your VRAM
    # comfortably fits multiple concurrent forward passes).
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
    # no-ops and every function goes straight to the local model.
    enable_semgrep_prefilter: bool = os.environ.get("ENABLE_SEMGREP_PREFILTER", "true").strip().lower() in ("1", "true", "yes")
    # "auto" requires metrics/telemetry enabled (it phones home to pick
    # rulesets for you) — defaulting to a fixed registry pack instead keeps
    # this fully no-telemetry by default.
    semgrep_config: str = os.environ.get("SEMGREP_CONFIG", "p/security-audit")
    semgrep_timeout: int = int(os.environ.get("SEMGREP_TIMEOUT", "300"))

    # Local trained classifier (see src/vulnscan/local_model/ and
    # src/vulnscan/training/). Requires the `ml` install extra (torch +
    # transformers). If no checkpoint exists at this path yet, the scanner
    # runs fine without it — you just get Semgrep's static findings until
    # you train a model with `vulnscan train-model`.
    local_model_checkpoint_dir: str = os.environ.get("LOCAL_MODEL_CHECKPOINT_DIR", "models/vuln-classifier")
    local_model_base: str = os.environ.get("LOCAL_MODEL_BASE", "microsoft/codebert-base")
    # "auto" resolves to cuda if available, else cpu, at inference time
    # (checked lazily inside local_model/inference.py — config.py itself
    # never imports torch, so it stays a light import even without the `ml`
    # extra installed).
    local_model_device: str = os.environ.get("LOCAL_MODEL_DEVICE", "auto")
    local_model_max_length: int = int(os.environ.get("LOCAL_MODEL_MAX_LENGTH", "512"))
    local_model_confidence_threshold: float = float(os.environ.get("LOCAL_MODEL_CONFIDENCE_THRESHOLD", "0.5"))


settings = Settings()