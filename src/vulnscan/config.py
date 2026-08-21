"""Central configuration, loaded from environment variables (.env supported via python-dotenv)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# src/vulnscan/config.py -> repo root is three levels up. Resolved here
# rather than left as a relative string so it works regardless of the cwd
# vulnscan is invoked from.
_REPO_ROOT = Path(__file__).parent.parent.parent
_SUPPLEMENTARY_RULES_PATH = _REPO_ROOT / "semgrep_rules" / "supplementary_rules.yaml"

# p/security-audit's taint-based rules can't flag os.system/open()/cursor.execute
# built from a plain function parameter with no visible caller providing real
# taint context (confirmed via check_semgrep_coverage.py testing isolated
# snippets) -- 3 canonical patterns (CWE-78 command injection, CWE-22 path
# traversal, CWE-89 SQL injection) came back MISSED for exactly that reason.
# supplementary_rules.yaml adds those 3 as unconditional sink rules instead
# (same trade-off p/security-audit's own pickle/exec/yaml rules already make).
# Verified via check_semgrep_coverage.py: 3/3 caught, 0 false positives across
# 5 safe counterparts (parameterized SQL, os.path.join, list-arg subprocess,
# etc). Only included if the file actually exists, so a fresh clone that
# hasn't set up semgrep_rules/ yet doesn't break -- falls back to
# p/security-audit alone.
_DEFAULT_SEMGREP_CONFIG = "p/security-audit"
if _SUPPLEMENTARY_RULES_PATH.exists():
    _DEFAULT_SEMGREP_CONFIG = f"p/security-audit,{_SUPPLEMENTARY_RULES_PATH}"


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
    # this fully no-telemetry by default. Comma-separated to run multiple
    # rulesets in one pass (run_semgrep splits on "," and passes each as its
    # own --config flag) -- see _DEFAULT_SEMGREP_CONFIG above.
    semgrep_config: str = os.environ.get("SEMGREP_CONFIG", _DEFAULT_SEMGREP_CONFIG)
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