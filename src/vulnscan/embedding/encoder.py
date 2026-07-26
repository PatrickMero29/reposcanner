"""Local, free code-embedding model wrapper — no API calls, no per-use cost.

Uses sentence-transformers to embed code snippets for CVE similarity search.
This is intentionally a separate install extra (`pip install -e ".[embeddings]"`)
since sentence-transformers pulls in torch, which is a large, sometimes fiddly
install (especially on Windows) — no reason to force it on people who only
want the plain scanner/benchmark.
"""

from __future__ import annotations

import logging

import numpy as np

from ..config import settings

logger = logging.getLogger("vulnscan.embedding")

_model = None


def get_encoder():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "sentence-transformers is not installed. Install it with "
                '`pip install -e ".[embeddings]"` to enable CVE retrieval, '
                "or set ENABLE_RETRIEVAL=false in .env to run without it."
            ) from exc
        logger.info(
            "Loading embedding model %s (first run downloads it; cached afterward)...",
            settings.embedding_model,
        )
        _model = SentenceTransformer(settings.embedding_model)
    return _model


def embed_texts(texts: list[str]) -> np.ndarray:
    """Embed a batch of code strings. Returns an (N, D) float32 array,
    L2-normalized so cosine similarity is a plain dot product."""
    if not texts:
        return np.zeros((0, 0), dtype="float32")
    model = get_encoder()
    embeddings = model.encode(
        texts, normalize_embeddings=True, show_progress_bar=False, convert_to_numpy=True
    )
    return embeddings.astype("float32")
