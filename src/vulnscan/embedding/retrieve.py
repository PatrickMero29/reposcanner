"""Retrieval helper: given a code snippet, find similar historical CVEs from
the local index (if one has been built). This is what lets the analyzer
answer "have I seen something like this before, and what was it" instead of
judging vulnerability from first principles alone every time.

Retrieval is deliberately a nice-to-have, not a hard dependency: if no index
has been built yet, or the embeddings package isn't installed, this quietly
returns no evidence rather than failing the whole analysis.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import settings
from .encoder import embed_texts
from .index import IndexEntry, VectorIndex

logger = logging.getLogger("vulnscan.embedding.retrieve")

_index: VectorIndex | None = None
_index_missing_logged = False


def _load_index_if_available() -> VectorIndex | None:
    global _index, _index_missing_logged
    if _index is not None:
        return _index
    index_dir = Path(settings.embedding_index_dir)
    if not (index_dir / "embeddings.npy").exists():
        if not _index_missing_logged:
            logger.info(
                "No CVE similarity index found at %s — analyzing without retrieval evidence. "
                "Run `vulnscan build-index` to enable it.",
                index_dir,
            )
            _index_missing_logged = True
        return None
    _index = VectorIndex.load(str(index_dir))
    return _index


def retrieve_similar_cves(
    code: str, top_k: int | None = None, *, exclude_pair_id: str | None = None
) -> list[tuple[IndexEntry, float]]:
    """Returns up to top_k (entry, cosine_similarity) pairs, or [] if no
    index exists yet or retrieval fails for any reason. Never raises.

    exclude_pair_id: pass the pair_id currently being analyzed when the
    index might contain that exact row (i.e. from bench-analyze querying
    the benchmark dataset -- the same data the index was built from). Live
    `vulnscan scan` code has no pair_id and doesn't need this: it's scanning
    arbitrary external code that was never in the index to begin with, so
    leaving this None there is correct, not an oversight. Without this,
    retrieval can find the exact row being queried sitting in its own
    index -- cosine similarity ~1.0 against its own true label, a
    guaranteed-correct match for free that inflated judge.py's
    cwe_confirmed_recall (confirmed: v19's benchmark run showed this
    metric nearly double in a way the absolute true-positive counts
    couldn't otherwise explain)."""
    index = _load_index_if_available()
    if index is None:
        return []
    top_k = top_k or settings.retrieval_top_k
    try:
        query_embedding = embed_texts([code])[0]
        # Over-fetch when excluding, so filtering out a self-match still
        # leaves top_k real results instead of silently returning fewer.
        raw_k = top_k + 1 if exclude_pair_id else top_k
        results = index.search(query_embedding, top_k=raw_k)
        if exclude_pair_id:
            results = [(e, s) for e, s in results if e.pair_id != exclude_pair_id]
        return results[:top_k]
    except Exception:  # noqa: BLE001 — retrieval failing should never break analysis
        logger.exception("Retrieval failed — continuing without evidence.")
        return []