"""Brute-force cosine-similarity vector index over CVE-labeled function pairs.

Deliberately avoids FAISS: for a corpus in the tens-of-thousands range, a
plain numpy matrix-vector product is fast enough (single-digit milliseconds),
and it sidesteps FAISS's notoriously fiddly Windows install. If this index
ever needs to scale past roughly 100k-1M vectors, swapping FAISS/Qdrant in
here is a contained change — nothing outside this module needs to know.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Optional

import numpy as np

logger = logging.getLogger("vulnscan.embedding.index")

EMBEDDINGS_FILENAME = "embeddings.npy"
METADATA_FILENAME = "metadata.jsonl"

# Truncate before embedding — keeps encoding fast and avoids per-model
# max-sequence-length issues on very large functions.
MAX_SNIPPET_CHARS = 4000


@dataclass
class IndexEntry:
    pair_id: str
    cve_id: Optional[str]
    cwe_ids: Optional[str]
    language: str
    repo: Optional[str]
    function_name: Optional[str]
    commit_message: Optional[str]
    snippet_preview: str  # first ~200 chars of the vulnerable function, for display in prompts


class VectorIndex:
    def __init__(self, embeddings: np.ndarray, entries: list[IndexEntry]):
        assert embeddings.shape[0] == len(entries), "embeddings/entries length mismatch"
        self.embeddings = embeddings
        self.entries = entries

    @classmethod
    def build(cls, pairs: list[dict], embed_fn: Callable[[list[str]], np.ndarray]) -> "VectorIndex":
        if not pairs:
            return cls(np.zeros((0, 0), dtype="float32"), [])
        texts = [p["func_before"][:MAX_SNIPPET_CHARS] for p in pairs]
        embeddings = embed_fn(texts)
        entries = [
            IndexEntry(
                pair_id=p["pair_id"],
                cve_id=p.get("cve_id"),
                cwe_ids=p.get("cwe_ids"),
                language=p.get("language", "unknown"),
                repo=p.get("repo"),
                function_name=p.get("function_name"),
                commit_message=p.get("commit_message"),
                snippet_preview=p["func_before"][:200],
            )
            for p in pairs
        ]
        return cls(embeddings, entries)

    def save(self, directory: str) -> None:
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        np.save(out_dir / EMBEDDINGS_FILENAME, self.embeddings)
        with (out_dir / METADATA_FILENAME).open("w", encoding="utf-8") as f:
            for entry in self.entries:
                f.write(json.dumps(asdict(entry)) + "\n")
        logger.info("Saved index with %d entries to %s", len(self.entries), out_dir)

    @classmethod
    def load(cls, directory: str) -> "VectorIndex":
        in_dir = Path(directory)
        embeddings = np.load(in_dir / EMBEDDINGS_FILENAME)
        entries = []
        with (in_dir / METADATA_FILENAME).open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(IndexEntry(**json.loads(line)))
        return cls(embeddings, entries)

    def search(self, query_embedding: np.ndarray, top_k: int = 5) -> list[tuple[IndexEntry, float]]:
        """query_embedding: a single L2-normalized (D,) vector. Returns
        [(entry, cosine_similarity), ...] sorted descending, best match first."""
        if self.embeddings.shape[0] == 0:
            return []
        scores = self.embeddings @ query_embedding  # cosine sim, since both sides are L2-normalized
        k = min(top_k, len(scores))
        top_indices = np.argpartition(-scores, k - 1)[:k]
        top_indices = top_indices[np.argsort(-scores[top_indices])]
        return [(self.entries[i], float(scores[i])) for i in top_indices]
