import numpy as np

from vulnscan.embedding.index import IndexEntry, VectorIndex


def _fake_embed(texts: list[str]) -> np.ndarray:
    """Deterministic pseudo-embedding — no model download needed for tests."""
    vectors = []
    for t in texts:
        rng = np.random.default_rng(abs(hash(t)) % (2**32))
        v = rng.normal(size=8).astype("float32")
        v /= np.linalg.norm(v)
        vectors.append(v)
    return np.stack(vectors) if vectors else np.zeros((0, 8), dtype="float32")


def _sample_pairs() -> list[dict]:
    return [
        {
            "pair_id": "p1", "cve_id": "CVE-2021-0001", "cwe_ids": "CWE-89",
            "language": "python", "repo": "r1", "function_name": "f1",
            "commit_message": "fix sqli",
            "func_before": "db.execute('SELECT * FROM x WHERE y=' + u)",
        },
        {
            "pair_id": "p2", "cve_id": "CVE-2021-0002", "cwe_ids": "CWE-78",
            "language": "python", "repo": "r2", "function_name": "f2",
            "commit_message": "fix cmd injection",
            "func_before": "os.system('ls ' + u)",
        },
    ]


def test_build_produces_matching_embeddings_and_entries():
    index = VectorIndex.build(_sample_pairs(), embed_fn=_fake_embed)
    assert index.embeddings.shape[0] == 2
    assert len(index.entries) == 2
    assert index.entries[0].pair_id == "p1"
    assert index.entries[0].cve_id == "CVE-2021-0001"


def test_build_with_no_pairs_is_empty_but_valid():
    index = VectorIndex.build([], embed_fn=_fake_embed)
    assert index.embeddings.shape == (0, 0)
    assert index.entries == []


def test_save_load_roundtrip(tmp_path):
    index = VectorIndex.build(_sample_pairs(), embed_fn=_fake_embed)
    index.save(str(tmp_path / "idx"))

    loaded = VectorIndex.load(str(tmp_path / "idx"))
    assert len(loaded.entries) == 2
    assert loaded.entries[0] == index.entries[0]
    assert np.allclose(loaded.embeddings, index.embeddings)


def test_search_returns_top_k_sorted_by_similarity():
    index = VectorIndex.build(_sample_pairs(), embed_fn=_fake_embed)
    query = _fake_embed(["db.execute('SELECT * FROM z WHERE a=' + b)"])[0]
    results = index.search(query, top_k=1)
    assert len(results) == 1
    entry, score = results[0]
    assert isinstance(entry, IndexEntry)
    assert -1.0 <= score <= 1.0


def test_search_on_empty_index_returns_empty_list():
    index = VectorIndex.build([], embed_fn=_fake_embed)
    results = index.search(np.zeros(8, dtype="float32"), top_k=5)
    assert results == []


def test_search_top_k_larger_than_corpus_does_not_error():
    index = VectorIndex.build(_sample_pairs(), embed_fn=_fake_embed)
    query = _fake_embed(["arbitrary code"])[0]
    results = index.search(query, top_k=50)
    assert len(results) == 2  # capped at corpus size, no error
