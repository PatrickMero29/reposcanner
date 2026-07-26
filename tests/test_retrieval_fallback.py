from vulnscan.embedding.retrieve import retrieve_similar_cves


def test_retrieve_returns_empty_when_no_index_built():
    """With no index built (the default state — settings.embedding_index_dir
    points at a directory that doesn't exist in a fresh checkout/test run),
    retrieval should quietly return no evidence rather than raising."""
    results = retrieve_similar_cves("def foo(): pass")
    assert results == []
