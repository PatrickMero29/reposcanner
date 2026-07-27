import dataclasses

import vulnscan.embedding.retrieve as retrieve_module
from vulnscan.config import settings as real_settings


def test_retrieve_returns_empty_when_no_index_built(tmp_path, monkeypatch):
    """Retrieval must quietly return no evidence when pointed at a directory
    with no index — regardless of whether some OTHER index happens to exist
    in the real working directory (e.g. a dev environment that has already
    run `vulnscan build-index` for real testing). The test must not depend on
    incidental filesystem state; it points settings at a guaranteed-empty
    tmp_path instead of relying on the default relative path being absent.
    """
    fake_settings = dataclasses.replace(
        real_settings, embedding_index_dir=str(tmp_path / "no_index_here")
    )
    monkeypatch.setattr(retrieve_module, "settings", fake_settings)
    # Reset the module-level cache too, in case an earlier test in the same
    # session already loaded a real index into it.
    monkeypatch.setattr(retrieve_module, "_index", None)
    monkeypatch.setattr(retrieve_module, "_index_missing_logged", False)

    results = retrieve_module.retrieve_similar_cves("def foo(): pass")
    assert results == []