"""Language-specific code chunkers.

Each chunker turns a source file into a list of `CodeChunk` (roughly:
"one function/method, with enough surrounding context to analyze it").
To add a new language, add a `<lang>_chunker.py` module exposing a
`chunk_file(path: str, source: str) -> list[CodeChunk]` function, and
register it in `CHUNKERS_BY_EXTENSION` below.
"""

from __future__ import annotations

from ..schemas import Language
from .base import CodeChunk
from .python_chunker import chunk_file as _chunk_python

CHUNKERS_BY_EXTENSION = {
    ".py": (_chunk_python, Language.PYTHON),
    # ".java": (_chunk_java, Language.JAVA),      # TODO: add java_chunker.py
    # ".c": (_chunk_c, Language.C),                # TODO: add c_chunker.py
    # ".cpp": (_chunk_c, Language.CPP),
    # ".js": (_chunk_js, Language.JAVASCRIPT),
}


def chunk_source_file(file_path: str, source: str) -> list[CodeChunk]:
    for ext, (chunker, _lang) in CHUNKERS_BY_EXTENSION.items():
        if file_path.endswith(ext):
            return chunker(file_path, source)
    return []
