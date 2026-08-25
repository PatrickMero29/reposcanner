from vulnscan.chunking import chunk_source_file
from vulnscan.chunking.python_chunker import chunk_file
from vulnscan.schemas import Language


SAMPLE_SOURCE = '''
import os

def safe_join(base, name):
    """A stub docstring-only function should be skipped if body is trivial."""
    ...

def run_command(user_input):
    cmd = "ls " + user_input
    os.system(cmd)
    return cmd

class Handler:
    def handle(self, request):
        query = f"SELECT * FROM users WHERE id = {request.id}"
        return query
'''


def test_chunk_file_skips_stub_functions():
    chunks = chunk_file("sample.py", SAMPLE_SOURCE)
    names = {c.function_name for c in chunks}
    assert "safe_join" not in names, "docstring/ellipsis-only stubs should be skipped"


def test_chunk_file_finds_top_level_function():
    chunks = chunk_file("sample.py", SAMPLE_SOURCE)
    names = {c.function_name for c in chunks}
    assert "run_command" in names


def test_chunk_file_finds_method_with_qualified_name():
    chunks = chunk_file("sample.py", SAMPLE_SOURCE)
    names = {c.function_name for c in chunks}
    assert "Handler.handle" in names


def test_chunk_file_sets_correct_language():
    chunks = chunk_file("sample.py", SAMPLE_SOURCE)
    assert all(c.language == Language.PYTHON for c in chunks)


def test_chunk_source_file_dispatches_by_extension():
    chunks = chunk_source_file("sample.py", SAMPLE_SOURCE)
    assert len(chunks) >= 2

    chunks_unknown_ext = chunk_source_file("sample.unknownlang", SAMPLE_SOURCE)
    assert chunks_unknown_ext == []


def test_chunk_file_handles_syntax_errors_gracefully():
    chunks = chunk_file("broken.py", "def broken(:\n    pass")
    assert chunks == []


NESTED_CLOSURE_SOURCE = '''
import os

def make_runner(base_cmd):
    def run(user_input):
        os.system(base_cmd + user_input)
        return True
    return run
'''


def test_chunk_file_does_not_double_chunk_nested_closures():
    # Regression test for HANDOFF_2.md §8.1: a function containing a nested
    # closure used to be chunked twice -- once whole, once again as an
    # isolated, context-stripped fragment for the closure alone (which
    # references outer-scope variables like `base_cmd` it can't see on its
    # own). The closure should now only appear as part of its enclosing
    # function's chunk.
    chunks = chunk_file("sample.py", NESTED_CLOSURE_SOURCE)
    names = [c.function_name for c in chunks]
    assert names == ["make_runner"], "nested closure `run` should not be a separate chunk"
    assert "def run(user_input):" in chunks[0].code, "closure should still be present in the parent's source"