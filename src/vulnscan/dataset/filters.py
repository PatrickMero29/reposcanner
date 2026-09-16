"""Shared filters for CVEfixes cleaning, CodeSearchNet negatives, and scan-time
test-file skipping. Regexes match ghsa_extract.py so GHSA and CVEfixes drop
the same test paths/names.
"""

from __future__ import annotations

import ast
import re
import textwrap

TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|e2e|specs?|__tests__|fixtures|cypress)/"
    r"|(^|/)(test_[^/]+|conftest|[^/]+_spec|spec_[^/]+)\.py$"
    r"|_test\.py$"
)
TEST_NAME_RE = re.compile(r"(^|\.)test_|^Test")

SINK_RE = re.compile(
    r"(?:os\.system|os\.popen|subprocess\.|pickle\.loads?|yaml\.load|"
    r"\beval\s*\(|\bexec\s*\(|urlopen\s*\(|\bopen\s*\(|"
    r"redirect\s*\(|\.execute\s*\(|shell\s*=\s*True)",
    re.IGNORECASE,
)

MIN_NONEMPTY_LINES = 4
MIN_TOKENS = 40


def is_test_path(path: str | None) -> bool:
    if not path:
        return False
    normalized = str(path).replace("\\", "/")
    return bool(TEST_PATH_RE.search(normalized))


def is_test_function(function_name: str | None) -> bool:
    if not function_name:
        return False
    return bool(TEST_NAME_RE.search(function_name))


def contains_sink(code: str | None) -> bool:
    if not code:
        return False
    return bool(SINK_RE.search(code))


def diff_hits_sink(before: str, after: str) -> bool:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    changed: list[str] = []
    for i, line in enumerate(before_lines):
        if i >= len(after_lines) or line != after_lines[i]:
            changed.append(line)
    if len(after_lines) > len(before_lines):
        changed.extend(after_lines[len(before_lines):])
    if not changed:
        return contains_sink(before) or contains_sink(after)
    return contains_sink("\n".join(changed))


def dedent_code(code: str) -> str:
    return textwrap.dedent(code or "").strip("\n") + ("\n" if code else "")


def is_parseable_function(code: str) -> bool:
    text = textwrap.dedent(code or "")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return True
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return True
    return False


def meets_min_size(code: str, *, min_lines: int = MIN_NONEMPTY_LINES, min_tokens: int = MIN_TOKENS) -> bool:
    nonempty = [ln for ln in (code or "").splitlines() if ln.strip()]
    tokens = (code or "").split()
    return len(nonempty) >= min_lines or len(tokens) >= min_tokens
