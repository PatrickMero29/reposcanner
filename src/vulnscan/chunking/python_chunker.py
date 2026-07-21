"""Extracts individual top-level and nested function/method definitions from
Python source using the standard library `ast` module, with enough
surrounding context (decorators, containing class signature) to be analyzable
in isolation.
"""

from __future__ import annotations

import ast

from ..schemas import Language
from .base import CodeChunk


def _get_source_segment(source_lines: list[str], node: ast.AST) -> str:
    segment = ast.get_source_segment("\n".join(source_lines), node)
    if segment is not None:
        return segment
    # Fallback for older Pythons / edge cases: slice by line numbers.
    start = node.lineno - 1
    end = getattr(node, "end_lineno", node.lineno)
    return "\n".join(source_lines[start:end])


def chunk_file(file_path: str, source: str) -> list[CodeChunk]:
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    source_lines = source.splitlines()
    chunks: list[CodeChunk] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.class_stack: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.class_stack.append(node.name)
            self.generic_visit(node)
            self.class_stack.pop()

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            qualified_name = ".".join([*self.class_stack, node.name])
            code = _get_source_segment(source_lines, node)
            # Skip trivial stubs (pass-only / docstring-only / ellipsis bodies)
            # — nothing for the analyzer to find here and it just burns tokens.
            meaningful_body = [
                n for n in node.body
                if not (
                    isinstance(n, ast.Expr)
                    and isinstance(getattr(n, "value", None), ast.Constant)
                )
                and not isinstance(n, ast.Pass)
            ]
            if code and meaningful_body:
                chunks.append(CodeChunk(
                    function_name=qualified_name,
                    code=code,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    language=Language.PYTHON,
                    file_path=file_path,
                ))
            # Still descend, in case of nested functions/closures.
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

    Visitor().visit(tree)
    return chunks
