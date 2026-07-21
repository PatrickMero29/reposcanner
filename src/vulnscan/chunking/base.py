from __future__ import annotations

from dataclasses import dataclass

from ..schemas import Language


@dataclass
class CodeChunk:
    function_name: str
    code: str
    start_line: int
    end_line: int
    language: Language
    file_path: str
