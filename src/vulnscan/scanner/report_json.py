from __future__ import annotations

import json
from pathlib import Path

from ..schemas import RepoFinding


def write_json_report(findings: list[RepoFinding], path: str) -> None:
    payload = {
        "finding_count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
