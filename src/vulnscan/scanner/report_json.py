from __future__ import annotations

import json
from pathlib import Path

from ..schemas import ScanReport


def write_json_report(report: ScanReport, path: str) -> None:
    payload = {
        "static_finding_count": len(report.static_findings),
        "ai_finding_count": len(report.ai_findings),
        "static_findings": [f.model_dump(mode="json") for f in report.static_findings],
        "ai_findings": [f.model_dump(mode="json") for f in report.ai_findings],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
