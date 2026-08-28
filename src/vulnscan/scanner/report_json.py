from __future__ import annotations

import json
from pathlib import Path

from ..schemas import ScanReport


def write_json_report(report: ScanReport, path: str) -> None:
    # Confidence descending -- see report_markdown.py's write_ai_finding for
    # why severity alone (always "low" today) isn't a real ranking.
    ai_sorted = sorted(report.ai_findings, key=lambda rf: -rf.finding.confidence)
    payload = {
        "static_finding_count": len(report.static_findings),
        "ai_finding_count": len(report.ai_findings),
        "static_findings": [f.model_dump(mode="json") for f in report.static_findings],
        "ai_findings": [f.model_dump(mode="json") for f in ai_sorted],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")