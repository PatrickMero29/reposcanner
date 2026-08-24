"""Wraps the Semgrep CLI as a fast, free, local static-analysis pre-filter.

This is the "Rule Engine (Fast)" half of the two-stage architecture: Semgrep
runs first, entirely locally, and flags candidate lines/functions. Only
flagged functions get sent to your locally-trained classifier (the "AI
Engine (Deep Analysis)" stage) — everything else is skipped, which is
where the actual cost/time savings come from.

Semgrep is a separate CLI tool, not a Python-importable library, so this
module shells out to the `semgrep` binary and parses its JSON output
(validated against a real local run — see the `columns`/JSON shape below).
It degrades gracefully if semgrep isn't installed: callers get an empty
result and a log message, never an exception, so a missing/broken semgrep
install never breaks a scan — it just runs without the pre-filter.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("vulnscan.rules.semgrep")

_CWE_PATTERN = re.compile(r"CWE-\d+")

# semgrep's own severities map onto our Severity enum this way. Anything not
# listed here (semgrep does have a few other values in some rulesets) falls
# back to MEDIUM rather than erroring.
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "CRITICAL": "critical",
}


@dataclass
class SemgrepFinding:
    rule_id: str
    message: str
    file_path: str  # relative to the scanned root, as reported by semgrep
    start_line: int
    end_line: int
    severity: str  # normalized to our Severity enum's string values
    cwe_ids: list[str]


def is_semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _extract_cwe_ids(raw_cwe_field) -> list[str]:  # noqa: ANN001
    """semgrep's metadata.cwe entries look like 'CWE-78: OS Command Injection'
    — pull out just the canonical 'CWE-78' part to match this project's other
    cwe_ids fields (schemas.UndesiredOperation.cwe_ids etc)."""
    if not raw_cwe_field:
        return []
    raw_list = raw_cwe_field if isinstance(raw_cwe_field, list) else [raw_cwe_field]
    ids = []
    for entry in raw_list:
        match = _CWE_PATTERN.search(str(entry))
        if match:
            ids.append(match.group(0))
    return ids


def run_semgrep(
    target_path: str,
    *,
    config: str | list[str] = "auto",
    timeout: int = 300,
) -> list[SemgrepFinding]:
    """Run semgrep against target_path and return parsed findings.

    config accepts either a single ruleset string ("p/security-audit"), a
    comma-separated string ("p/security-audit,p/secrets"), or a list of
    rulesets — all get passed to semgrep as repeated --config flags in one
    invocation (semgrep natively supports combining multiple rulesets this
    way), so results reflect ALL of them, not just the last one.

    Never raises: any failure (semgrep not installed, timeout, bad JSON,
    non-zero exit for a real error) is logged and results in an empty list,
    so a broken semgrep install degrades to "no pre-filter" rather than
    breaking the scan.
    """
    if not is_semgrep_available():
        logger.info(
            "semgrep not found on PATH — skipping static pre-filter, every function will go "
            "straight to the AI analyzer. Install with `pip install semgrep` (or `pip install "
            '-e ".[semgrep]"`) to enable it.'
        )
        return []

    if isinstance(config, str):
        configs = [c.strip() for c in config.split(",") if c.strip()]
    else:
        configs = list(config)
    if not configs:
        configs = ["auto"]

    with tempfile.TemporaryDirectory() as tmp_dir:
        json_out_path = Path(tmp_dir) / "semgrep_out.json"
        cmd = ["semgrep", "scan"]
        for c in configs:
            cmd += ["--config", c]
        cmd += ["--json-output", str(json_out_path), "--quiet", target_path]
        # semgrep's "auto" config mode requires metrics/telemetry enabled (it
        # phones home to pick rulesets based on the repo) — --metrics=off is
        # only safe to add when "auto" isn't one of the requested rulesets.
        # Since offline/no-telemetry operation matters here, the default
        # config is a fixed ruleset (see config.py), not "auto" — but this
        # stays defensive in case a caller explicitly includes "auto".
        if "auto" not in configs:
            cmd.append("--metrics=off")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "semgrep timed out after %ss on %s — continuing without static pre-filter for this run.",
                timeout, target_path,
            )
            return []
        except FileNotFoundError:
            logger.info("semgrep not found — skipping static pre-filter.")
            return []

        # semgrep's exit codes: 0 = ran clean with no findings, 1 = ran clean
        # WITH findings (not an error). Anything else is a real problem, but
        # we still try to parse whatever JSON it managed to write, since
        # partial results (e.g. one file failed to parse) beat nothing.
        if result.returncode not in (0, 1):
            logger.warning(
                "semgrep exited with code %s on %s: %s",
                result.returncode, target_path, (result.stderr or "")[:2000],
            )

        if not json_out_path.exists():
            logger.warning("semgrep produced no JSON output for %s — continuing without static pre-filter.", target_path)
            return []

        try:
            payload = json.loads(json_out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("Could not parse semgrep JSON output for %s — continuing without static pre-filter.", target_path)
            return []

    findings: list[SemgrepFinding] = []
    for r in payload.get("results", []):
        extra = r.get("extra", {})
        severity_raw = extra.get("severity", "WARNING")
        findings.append(SemgrepFinding(
            rule_id=r.get("check_id", "unknown"),
            message=extra.get("message", ""),
            file_path=r.get("path", ""),
            start_line=r.get("start", {}).get("line", 0),
            end_line=r.get("end", {}).get("line", 0),
            severity=_SEVERITY_MAP.get(severity_raw, "medium"),
            cwe_ids=_extract_cwe_ids(extra.get("metadata", {}).get("cwe")),
        ))

    logger.info("semgrep found %d result(s) in %s (rulesets: %s)", len(findings), target_path, ", ".join(configs))
    return findings