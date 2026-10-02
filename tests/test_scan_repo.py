import asyncio
import dataclasses

import pytest

import vulnscan.local_model.inference as inference_module
import vulnscan.scanner.scan_repo as scan_repo_module
from vulnscan.config import settings as real_settings
from vulnscan.rules.semgrep_runner import SemgrepFinding, SemgrepRunResult


APP_SOURCE = """import os


def run(user_input):
    os.system("ls " + user_input)
    return 1


def helper(a, b):
    return a + b
"""


def _make_repo(tmp_path):
    (tmp_path / "app.py").write_text(APP_SOURCE, encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text(
        "def test_run():\n    assert run('x') == 1\n", encoding="utf-8",
    )
    (tmp_path / "app_test.py").write_text("def test_more():\n    assert 1\n", encoding="utf-8")
    return tmp_path


def _finding(app_py, line):
    return SemgrepFinding(
        rule_id="os-system-call", message="os.system call", file_path=str(app_py),
        start_line=line, end_line=line, severity="high", cwe_ids=["CWE-78"],
    )


@pytest.fixture
def analyze_calls(monkeypatch):
    calls: list[dict] = []

    async def fake_analyze(**kwargs):
        calls.append(kwargs)
        return []

    monkeypatch.setattr(scan_repo_module, "analyze", fake_analyze)
    return calls


def _patch_semgrep(monkeypatch, status, findings):
    def fake_run_semgrep_ex(target_path, *, config=None, timeout=None):
        return SemgrepRunResult(
            findings=findings, status=status,
            returncode=0 if status == "ok" else 2,
        )

    monkeypatch.setattr(scan_repo_module, "run_semgrep_ex", fake_run_semgrep_ex)


def test_semgrep_ran_clean_with_zero_findings_classifies_nothing(tmp_path, monkeypatch, analyze_calls):
    """Phase 4 item 1: exit 0/1 with results=[] must NOT look like a broken
    semgrep -- the repo is clean, so nothing reaches the classifier."""
    _make_repo(tmp_path)
    _patch_semgrep(monkeypatch, "ok", findings=[])

    report = asyncio.run(scan_repo_module.scan_repo(str(tmp_path)))
    assert analyze_calls == [], "a clean semgrep run must not classify anything"
    assert report.ai_findings == []
    assert report.static_findings == []


def test_semgrep_unavailable_fails_open_on_everything(tmp_path, monkeypatch, analyze_calls):
    _make_repo(tmp_path)
    _patch_semgrep(monkeypatch, "unavailable", findings=[])

    report = asyncio.run(scan_repo_module.scan_repo(str(tmp_path)))
    assert len(analyze_calls) == 2, "both app functions analyzed; test files skipped"
    assert all(c["fail_open"] for c in analyze_calls), "fail-open mode raises the confidence bar"
    assert report.ai_findings == []


def test_semgrep_timeout_fails_open(tmp_path, monkeypatch, analyze_calls):
    _make_repo(tmp_path)
    _patch_semgrep(monkeypatch, "timeout", findings=[])

    asyncio.run(scan_repo_module.scan_repo(str(tmp_path)))
    assert len(analyze_calls) == 2
    assert all(c["fail_open"] for c in analyze_calls)


def test_semgrep_error_fails_open(tmp_path, monkeypatch, analyze_calls):
    _make_repo(tmp_path)
    _patch_semgrep(monkeypatch, "error", findings=[])

    asyncio.run(scan_repo_module.scan_repo(str(tmp_path)))
    assert len(analyze_calls) == 2
    assert all(c["fail_open"] for c in analyze_calls)


def test_semgrep_ok_with_finding_narrows_to_overlapping_chunk(tmp_path, monkeypatch, analyze_calls):
    app_py = tmp_path / "app.py"
    _make_repo(tmp_path)
    _patch_semgrep(monkeypatch, "ok", findings=[_finding(app_py, line=5)])

    report = asyncio.run(scan_repo_module.scan_repo(str(tmp_path)))
    assert [c["function_name"] for c in analyze_calls] == ["run"], \
        "only the function the finding overlaps gets classified"
    assert analyze_calls[0]["fail_open"] is False
    assert analyze_calls[0]["chunk_start_line"] == 4, "chunk line handed to analyze for window centering"
    assert analyze_calls[0]["static_findings"], "the overlapping semgrep finding is passed along"
    assert len(report.static_findings) == 1


def test_no_semgrep_flag_fails_open(tmp_path, monkeypatch, analyze_calls):
    _make_repo(tmp_path)
    _patch_semgrep(monkeypatch, "ok", findings=[])

    asyncio.run(scan_repo_module.scan_repo(str(tmp_path), use_semgrep_prefilter=False))
    assert len(analyze_calls) == 2
    assert all(c["fail_open"] for c in analyze_calls)


def test_discover_files_skips_test_paths(tmp_path):
    _make_repo(tmp_path)
    files = {f.name for f in scan_repo_module.discover_files(tmp_path)}
    assert files == {"app.py"}


def _threshold_settings(tmp_path, *, ckpt_threshold=None, base=0.5, failopen=0.7):
    ckpt = tmp_path / "ckpt"
    ckpt.mkdir(exist_ok=True)
    if ckpt_threshold is not None:
        (ckpt / "threshold.json").write_text(
            __import__("json").dumps({"threshold": ckpt_threshold}), encoding="utf-8",
        )
    return dataclasses.replace(
        real_settings,
        local_model_checkpoint_dir=str(ckpt),
        local_model_confidence_threshold=base,
        local_model_failopen_confidence_threshold=failopen,
    )


def test_resolve_threshold_prefers_checkpoint_threshold(tmp_path, monkeypatch):
    fake = _threshold_settings(tmp_path, ckpt_threshold=0.75)
    monkeypatch.setattr(inference_module, "settings", fake)
    monkeypatch.setattr(inference_module, "_checkpoint_threshold", None)
    assert inference_module.resolve_threshold() == 0.75
    # fail-open bar never LOWERS a frozen checkpoint threshold
    assert inference_module.resolve_threshold(fail_open=True) == 0.75


def test_resolve_threshold_failopen_raises_bar(tmp_path, monkeypatch):
    fake = _threshold_settings(tmp_path, ckpt_threshold=None, base=0.5, failopen=0.7)
    monkeypatch.setattr(inference_module, "settings", fake)
    monkeypatch.setattr(inference_module, "_checkpoint_threshold", None)
    assert inference_module.resolve_threshold() == 0.5
    assert inference_module.resolve_threshold(fail_open=True) == 0.7


# --- chunk/finding overlap helpers (ported from the old rules/scan_repo_overlay.py) ---

def _static(path: str, start: int, end: int) -> SemgrepFinding:
    return SemgrepFinding(
        rule_id="r", message="m", file_path=path, start_line=start, end_line=end,
        severity="high", cwe_ids=[],
    )


def test_findings_overlapping_chunk_contained():
    findings = [_static("f.py", 10, 12)]
    assert scan_repo_module._findings_overlapping_chunk(5, 20, findings) == findings


def test_findings_overlapping_chunk_outside_range():
    findings = [_static("f.py", 100, 105)]
    assert scan_repo_module._findings_overlapping_chunk(5, 20, findings) == []


def test_findings_overlapping_chunk_partial_overlap():
    # finding starts before the chunk but ends inside it
    findings = [_static("f.py", 1, 6)]
    assert scan_repo_module._findings_overlapping_chunk(5, 20, findings) == findings


def test_findings_overlapping_chunk_boundary_touch():
    findings = [_static("f.py", 20, 25)]  # starts exactly at chunk_end
    assert scan_repo_module._findings_overlapping_chunk(5, 20, findings) == findings


def test_group_semgrep_findings_by_file(tmp_path):
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text("x = 1")
    f2.write_text("y = 2")

    findings = [_static(str(f1), 1, 2), _static(str(f2), 3, 4), _static(str(f1), 5, 6)]
    grouped = scan_repo_module._group_semgrep_findings_by_file(findings)

    assert len(grouped[str(f1.resolve())]) == 2
    assert len(grouped[str(f2.resolve())]) == 1
