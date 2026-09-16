import pytest

from vulnscan.rules.semgrep_runner import SemgrepFinding
from vulnscan.schemas import Finding, Language, Severity, UndesiredOperation


def _make_finding() -> Finding:
    return Finding(
        function_name="run_cmd",
        language=Language.PYTHON,
        undesired_operation=UndesiredOperation(
            description="Local classifier flagged this function.",
            code_snippet="os.system(x)",
            cwe_ids=[],
            severity=Severity.MEDIUM,
        ),
        confidence=0.8,
    )


@pytest.mark.asyncio
async def test_analyze_returns_empty_when_local_model_finds_nothing(monkeypatch):
    import vulnscan.analyzer as analyzer_module

    def fake_predict_detailed(*, code, function_name, language, **kwargs):
        from vulnscan.local_model.inference import PredictResult
        return PredictResult(findings=[], prob_vuln=0.0, n_tokens=0)

    monkeypatch.setattr(analyzer_module, "predict_detailed", fake_predict_detailed)

    results = await analyzer_module.analyze(code="x = 1", function_name="f", language=Language.PYTHON)
    assert results == []


@pytest.mark.asyncio
async def test_analyze_appends_semgrep_context_to_positive_finding(monkeypatch):
    import vulnscan.analyzer as analyzer_module

    def fake_predict_detailed(*, code, function_name, language, **kwargs):
        from vulnscan.local_model.inference import PredictResult
        return PredictResult(findings=[_make_finding()], prob_vuln=0.8, n_tokens=12)

    monkeypatch.setattr(analyzer_module, "predict_detailed", fake_predict_detailed)
    # Disable retrieval so this test only exercises the semgrep-context path.
    import dataclasses
    from vulnscan.config import settings as real_settings
    monkeypatch.setattr(analyzer_module, "settings", dataclasses.replace(real_settings, enable_retrieval=False))

    static_findings = [SemgrepFinding(
        rule_id="test-rule", message="dangerous os.system call", file_path="f.py",
        start_line=3, end_line=3, severity="high", cwe_ids=["CWE-78"],
    )]

    results = await analyzer_module.analyze(
        code="os.system(x)", function_name="f", language=Language.PYTHON,
        static_findings=static_findings,
    )
    assert len(results) == 1
    assert "test-rule" in results[0].undesired_operation.description
    assert "dangerous os.system call" in results[0].undesired_operation.description
