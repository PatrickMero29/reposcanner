from vulnscan.rules.semgrep_runner import (
    SemgrepFinding,
    _extract_cwe_ids,
    is_semgrep_available,
    run_semgrep,
)


def test_extract_cwe_ids_parses_canonical_id_from_verbose_string():
    assert _extract_cwe_ids("CWE-78: OS Command Injection") == ["CWE-78"]


def test_extract_cwe_ids_handles_list_input():
    assert _extract_cwe_ids(["CWE-89: SQL Injection", "CWE-20: Improper Input Validation"]) == ["CWE-89", "CWE-20"]


def test_extract_cwe_ids_handles_none_or_empty():
    assert _extract_cwe_ids(None) == []
    assert _extract_cwe_ids([]) == []
    assert _extract_cwe_ids("") == []


def test_extract_cwe_ids_ignores_unparseable_entries():
    assert _extract_cwe_ids(["not a cwe string"]) == []


def test_run_semgrep_degrades_gracefully_when_not_installed(monkeypatch):
    monkeypatch.setattr("vulnscan.rules.semgrep_runner.is_semgrep_available", lambda: False)
    results = run_semgrep("/some/path", config="auto")
    assert results == []


def test_is_semgrep_available_returns_bool():
    # Whatever the actual environment has, this should never raise.
    assert isinstance(is_semgrep_available(), bool)


def test_semgrep_finding_is_a_plain_dataclass_with_expected_fields():
    finding = SemgrepFinding(
        rule_id="test-rule", message="test message", file_path="foo.py",
        start_line=1, end_line=3, severity="high", cwe_ids=["CWE-78"],
    )
    assert finding.rule_id == "test-rule"
    assert finding.severity == "high"
    assert finding.cwe_ids == ["CWE-78"]