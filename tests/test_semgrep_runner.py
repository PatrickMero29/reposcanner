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


def test_run_semgrep_omits_metrics_off_flag_when_config_is_auto(monkeypatch):
    """Regression test: semgrep's `auto` config mode requires telemetry/metrics
    enabled (it phones home to pick rulesets). Passing --metrics=off alongside
    --config auto causes semgrep to hard-fail with 'Cannot create auto config
    when metrics are off.' This must never regress."""
    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""
        return FakeResult()

    monkeypatch.setattr("vulnscan.rules.semgrep_runner.is_semgrep_available", lambda: True)
    monkeypatch.setattr("vulnscan.rules.semgrep_runner.subprocess.run", fake_run)

    run_semgrep("/some/path", config="auto")
    assert "--metrics=off" not in captured_cmd["cmd"]

    run_semgrep("/some/path", config="p/security-audit")
    assert "--metrics=off" in captured_cmd["cmd"]


def _fake_run_capturing_cmd(monkeypatch):
    """Shared test helper: stub subprocess.run to just record the built
    command, without actually invoking semgrep."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""
        return FakeResult()

    monkeypatch.setattr("vulnscan.rules.semgrep_runner.is_semgrep_available", lambda: True)
    monkeypatch.setattr("vulnscan.rules.semgrep_runner.subprocess.run", fake_run)
    return captured


def test_run_semgrep_passes_every_ruleset_from_a_list(monkeypatch):
    """Regression test: a real bug where passing --semgrep-config twice on the
    CLI silently used only the LAST value, since the arg wasn't action='append'.
    Once the CLI does collect a list, run_semgrep must include --config for
    every entry, not just one."""
    captured = _fake_run_capturing_cmd(monkeypatch)
    run_semgrep("/some/path", config=["p/security-audit", "p/secrets"])
    cmd = captured["cmd"]
    config_flag_indices = [i for i, arg in enumerate(cmd) if arg == "--config"]
    assert len(config_flag_indices) == 2
    configs_passed = [cmd[i + 1] for i in config_flag_indices]
    assert configs_passed == ["p/security-audit", "p/secrets"]


def test_run_semgrep_splits_comma_separated_config_string(monkeypatch):
    captured = _fake_run_capturing_cmd(monkeypatch)
    run_semgrep("/some/path", config="p/security-audit,p/secrets")
    cmd = captured["cmd"]
    config_flag_indices = [i for i, arg in enumerate(cmd) if arg == "--config"]
    configs_passed = [cmd[i + 1] for i in config_flag_indices]
    assert configs_passed == ["p/security-audit", "p/secrets"]


def test_run_semgrep_metrics_off_only_when_auto_not_among_multiple_configs(monkeypatch):
    captured = _fake_run_capturing_cmd(monkeypatch)
    run_semgrep("/some/path", config=["auto", "p/secrets"])
    assert "--metrics=off" not in captured["cmd"]

    run_semgrep("/some/path", config=["p/security-audit", "p/secrets"])
    assert "--metrics=off" in captured["cmd"]
