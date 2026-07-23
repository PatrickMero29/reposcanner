import pytest
from pydantic import ValidationError

from vulnscan.schemas import (
    Finding,
    FindingList,
    Language,
    Severity,
    UndesiredOperation,
)


def _make_finding(**overrides) -> dict:
    base = dict(
        function_name="run_command",
        language=Language.PYTHON,
        undesired_operation=dict(
            description="Command injection via unsanitized user input.",
            code_snippet='os.system("ls " + user_input)',
            cwe_ids=["CWE-78"],
            severity=Severity.HIGH,
            impact="Arbitrary command execution.",
        ),
        confidence=0.9,
    )
    base.update(overrides)
    return base


def test_finding_round_trips_through_json():
    finding = Finding.model_validate(_make_finding())
    dumped = finding.model_dump_json()
    reloaded = Finding.model_validate_json(dumped)
    assert reloaded == finding


def test_finding_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        Finding.model_validate(_make_finding(confidence=1.5))


def test_finding_requires_undesired_operation_fields():
    with pytest.raises(ValidationError):
        UndesiredOperation.model_validate({"description": "missing required fields"})


def test_finding_list_defaults_to_empty():
    fl = FindingList()
    assert fl.findings == []


def test_finding_list_parses_multiple_findings():
    fl = FindingList.model_validate({"findings": [_make_finding(), _make_finding(function_name="other_fn")]})
    assert len(fl.findings) == 2
    assert {f.function_name for f in fl.findings} == {"run_command", "other_fn"}
