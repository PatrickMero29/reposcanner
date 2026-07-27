from vulnscan.rules.semgrep_runner import SemgrepFinding
from vulnscan.scanner.scan_repo import _findings_overlapping_chunk, _group_semgrep_findings_by_file

#Might be unnecessary now

def _finding(path: str, start: int, end: int) -> SemgrepFinding:
    return SemgrepFinding(
        rule_id="r", message="m", file_path=path, start_line=start, end_line=end,
        severity="high", cwe_ids=[],
    )


def test_findings_overlapping_chunk_finds_contained_finding():
    findings = [_finding("f.py", 10, 12)]
    matches = _findings_overlapping_chunk(5, 20, findings)
    assert matches == findings


def test_findings_overlapping_chunk_excludes_finding_outside_range():
    findings = [_finding("f.py", 100, 105)]
    matches = _findings_overlapping_chunk(5, 20, findings)
    assert matches == []


def test_findings_overlapping_chunk_handles_partial_overlap():
    # finding starts before the chunk but ends inside it
    findings = [_finding("f.py", 1, 6)]
    matches = _findings_overlapping_chunk(5, 20, findings)
    assert matches == findings


def test_findings_overlapping_chunk_handles_exact_boundary_touch():
    findings = [_finding("f.py", 20, 25)]  # starts exactly at chunk_end
    matches = _findings_overlapping_chunk(5, 20, findings)
    assert matches == findings


def test_group_semgrep_findings_by_file_groups_correctly(tmp_path):
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text("x = 1")
    f2.write_text("y = 2")

    findings = [_finding(str(f1), 1, 2), _finding(str(f2), 3, 4), _finding(str(f1), 5, 6)]
    grouped = _group_semgrep_findings_by_file(findings)

    assert len(grouped[str(f1.resolve())]) == 2
    assert len(grouped[str(f2.resolve())]) == 1