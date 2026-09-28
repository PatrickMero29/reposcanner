from vulnscan.pipeline.scan_metrics import (
    breakdowns,
    from_analysis_records,
    metrics_at,
    pick_threshold,
    pr_curve,
)


def test_scan_faithful_tp_fn_noise():
    before = [0.8, 0.2, 0.9, 0.6]
    after = [0.1, 0.1, 0.85, 0.2]
    m = metrics_at(before, after, 0.5)
    assert m["tp"] == 2
    assert m["fn"] == 1
    assert m["noise_count"] == 1
    assert m["detection"] == 0.5
    assert m["noise"] == 0.25


def test_pr_curve_covers_requested_thresholds():
    curve = pr_curve([0.9, 0.4], [0.1, 0.2], thresholds=(0.3, 0.5, 0.8))
    assert [c["threshold"] for c in curve] == [0.3, 0.5, 0.8]


def test_pick_threshold_prefers_detection_minus_noise():
    before = [0.9, 0.9, 0.9, 0.2]
    after = [0.1, 0.1, 0.85, 0.1]
    t, m = pick_threshold(before, after, thresholds=(0.3, 0.5, 0.8), noise_penalty=0.5)
    assert t in (0.3, 0.5, 0.8)
    assert m["n"] == 4


def test_breakdowns_by_cwe_repo_length():
    records = [
        {"before_prob": 0.9, "after_prob": 0.1, "cwe_ids": "CWE-89", "repo": "a", "n_tokens": 40},
        {"before_prob": 0.2, "after_prob": 0.1, "cwe_ids": "CWE-89", "repo": "a", "n_tokens": 40},
        {"before_prob": 0.8, "after_prob": 0.1, "cwe_ids": "CWE-78", "repo": "b", "n_tokens": 900},
    ]
    out = breakdowns(records, 0.5)
    assert out["by_cwe"]["CWE-89"]["n"] == 2
    assert out["by_repo"]["b"]["detection"] == 1.0
    assert out["by_length"]["le_512"]["n"] == 2
    assert out["by_length"]["truncated"]["n"] == 1


def test_from_analysis_records():
    records = [
        {"pair_id": "p1", "variant": "before", "prob_vuln": 0.8, "n_tokens": 10, "cwe_ids": "CWE-89", "repo": "r"},
        {"pair_id": "p1", "variant": "after", "prob_vuln": 0.1, "n_tokens": 10, "cwe_ids": "CWE-89", "repo": "r"},
        {"pair_id": "p2", "variant": "before", "prob_vuln": 0.2, "n_tokens": 10},
        {"pair_id": "p2", "variant": "after", "prob_vuln": 0.1, "n_tokens": 10},
    ]
    m = from_analysis_records(records, threshold=0.5)
    assert m["n_pairs"] == 2
    assert m["tp"] == 1
    assert m["fn"] == 1
    assert m["detection"] == 0.5
