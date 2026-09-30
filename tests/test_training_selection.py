from pathlib import Path

import pytest

from vulnscan.training.train import (
    AFTER_PROB_PENALTY,
    GENERIC_RANKING_GATE,
    selection_score,
)


def test_scan_detection_is_primary_score():
    m = {
        "val_scan_detection": 0.80,
        "val_avg_after_prob_vuln": 0.30,
        "held_out_generic_ranking_accuracy": 0.99,
    }
    assert selection_score(m) == pytest.approx(0.80 - AFTER_PROB_PENALTY * 0.30)


def test_generic_ranking_is_a_gate_not_half_the_score():
    # A 99% generic score used to average in and mask a weak val detection;
    # now anything below the gate is disqualifying outright.
    below_gate = {
        "val_scan_detection": 0.80,
        "val_avg_after_prob_vuln": 0.10,
        "held_out_generic_ranking_accuracy": GENERIC_RANKING_GATE - 0.02,
    }
    assert selection_score(below_gate) == float("-inf")
    exactly_gate = dict(below_gate, held_out_generic_ranking_accuracy=GENERIC_RANKING_GATE)
    assert selection_score(exactly_gate) != float("-inf")


def test_gate_not_applied_when_generic_metric_absent():
    m = {"val_scan_detection": 0.7, "val_avg_after_prob_vuln": 0.2}
    assert selection_score(m) == pytest.approx(0.7 - AFTER_PROB_PENALTY * 0.2)


def test_scan_detection_falls_back_to_ranking_when_missing():
    m = {"val_ranking_accuracy": 0.75, "held_out_generic_ranking_accuracy": 0.99}
    assert selection_score(m) == 0.75


def test_composite_still_averages_when_selected():
    # Composite remains selectable for ablations, but still under the same
    # generic gate as every other metric.
    m = {
        "val_ranking_accuracy": 0.80,
        "held_out_generic_ranking_accuracy": 0.99,
    }
    assert selection_score(m, best_epoch_metric="composite") == pytest.approx(0.895)


def test_unknown_metric_raises():
    with pytest.raises(ValueError):
        selection_score({}, best_epoch_metric="nope")


def test_missing_everything_is_negative_infinity():
    assert selection_score({}) == float("-inf")
