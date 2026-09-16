"""Scan-faithful classifier metrics.

This is what `vulnscan scan` actually does: flag a function if
P(vulnerable) >= t. On a labeled before/after pair:

  TP:      P(before) >= t and P(after) < t
  FN:      P(before) < t
  noise:   P(after) >= t

CWE-from-retrieval is a retrieval diagnostic, not a classifier score.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

DEFAULT_THRESHOLDS = tuple(round(x * 0.05, 2) for x in range(6, 17))  # 0.30 .. 0.80


def metrics_at(
    before_probs: list[float],
    after_probs: list[float],
    threshold: float,
) -> dict:
    n = len(before_probs)
    if n == 0 or n != len(after_probs):
        return {
            "n": n,
            "threshold": threshold,
            "tp": 0,
            "fn": 0,
            "noise_count": 0,
            "detection": 0.0,
            "noise": 0.0,
        }
    tp = fn = noise_count = 0
    for pb, pa in zip(before_probs, after_probs):
        if pb >= threshold and pa < threshold:
            tp += 1
        if pb < threshold:
            fn += 1
        if pa >= threshold:
            noise_count += 1
    return {
        "n": n,
        "threshold": threshold,
        "tp": tp,
        "fn": fn,
        "noise_count": noise_count,
        "detection": tp / n,
        "noise": noise_count / n,
    }


def pr_curve(
    before_probs: list[float],
    after_probs: list[float],
    thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS,
) -> list[dict]:
    return [metrics_at(before_probs, after_probs, t) for t in thresholds]


def pick_threshold(
    before_probs: list[float],
    after_probs: list[float],
    thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS,
    *,
    noise_penalty: float = 0.5,
) -> tuple[float, dict]:
    """Pick t on val: maximize detection - noise_penalty * noise."""
    best_t = thresholds[0] if thresholds else 0.5
    best_m = metrics_at(before_probs, after_probs, best_t)
    best_score = best_m["detection"] - noise_penalty * best_m["noise"]
    for t in thresholds[1:]:
        m = metrics_at(before_probs, after_probs, t)
        score = m["detection"] - noise_penalty * m["noise"]
        if score > best_score or (score == best_score and m["noise"] < best_m["noise"]):
            best_t, best_m, best_score = t, m, score
    return best_t, best_m


def _bucket_key(cwe_ids: str | None) -> str:
    if not cwe_ids:
        return "unknown"
    first = str(cwe_ids).split(",")[0].strip()
    return first or "unknown"


def breakdowns(
    records: list[dict],
    threshold: float,
    *,
    token_limit: int = 512,
) -> dict:
    """records: dicts with before_prob, after_prob, cwe_ids, repo, n_tokens."""
    by_cwe: dict[str, list[tuple[float, float]]] = defaultdict(list)
    by_repo: dict[str, list[tuple[float, float]]] = defaultdict(list)
    by_len: dict[str, list[tuple[float, float]]] = defaultdict(list)

    for r in records:
        pair = (float(r["before_prob"]), float(r["after_prob"]))
        by_cwe[_bucket_key(r.get("cwe_ids"))].append(pair)
        by_repo[r.get("repo") or "unknown"].append(pair)
        n_tokens = r.get("n_tokens")
        if n_tokens is None:
            bucket = "unknown"
        elif int(n_tokens) <= token_limit:
            bucket = "le_512"
        else:
            bucket = "truncated"
        by_len[bucket].append(pair)

    def _summarize(groups: dict[str, list[tuple[float, float]]]) -> dict:
        out = {}
        for key, pairs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            befores = [p[0] for p in pairs]
            afters = [p[1] for p in pairs]
            m = metrics_at(befores, afters, threshold)
            out[key] = {
                "n": m["n"],
                "detection": round(m["detection"], 4),
                "noise": round(m["noise"], 4),
            }
        return out

    return {
        "by_cwe": _summarize(by_cwe),
        "by_repo": _summarize(by_repo),
        "by_length": _summarize(by_len),
    }


def from_analysis_records(
    analysis_records: list[dict],
    pair_meta: dict[str, dict] | None = None,
    *,
    threshold: float,
    thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS,
) -> dict:
    """Build scan-faithful metrics from bench-analyze records that include
    prob_vuln on before/after variants."""
    by_pair: dict[str, dict[str, dict]] = {}
    for rec in analysis_records:
        by_pair.setdefault(rec["pair_id"], {})[rec.get("variant", "")] = rec

    before_probs: list[float] = []
    after_probs: list[float] = []
    detail: list[dict] = []
    skipped = 0
    for pair_id, variants in by_pair.items():
        b = variants.get("before") or {}
        a = variants.get("after") or {}
        if "prob_vuln" not in b or "prob_vuln" not in a:
            skipped += 1
            continue
        pb, pa = float(b["prob_vuln"]), float(a["prob_vuln"])
        before_probs.append(pb)
        after_probs.append(pa)
        meta = (pair_meta or {}).get(pair_id, {})
        n_tokens = b.get("n_tokens")
        detail.append({
            "pair_id": pair_id,
            "before_prob": pb,
            "after_prob": pa,
            "cwe_ids": meta.get("cwe_ids") or b.get("cwe_ids"),
            "repo": meta.get("repo") or b.get("repo"),
            "n_tokens": n_tokens,
        })

    curve = pr_curve(before_probs, after_probs, thresholds)
    at_t = metrics_at(before_probs, after_probs, threshold)
    return {
        "n_pairs": len(before_probs),
        "skipped_missing_prob": skipped,
        "threshold": threshold,
        "detection": round(at_t["detection"], 4),
        "noise": round(at_t["noise"], 4),
        "tp": at_t["tp"],
        "fn": at_t["fn"],
        "noise_count": at_t["noise_count"],
        "pr_curve": [
            {**m, "detection": round(m["detection"], 4), "noise": round(m["noise"], 4)}
            for m in curve
        ],
        "breakdowns": breakdowns(detail, threshold),
    }


def compute_scan_faithful(
    *,
    analysis_json_path: str,
    threshold: float,
    dataset_db_path: str | None = None,
    out_path: str | None = None,
) -> dict:
    records = json.loads(Path(analysis_json_path).read_text(encoding="utf-8"))
    pair_meta: dict[str, dict] = {}
    if dataset_db_path:
        from ..dataset.cvefixes_loader import get_pairs
        for p in get_pairs(dataset_db_path):
            pair_meta[p["pair_id"]] = p
    metrics = from_analysis_records(records, pair_meta, threshold=threshold)
    if out_path:
        Path(out_path).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics
