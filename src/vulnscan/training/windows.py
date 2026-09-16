"""Diff-centered 512-token crops for pairwise training.

If the before/after edit sits past the first 512 tokens, a head-only encode
collapses both sides to the same input with opposite labels. Crop around the
first differing token instead, keeping a short prefix so the def/signature
is still visible.
"""

from __future__ import annotations

from typing import Any


def first_diff_token_index(before_ids: list[int], after_ids: list[int]) -> int:
    for i, (a, b) in enumerate(zip(before_ids, after_ids)):
        if a != b:
            return i
    return min(len(before_ids), len(after_ids))


def crop_token_ids(
    ids: list[int],
    diff_idx: int,
    budget: int,
    *,
    prefix: int = 16,
) -> list[int]:
    if len(ids) <= budget:
        return list(ids)
    if diff_idx < budget:
        return list(ids[:budget])
    prefix_len = min(prefix, diff_idx, max(1, budget // 8))
    window_budget = budget - prefix_len
    w_start = max(prefix_len, diff_idx - window_budget // 2)
    w_end = min(len(ids), w_start + window_budget)
    if w_end - w_start < window_budget:
        w_start = max(prefix_len, w_end - window_budget)
    return list(ids[:prefix_len]) + list(ids[w_start:w_end])


def crop_pair_texts(
    before_code: str,
    after_code: str,
    tokenizer: Any,
    *,
    max_length: int = 512,
    prefix_tokens: int = 16,
) -> tuple[str, str]:
    """Return (cropped_before, cropped_after) decoded from a shared window."""
    special = tokenizer.num_special_tokens_to_add(pair=False)
    budget = max(8, max_length - special)
    before_ids = tokenizer(before_code, add_special_tokens=False, truncation=False)["input_ids"]
    after_ids = tokenizer(after_code, add_special_tokens=False, truncation=False)["input_ids"]
    diff_idx = first_diff_token_index(before_ids, after_ids)
    b_crop = crop_token_ids(before_ids, diff_idx, budget, prefix=prefix_tokens)
    a_crop = crop_token_ids(after_ids, diff_idx, budget, prefix=prefix_tokens)
    before_out = tokenizer.decode(b_crop, skip_special_tokens=True)
    after_out = tokenizer.decode(a_crop, skip_special_tokens=True)
    return before_out, after_out


def sliding_window_offsets(n_tokens: int, budget: int, stride: int) -> list[int]:
    if n_tokens <= budget:
        return [0]
    starts = list(range(0, n_tokens - budget + 1, stride))
    last = n_tokens - budget
    if not starts or starts[-1] != last:
        starts.append(last)
    return starts


def line_token_offsets(code: str, tokenizer: Any) -> list[int]:
    offsets: list[int] = []
    running = 0
    lines = code.splitlines(keepends=True) or [code]
    for line in lines:
        offsets.append(running)
        running += len(tokenizer(line, add_special_tokens=False, truncation=False)["input_ids"])
    return offsets
