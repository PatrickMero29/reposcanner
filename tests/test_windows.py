from vulnscan.training.windows import (
    crop_pair_texts,
    crop_token_ids,
    first_diff_token_index,
    line_token_offsets,
    sliding_window_offsets,
)


class FakeTokenizer:
    """Word-level stand-in: enough API surface for windows.py, no torch."""

    def __init__(self) -> None:
        self._w2i: dict[str, int] = {}
        self._i2w: dict[int, str] = {}

    def _tok(self, word: str) -> int:
        if word not in self._w2i:
            idx = len(self._w2i) + 1
            self._w2i[word] = idx
            self._i2w[idx] = word
        return self._w2i[word]

    def num_special_tokens_to_add(self, pair: bool = False) -> int:
        return 2  # [CLS], [SEP]

    def __call__(self, text, add_special_tokens=False, truncation=False, **kwargs):  # noqa: ANN001, ANN202
        return {"input_ids": [self._tok(w) for w in text.split()]}

    def decode(self, ids, skip_special_tokens: bool = True) -> str:  # noqa: ANN001
        return " ".join(self._i2w[i] for i in ids)


def test_first_diff_token_index():
    assert first_diff_token_index([1, 2, 3], [1, 2, 4]) == 2
    # one side a strict prefix of the other: diff is at the shorter one's end
    assert first_diff_token_index([1, 2], [1, 2, 3]) == 2
    assert first_diff_token_index([1, 2, 3], [1, 2]) == 2
    assert first_diff_token_index([], []) == 0


def test_crop_token_ids_short_input_unchanged():
    ids = [1, 2, 3, 4]
    assert crop_token_ids(ids, 2, 10) == ids


def test_crop_token_ids_diff_inside_head_keeps_head():
    ids = list(range(1000))
    assert crop_token_ids(ids, 100, 510) == ids[:510]


def test_crop_token_ids_far_diff_keeps_signature_prefix_and_diff():
    ids = list(range(2000))
    diff = 1500
    out = crop_token_ids(ids, diff, 510, prefix=16)
    assert out[:16] == ids[:16], "def/signature prefix is preserved"
    assert diff in out, "the differing token must be inside the window"
    assert len(out) <= 510
    # window is centered: the diff sits in the back half, not at the edge
    assert out.index(diff) > 16 + 100


def test_crop_token_ids_window_bounds_respected():
    ids = list(range(2000))
    for diff in (520, 900, 1500, 1990):
        out = crop_token_ids(ids, diff, 510, prefix=16)
        assert len(out) <= 510
        assert diff in out


def test_sliding_window_offsets_short_is_single_window():
    assert sliding_window_offsets(100, 510, 256) == [0]
    assert sliding_window_offsets(510, 510, 256) == [0]


def test_sliding_window_offsets_covers_to_the_end():
    offs = sliding_window_offsets(1000, 510, 256)
    assert offs == [0, 256, 490]
    # every start yields a full in-bounds window, and the last window
    # always ends exactly at the final token
    for n in (511, 600, 766, 1023, 5000):
        starts = sliding_window_offsets(n, 510, 256)
        assert starts[-1] == n - 510
        assert all(0 <= s <= n - 510 for s in starts)


def test_line_token_offsets_maps_lines_to_token_positions():
    tok = FakeTokenizer()
    code = "def f():\n    alpha beta\n    gamma delta\n"
    offs = line_token_offsets(code, tok)
    # "def f():" -> 2 tokens; "alpha beta" -> 2 tokens
    assert offs == [0, 2, 4]


def test_crop_pair_texts_far_diff_is_not_a_label_collision():
    # A pair whose fix sits past token 512: head-truncation makes both
    # sides identical (a label collision); the crop must keep the differing
    # token visible on both sides instead.
    tok = FakeTokenizer()
    words = [f"w{i}" for i in range(900)]
    before = "def f(): " + " ".join(words)
    after_words = words.copy()
    after_words[850] = "PATCHED"
    after = "def f(): " + " ".join(after_words)

    # head-truncation collision confirmed on the raw texts
    head_b = tok(before)["input_ids"][:510]
    head_a = tok(after)["input_ids"][:510]
    assert head_b == head_a

    cb, ca = crop_pair_texts(before, after, tok, max_length=512)
    assert "PATCHED" in ca
    assert "PATCHED" not in cb
    assert "w850" in cb, "the vulnerable-side counterpart stays visible"
    # and the cropped sides are no longer identical inputs
    assert tok(cb)["input_ids"] != tok(ca)["input_ids"]
    assert cb.split()[0] == "def", "signature prefix survives the crop"


def test_crop_pair_texts_short_pair_untouched():
    tok = FakeTokenizer()
    before = "def f(x): return x + 1"
    after = "def f(x): return x + 2"
    cb, ca = crop_pair_texts(before, after, tok, max_length=512)
    assert cb == before
    assert ca == after
