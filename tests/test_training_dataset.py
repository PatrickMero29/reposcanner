from vulnscan.dataset.cvefixes_loader import load_from_csv
from vulnscan.dataset.filters import strip_sinks_from_jsonl
from vulnscan.training.dataset import Example, build_examples, build_pairs, load_generic_negatives, train_val_split


def _write_demo_csv(path) -> None:  # noqa: ANN001
    import csv
    fieldnames = ["pair_id", "cve_id", "cwe_ids", "language", "repo", "file_path",
                  "function_name", "func_before", "func_after", "commit_message", "nvd_url"]
    rows = [
        {"pair_id": "p1", "cve_id": "CVE-1", "cwe_ids": "CWE-89", "language": "python",
         "repo": "r", "file_path": "f.py", "function_name": "f1",
         "func_before": "bad code 1", "func_after": "good code 1",
         "commit_message": "fix", "nvd_url": ""},
        {"pair_id": "p2", "cve_id": "CVE-2", "cwe_ids": "CWE-78", "language": "python",
         "repo": "r", "file_path": "f.py", "function_name": "f2",
         "func_before": "bad code 2", "func_after": "good code 2",
         "commit_message": "fix", "nvd_url": ""},
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def test_build_examples_produces_one_positive_one_negative_per_pair(tmp_path):
    csv_path = tmp_path / "demo.csv"
    db_path = tmp_path / "demo.duckdb"
    _write_demo_csv(csv_path)
    load_from_csv(str(csv_path), str(db_path), replace=True)

    examples = build_examples(str(db_path), language="python")
    assert len(examples) == 4  # 2 pairs x (before + after)

    labels_by_pair: dict[str, set[int]] = {}
    for e in examples:
        labels_by_pair.setdefault(e.pair_id, set()).add(e.label)
    assert labels_by_pair == {"p1": {0, 1}, "p2": {0, 1}}


def test_train_val_split_never_splits_a_pair_across_sides():
    examples = [
        Example(pair_id="p1", code="a", label=1),
        Example(pair_id="p1", code="b", label=0),
        Example(pair_id="p2", code="c", label=1),
        Example(pair_id="p2", code="d", label=0),
        Example(pair_id="p3", code="e", label=1),
        Example(pair_id="p3", code="f", label=0),
        Example(pair_id="p4", code="g", label=1),
        Example(pair_id="p4", code="h", label=0),
    ]
    train, val = train_val_split(examples, val_fraction=0.25, seed=1)

    train_pairs = {e.pair_id for e in train}
    val_pairs = {e.pair_id for e in val}
    assert train_pairs.isdisjoint(val_pairs), "no pair_id should appear on both sides"
    assert train_pairs | val_pairs == {"p1", "p2", "p3", "p4"}


def test_train_val_split_respects_approximate_fraction():
    examples = [Example(pair_id=f"p{i}", code="x", label=i % 2) for i in range(20)]
    train, val = train_val_split(examples, val_fraction=0.2, seed=1)
    val_pairs = {e.pair_id for e in val}
    assert len(val_pairs) == 4  # 20% of 20 pair_ids


def test_load_generic_negatives_strips_sinks(tmp_path):
    path = tmp_path / "neg.jsonl"
    path.write_text(
        '{"code": "def add(a, b):\\n    return a + b\\n"}\n'
        '{"code": "def run(x):\\n    return eval(x)\\n"}\n'
        '{"code": "def ping(c):\\n    os.system(c)\\n"}\n',
        encoding="utf-8",
    )
    negs = load_generic_negatives(str(path), strip_sinks=True)
    assert len(negs) == 1
    assert "add" in negs[0]


def test_strip_sinks_from_jsonl_rewrites_file(tmp_path):
    path = tmp_path / "neg.jsonl"
    path.write_text(
        '{"code": "def add(a, b):\\n    return a + b\\n"}\n'
        '{"code": "pickle.loads(x)\\n"}\n',
        encoding="utf-8",
    )
    stats = strip_sinks_from_jsonl(str(path))
    assert stats == {"input": 2, "dropped_sinks": 1, "kept": 1}
    kept = load_generic_negatives(str(path), strip_sinks=False)
    assert len(kept) == 1


def test_build_pairs_skips_tests_and_identical(tmp_path):
    import csv
    csv_path = tmp_path / "demo.csv"
    db_path = tmp_path / "demo.duckdb"
    fieldnames = ["pair_id", "cve_id", "cwe_ids", "language", "repo", "file_path",
                  "function_name", "func_before", "func_after", "commit_message", "nvd_url"]
    rows = [
        {"pair_id": "ok", "cve_id": "CVE-1", "cwe_ids": "CWE-89", "language": "python",
         "repo": "r", "file_path": "app.py", "function_name": "run",
         "func_before": "def run():\n    return 1\n", "func_after": "def run():\n    return 2\n",
         "commit_message": "fix", "nvd_url": ""},
        {"pair_id": "same", "cve_id": "CVE-2", "cwe_ids": "CWE-78", "language": "python",
         "repo": "r", "file_path": "app.py", "function_name": "noop",
         "func_before": "def noop():\n    return 1\n", "func_after": "def noop():\n    return 1\n",
         "commit_message": "fix", "nvd_url": ""},
        {"pair_id": "test", "cve_id": "CVE-3", "cwe_ids": "CWE-78", "language": "python",
         "repo": "r", "file_path": "tests/test_app.py", "function_name": "test_login",
         "func_before": "def test_login():\n    assert 1\n", "func_after": "def test_login():\n    assert 2\n",
         "commit_message": "fix", "nvd_url": ""},
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    load_from_csv(str(csv_path), str(db_path), replace=True)
    pairs = build_pairs(str(db_path), language="python")
    assert [p.pair_id for p in pairs] == ["ok"]


def test_train_val_split_is_deterministic_given_seed():
    examples = [Example(pair_id=f"p{i}", code="x", label=i % 2) for i in range(10)]
    train1, val1 = train_val_split(examples, val_fraction=0.3, seed=7)
    train2, val2 = train_val_split(examples, val_fraction=0.3, seed=7)
    assert {e.pair_id for e in val1} == {e.pair_id for e in val2}
