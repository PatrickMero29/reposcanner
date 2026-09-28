from vulnscan.training.dataset import PairExample
from vulnscan.training.splits import (
    group_key,
    load_splits_dir,
    save_splits,
    train_val_test_split_grouped,
    write_splits_from_db,
)


def _pairs() -> list[PairExample]:
    out: list[PairExample] = []
    for i in range(10):
        repo = "https://github.com/a/a" if i < 6 else "https://github.com/b/b"
        cve = f"CVE-2020-{i // 2:04d}"
        out.append(PairExample(
            pair_id=f"p{i}",
            before_code=f"def f{i}():\n    return {i}\n",
            after_code=f"def f{i}():\n    return {i}+1\n",
            cve_id=cve,
            repo=repo,
        ))
    return out


def test_grouped_split_keeps_advisory_on_one_side():
    train, val, test = train_val_test_split_grouped(_pairs(), train_fraction=0.7, val_fraction=0.15, seed=1)
    sides = [
        {group_key(p) for p in train},
        {group_key(p) for p in val},
        {group_key(p) for p in test},
    ]
    assert sides[0].isdisjoint(sides[1])
    assert sides[0].isdisjoint(sides[2])
    assert sides[1].isdisjoint(sides[2])
    assert {p.pair_id for p in train + val + test} == {f"p{i}" for i in range(10)}


def test_grouped_split_is_by_cve_not_row():
    pairs = _pairs()
    train, val, test = train_val_test_split_grouped(pairs, train_fraction=0.7, val_fraction=0.15, seed=1)
    n_groups = len({group_key(p) for p in pairs})
    assert len({group_key(p) for p in train}) + len({group_key(p) for p in val}) + len({group_key(p) for p in test}) == n_groups


def test_save_and_load_splits(tmp_path):
    train, val, test = train_val_test_split_grouped(_pairs(), seed=2)
    save_splits(tmp_path, [p.pair_id for p in train], [p.pair_id for p in val], [p.pair_id for p in test])
    loaded = load_splits_dir(tmp_path)
    assert set(loaded["train"]) == {p.pair_id for p in train}
    assert set(loaded["val"]) == {p.pair_id for p in val}
    assert set(loaded["test"]) == {p.pair_id for p in test}


def test_write_splits_from_db(tmp_path):
    from vulnscan.dataset.cvefixes_loader import load_from_csv
    import csv

    csv_path = tmp_path / "p.csv"
    db_path = tmp_path / "p.duckdb"
    fieldnames = [
        "pair_id", "cve_id", "cwe_ids", "language", "repo", "file_path",
        "function_name", "func_before", "func_after", "commit_message", "nvd_url",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        w.writeheader()
        for i in range(8):
            w.writerow({
                "pair_id": f"p{i}", "cve_id": f"CVE-{i}", "cwe_ids": "CWE-89",
                "language": "python", "repo": f"r{i % 3}", "file_path": "a.py",
                "function_name": "f", "func_before": f"def f():\n    return {i}\n",
                "func_after": f"def f():\n    return {i}+1\n",
                "commit_message": "fix", "nvd_url": "",
            })
    load_from_csv(str(csv_path), str(db_path), replace=True)
    split_dir = tmp_path / "splits"
    summary = write_splits_from_db(str(db_path), split_dir, seed=0)
    assert summary["n_pairs"]["train"] + summary["n_pairs"]["val"] + summary["n_pairs"]["test"] == 8
    assert (split_dir / "test_pair_ids.json").exists()
