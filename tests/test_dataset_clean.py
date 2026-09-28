from vulnscan.dataset.clean import cap_pairs, filter_pairs


def _pair(**kwargs):
    base = {
        "pair_id": "p",
        "cve_id": "CVE-1",
        "cwe_ids": "CWE-89",
        "language": "python",
        "repo": "https://github.com/x/y",
        "file_path": "app.py",
        "function_name": "run",
        "func_before": "def run(q):\n    cur.execute('select ' + q)\n    return 1\n",
        "func_after": "def run(q):\n    cur.execute('select %s', (q,))\n    return 1\n",
        "commit_message": "fix",
        "nvd_url": "",
    }
    base.update(kwargs)
    return base


def test_filter_drops_identical_and_tests_and_junk():
    pairs = [
        _pair(pair_id="ok"),
        _pair(pair_id="same", func_before="def f():\n    return 1\n", func_after="def f():\n    return 1\n"),
        _pair(pair_id="testf", function_name="test_login"),
        _pair(pair_id="testp", file_path="tests/test_app.py"),
        _pair(pair_id="junk", func_before='""" % stack', func_after="from tornado import locale\n"),
    ]
    kept, stats = filter_pairs(pairs)
    ids = {p["pair_id"] for p in kept}
    assert ids == {"ok"}
    assert stats["identical_before_after"] == 1
    assert stats["test_path_or_name"] == 2
    assert stats["unparseable"] == 1


def test_filter_dedents_methods():
    before = "    def handle(self, q):\n        cur.execute('x' + q)\n        return q\n"
    after = "    def handle(self, q):\n        cur.execute('x', (q,))\n        return q\n"
    kept, _ = filter_pairs([_pair(func_before=before, func_after=after)])
    assert len(kept) == 1
    assert kept[0]["func_before"].startswith("def handle")


def test_cap_pairs_limits_cve_and_repo():
    pairs = []
    for i in range(30):
        pairs.append(_pair(pair_id=f"a{i}", cve_id="CVE-A", repo="repo-a"))
    for i in range(5):
        pairs.append(_pair(pair_id=f"b{i}", cve_id="CVE-B", repo="repo-b"))
    kept, stats = cap_pairs(pairs, max_per_cve=20, max_per_repo=40)
    assert stats["dropped_cve_cap"] == 10
    assert len([p for p in kept if p["cve_id"] == "CVE-A"]) == 20
    assert len([p for p in kept if p["cve_id"] == "CVE-B"]) == 5
