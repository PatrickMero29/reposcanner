"""Expanded regression check for the local classifier -- broader than the
original 2-example version (command injection / trivial add()) that missed
the v8 short-code calibration gap. Covers several distinct vulnerability
patterns at several different code lengths, and several safe counterparts
(including short ones -- that's specifically what v8 got wrong), so this can
catch both "wrong vulnerability pattern" and "wrong code length" failure
modes going forward.

Run:
    $env:LOCAL_MODEL_CHECKPOINT_DIR = "models/vuln-classifier-v9"
    python sanity_check.py
"""

import asyncio

from vulnscan.config import settings
from vulnscan.local_model.inference import predict
from vulnscan.schemas import Language

# (label, expected_vulnerable, code)
CASES: list[tuple[str, bool, str]] = [
    # --- vulnerable: varied patterns, varied lengths ---
    ("command_injection_short", True, '''import os
def run(x):
    os.system("ls " + x)
'''),
    ("sql_injection", True, '''def get_user(conn, username):
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
'''),
    ("path_traversal", True, '''def read_user_file(base_dir, filename):
    path = base_dir + "/" + filename
    with open(path) as f:
        return f.read()
'''),
    ("pickle_deserialize", True, '''import pickle
def load_session(data):
    return pickle.loads(data)
'''),
    ("eval_untrusted", True, '''def compute(expr):
    return eval(expr)
'''),
    ("yaml_unsafe_load", True, '''import yaml
def parse_config(raw):
    return yaml.load(raw, Loader=yaml.UnsafeLoader)
'''),

    # --- safe: varied lengths, including deliberately trivial ones ---
    ("add_trivial", False, '''def add(a, b):
    return a + b
'''),
    ("is_even_trivial", False, '''def is_even(n):
    return n % 2 == 0
'''),
    ("getter_trivial", False, '''def get_name(self):
    return self.name
'''),
    ("sql_parameterized", False, '''def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()
'''),
    ("subprocess_list_args", False, '''import subprocess
def list_dir(path):
    result = subprocess.run(["ls", path], capture_output=True, text=True, check=True)
    return result.stdout
'''),
    ("path_join_safe", False, '''import os
def read_user_file(base_dir, filename):
    safe_name = os.path.basename(filename)
    path = os.path.join(base_dir, safe_name)
    with open(path) as f:
        return f.read()
'''),
    ("longer_utility", False, '''def summarize_orders(orders):
    """Aggregate order totals by customer, skipping cancelled orders."""
    totals = {}
    for order in orders:
        if order.get("status") == "cancelled":
            continue
        customer = order["customer_id"]
        totals[customer] = totals.get(customer, 0) + order["amount"]
    return sorted(totals.items(), key=lambda item: item[1], reverse=True)
'''),
]


async def main() -> None:
    print(f"Checkpoint: {settings.local_model_checkpoint_dir}")
    print(f"Confidence threshold: {settings.local_model_confidence_threshold}\n")

    correct = 0
    for name, expected_vulnerable, code in CASES:
        results = await predict(code=code, function_name=name, language=Language.PYTHON)
        flagged = bool(results)
        confidence = results[0].confidence if results else 0.0
        got_vulnerable = flagged  # predict() only returns a Finding when above threshold

        ok = got_vulnerable == expected_vulnerable
        correct += ok
        mark = "PASS" if ok else "FAIL"
        expected_str = "vulnerable" if expected_vulnerable else "safe"
        got_str = "flagged" if flagged else "not flagged"
        print(f"[{mark}] {name:24s} expected={expected_str:10s} got={got_str:12s} confidence={confidence:.0%}")

    print(f"\n{correct}/{len(CASES)} passed")


if __name__ == "__main__":
    asyncio.run(main())