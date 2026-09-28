"""Held-out sanity set — never loaded in training.

Different snippets from sanity_check.py / curated jsonl. Keep that file as
the train-side regression suite; this one is for uncontaminated checks.
"""

from __future__ import annotations

import asyncio

from vulnscan.config import settings
from vulnscan.local_model.inference import predict
from vulnscan.schemas import Language

CASES: list[tuple[str, bool, str]] = [
    ("cmd_injection_format", True, '''import os
def launch(arg):
    os.system("ping {}".format(arg))
'''),
    ("sqli_percent", True, '''def lookup(db, name):
    cur = db.cursor()
    cur.execute("SELECT * FROM accounts WHERE name = '%s'" % name)
    return cur.fetchall()
'''),
    ("path_concat_open", True, '''def serve(root, name):
    with open(root + name) as fh:
        return fh.read()
'''),
    ("pickle_load_file", True, '''import pickle
def restore(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)
'''),
    ("eval_getattr", True, '''def run_attr(obj, expr):
    return eval(expr, {"obj": obj})
'''),
    ("yaml_load_default", True, '''import yaml
def read_spec(text):
    return yaml.load(text)
'''),
    ("subprocess_shell", True, '''import subprocess
def ping_host(host):
    return subprocess.run("ping -c 1 " + host, shell=True)
'''),
    ("safe_add_mul", False, '''def add_then_mul(a, b, c):
    return (a + b) * c
'''),
    ("safe_param_sql", False, '''def lookup(db, name):
    cur = db.cursor()
    cur.execute("SELECT * FROM accounts WHERE name = ?", (name,))
    return cur.fetchall()
'''),
    ("safe_path_join", False, '''import os
def serve(root, name):
    path = os.path.join(root, os.path.basename(name))
    with open(path) as fh:
        return fh.read()
'''),
    ("safe_literal_eval", False, '''import ast
def parse_num(text):
    return ast.literal_eval(text)
'''),
    ("safe_yaml", False, '''import yaml
def read_spec(text):
    return yaml.safe_load(text)
'''),
    ("safe_requests_params", False, '''import requests
def weather(city):
    r = requests.get("https://api.example.com/w", params={"city": city}, timeout=5)
    return r.json()
'''),
    ("safe_eval_program_wrapper", False, '''def eval_program(self, program, inputs):
    return self.executor.run(program, inputs)
'''),
]


async def main() -> None:
    print(f"Checkpoint: {settings.local_model_checkpoint_dir}")
    print(f"Confidence threshold: {settings.local_model_confidence_threshold}\n")
    correct = 0
    for name, expected_vulnerable, code in CASES:
        preds = await predict(code=code, function_name=name, language=Language.PYTHON)
        flagged = bool(preds)
        confidence = preds[0].confidence if preds else 0.0
        ok = flagged == expected_vulnerable
        correct += ok
        mark = "PASS" if ok else "FAIL"
        expected_str = "vulnerable" if expected_vulnerable else "safe"
        got_str = "flagged" if flagged else "not flagged"
        print(f"[{mark}] {name:28s} expected={expected_str:10s} got={got_str:12s} confidence={confidence:.0%}")
    print(f"\n{correct}/{len(CASES)} passed (held-out)")


if __name__ == "__main__":
    asyncio.run(main())
