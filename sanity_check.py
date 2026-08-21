"""Expanded regression check for the local classifier -- broader than the
original 2-example version (command injection / trivial add()) that missed
the v8 short-code calibration gap. Covers several distinct vulnerability
patterns at several different code lengths, and several safe counterparts
(including short ones -- that's specifically what v8 got wrong), so this can
catch both "wrong vulnerability pattern" and "wrong code length" failure
modes going forward.

Now also a TRACKED regression suite: every run appends a record to
sanity_check_history.jsonl (checkpoint, timestamp, per-case pass/fail) and
automatically diffs against the previous run, printing exactly which cases
flipped PASS->FAIL (regressions) or FAIL->PASS (improvements). This is what
caught, by hand, that v10 fixed some false positives but regressed
sql_parameterized/yaml_unsafe_load relative to v9 -- now that comparison
happens automatically on every run instead of requiring a manual re-read of
old transcripts.

Run:
    $env:LOCAL_MODEL_CHECKPOINT_DIR = "models/vuln-classifier-v9"
    python sanity_check.py
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from vulnscan.config import settings
from vulnscan.local_model.inference import predict
from vulnscan.schemas import Language

HISTORY_PATH = Path("sanity_check_history.jsonl")

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
    ("eval_untrusted_longer", True, '''def compute_user_formula(request):
    """Evaluate a user-supplied math expression from a web request."""
    expr = request.form.get("formula", "0")
    logger.info("Evaluating user formula: %s", expr)
    try:
        result = eval(expr)
    except Exception as e:
        logger.warning("Formula evaluation failed: %s", e)
        return None
    return result
'''),
    ("exec_untrusted_short", True, '''def run_snippet(code):
    exec(code)
'''),
    ("exec_untrusted_longer", True, '''def run_plugin_code(plugin_name, plugin_source, context):
    """Load and execute a user-submitted plugin against the given context."""
    namespace = {"context": context}
    logger.info("Loading plugin: %s", plugin_name)
    exec(plugin_source, namespace)
    return namespace.get("result")
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
    ("subprocess_check_output", False, '''import subprocess
def get_git_commit_hash(repo_dir):
    output = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir)
    return output.decode().strip()
'''),
    ("path_join_safe", False, '''import os
def read_user_file(base_dir, filename):
    safe_name = os.path.basename(filename)
    path = os.path.join(base_dir, safe_name)
    with open(path) as f:
        return f.read()
'''),
    ("api_client_wrapper", False, '''def get_completion(client, model_name, prompt):
    """Call a chat completion API and return the response text."""
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content.strip()
'''),
    ("scoring_wrapper", False, '''def score_response(judge_client, question, answer):
    """Score a response using an external judge/eval client."""
    result = judge_client.run([{"question": question, "answer": answer}])[0]
    return round(result, 2)
'''),
    ("http_get_params", False, '''import requests
def fetch_weather(city):
    response = requests.get("https://api.example.com/weather", params={"city": city}, timeout=10)
    response.raise_for_status()
    return response.json()
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


def _load_history() -> list[dict]:
    """Every run ever logged, oldest first -- needed for streak tracking,
    not just the single most recent run."""
    if not HISTORY_PATH.exists():
        return []
    records = []
    with open(HISTORY_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _append_run(record: dict) -> None:
    with open(HISTORY_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def _trailing_fail_streak(prior_passes: list[bool]) -> int:
    """How many consecutive most-recent prior runs failed this case. 0 if
    the most recent prior run passed (or there's no prior data)."""
    streak = 0
    for passed in reversed(prior_passes):
        if passed:
            break
        streak += 1
    return streak


async def main() -> None:
    checkpoint = settings.local_model_checkpoint_dir
    print(f"Checkpoint: {checkpoint}")
    print(f"Confidence threshold: {settings.local_model_confidence_threshold}\n")

    history_records = _load_history()
    previous = history_records[-1] if history_records else None

    # Per-case chronological pass/fail across every run ever logged, not
    # just the immediately previous one -- this is what lets us tell "just
    # started failing" apart from "has been failing for 3 runs and nobody
    # noticed because each individual diff only checked the run right before
    # it" (exactly what happened to sql_injection/path_join_safe: broke
    # around v11, stayed broken in v12, and looked like neither a regression
    # nor an improvement in that single-run diff).
    case_history: dict[str, list[bool]] = {}
    for record in history_records:
        for r in record["results"]:
            case_history.setdefault(r["name"], []).append(r["pass"])

    results = []
    correct = 0
    persistent_failures = []  # (name, total_streak_including_this_run)
    for name, expected_vulnerable, code in CASES:
        preds = await predict(code=code, function_name=name, language=Language.PYTHON)
        flagged = bool(preds)
        confidence = preds[0].confidence if preds else 0.0
        got_vulnerable = flagged  # predict() only returns a Finding when above threshold

        ok = got_vulnerable == expected_vulnerable
        correct += ok
        mark = "PASS" if ok else "FAIL"
        expected_str = "vulnerable" if expected_vulnerable else "safe"
        got_str = "flagged" if flagged else "not flagged"

        prior_passes = case_history.get(name, [])
        streak_before = _trailing_fail_streak(prior_passes)

        tag = ""
        if ok:
            if prior_passes and not prior_passes[-1]:
                tag = f" <-- RECOVERED (was failing {streak_before}x in a row)"
        else:
            total_streak = streak_before + 1
            if streak_before == 0:
                if prior_passes:  # most recent prior run passed, this one didn't
                    tag = " <-- NEW REGRESSION"
                # else: first time this case has ever been tested, not a regression
            else:
                tag = f" <-- STILL FAILING ({total_streak} runs in a row)"
                persistent_failures.append((name, total_streak))

        print(
            f"[{mark}] {name:24s} expected={expected_str:10s} got={got_str:12s} "
            f"confidence={confidence:.0%}{tag}"
        )
        results.append({
            "name": name, "expected_vulnerable": expected_vulnerable,
            "got_vulnerable": got_vulnerable, "confidence": confidence, "pass": ok,
        })

    print(f"\n{correct}/{len(CASES)} passed")

    if previous is not None:
        previous_results = {r["name"]: r for r in previous["results"]}
        current_results = {r["name"]: r for r in results}
        regressions = [
            n for n, p in previous_results.items()
            if n in current_results and p["pass"] and not current_results[n]["pass"]
        ]
        improvements = [
            n for n, p in previous_results.items()
            if n in current_results and not p["pass"] and current_results[n]["pass"]
        ]
        print(f"\nCompared to previous run ({previous['checkpoint']}):")
        print(f"  New regressions: {regressions if regressions else 'none'}")
        print(f"  Improvements: {improvements if improvements else 'none'}")

    if persistent_failures:
        persistent_failures.sort(key=lambda x: -x[1])
        print("\nPersistent failures (2+ runs in a row -- likely a real, not one-off, problem):")
        for name, streak in persistent_failures:
            print(f"  {name}: failing {streak} runs in a row")

    _append_run({
        "checkpoint": checkpoint,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "passed": correct,
        "total": len(CASES),
        "results": results,
    })
    print(f"\nLogged to {HISTORY_PATH}")


if __name__ == "__main__":
    asyncio.run(main())