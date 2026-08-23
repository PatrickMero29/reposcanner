"""One-time fetch: samples diverse Python functions from CodeSearchNet to use
as generic "probably safe" negative examples for pairwise training (see
train_model_pairwise's generic_negatives_path parameter in training/train.py).

These are NOT verified vulnerability-free -- "most random GitHub functions
are safe" is a weak label, the same assumption most vulnerability-detection
training sets rely on. The goal here is diversity (teaching the model what
ordinary, unremarkable code looks like), not perfect ground truth. This is
what's missing from the current dataset: every existing "not vulnerable"
example is a specific CVE's fixed version, 1-3 lines after the bug -- never
a broadly diverse population of code that was never near a CVE.

Run once from C:\\reposcanner with the venv active:
    python fetch_codesearchnet_negatives.py

Writes:
  data/codesearchnet_negatives.jsonl  -- CodeSearchNet samples, subject to
                                          train/val split in train.py
  data/curated_negatives.jsonl        -- hand-curated examples, ALWAYS
                                          trained on, never held out (see
                                          note below on why this is separate)
"""

from __future__ import annotations

import json
import os
import random

from datasets import load_dataset

OUT_PATH = "data/codesearchnet_negatives.jsonl"
CURATED_OUT_PATH = "data/curated_negatives.jsonl"
TARGET_COUNT = 5000
# Lowered from 40 -- the original MIN_CHARS=40 systematically excluded short
# functions (getters, one-line arithmetic, tiny helpers) from BOTH the
# CodeSearchNet negatives AND, by construction, the held-out eval slice.
# direct_check.py showed the model at 94% "vulnerable" on a 2-line add()
# function despite averaging 1.7% on the (length-filtered) held-out set --
# short code was untested territory, not usefully "out of distribution" in
# some vague sense. Real codebases have plenty of short functions; the model
# needs to have actually seen some during training.
MIN_CHARS = 10
MAX_CHARS = 4000     # skip huge files that would dominate tokenization anyway
SEED = 42

# Hand-curated, genuinely trivial, unambiguously-safe functions -- guarantees
# coverage of the very-short regime regardless of how many short examples
# happen to survive random sampling from CodeSearchNet. No I/O, no
# subprocess/os/eval/exec, no string-built SQL or shell commands, no
# deserialization -- nothing that could be mistaken for a real sink.
_TRIVIAL_SAFE_EXAMPLES = [
    "def add(a, b):\n    return a + b\n",
    "def subtract(a, b):\n    return a - b\n",
    "def multiply(a, b):\n    return a * b\n",
    "def is_even(n):\n    return n % 2 == 0\n",
    "def square(x):\n    return x * x\n",
    "def max_of_two(a, b):\n    return a if a > b else b\n",
    "def get_name(self):\n    return self.name\n",
    "def set_value(self, value):\n    self.value = value\n",
    "def is_empty(items):\n    return len(items) == 0\n",
    "def first(items):\n    return items[0] if items else None\n",
    "def clamp(value, low, high):\n    return max(low, min(value, high))\n",
    "def to_upper(s):\n    return s.upper()\n",
    "def reverse_list(items):\n    return items[::-1]\n",
    "def average(numbers):\n    return sum(numbers) / len(numbers)\n",
    "def is_positive(n):\n    return n > 0\n",
    "class Point:\n    def __init__(self, x, y):\n        self.x = x\n        self.y = y\n",
    "def greet(name):\n    return f'Hello, {name}!'\n",
    "def count_items(items):\n    return len(items)\n",
    "def flatten_pair(pair):\n    return list(pair)\n",
    "def is_valid_age(age):\n    return 0 <= age <= 150\n",
]

# Hand-curated, unambiguously-SAFE examples that DO real I/O -- subprocess,
# file paths, external API clients, HTTP, databases -- but do it safely
# (list args, validated/joined paths, parameterized queries, no string-built
# shell/SQL). Added after scanning a real repo (dspy-redteam) that flagged
# 6/9 functions, none of which were actually dangerous -- they were LLM-API
# wrapper functions (client.chat.completions.create(...), judge.run(...)),
# textbook-safe subprocess.run(["ls", path]), and os.path.join-based file
# reads. That pattern -- flagging code for merely TOUCHING something
# external, rather than judging whether it does so safely -- suggests the
# model may have been keying on a shallow "this code does I/O" correlation.
# _TRIVIAL_SAFE_EXAMPLES fixed "short code" being wrongly flagged; this list
# targets "safe I/O code" being wrongly flagged, the same way: guaranteed
# explicit coverage rather than hoping enough examples survive random
# sampling from CodeSearchNet.
#
# IMPORTANT: these (and _TRIVIAL_SAFE_EXAMPLES) are written to a SEPARATE
# file from the CodeSearchNet samples (see CURATED_OUT_PATH below), and
# train.py loads that file as always-trained-on, never held out. Writing
# them into the same shuffled/split pool as the CodeSearchNet samples was
# a real bug: path_join_safe (below) has a ~15% chance each run of landing
# in the held-out validation slice instead of training, by construction --
# confirmed as the root cause of path_join_safe's persistent sanity_check.py
# failure (5 consecutive tracked runs) via sanity_check_history.jsonl.
_SAFE_IO_EXAMPLES = [
    # subprocess: list args, several call variants
    "import subprocess\ndef list_dir(path):\n    result = subprocess.run([\"ls\", path], capture_output=True, text=True, check=True)\n    return result.stdout\n",
    "import subprocess\ndef get_git_commit_hash(repo_dir):\n    output = subprocess.check_output([\"git\", \"rev-parse\", \"HEAD\"], cwd=repo_dir)\n    return output.decode().strip()\n",
    "import subprocess\ndef run_tests(test_dir):\n    subprocess.check_call([\"pytest\", test_dir, \"-v\"])\n",
    "import subprocess\ndef start_server(port):\n    return subprocess.Popen([\"python\", \"-m\", \"http.server\", str(port)])\n",
    "import subprocess\ndef format_file(path):\n    subprocess.run([\"black\", path], check=True)\n",

    # file paths: joined/validated, not concatenated from raw input
    "import os\ndef read_user_file(base_dir, filename):\n    safe_name = os.path.basename(filename)\n    path = os.path.join(base_dir, safe_name)\n    with open(path) as f:\n        return f.read()\n",
    "from pathlib import Path\ndef load_config(config_dir, name):\n    config_path = Path(config_dir) / f'{name}.json'\n    return config_path.read_text()\n",
    "import os\ndef save_report(output_dir, report_id, content):\n    filename = os.path.basename(f'report_{report_id}.txt')\n    path = os.path.join(output_dir, filename)\n    with open(path, 'w') as f:\n        f.write(content)\n",
    "import tempfile\ndef write_temp_file(content):\n    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:\n        f.write(content)\n        return f.name\n",

    # external API clients: chat/completion/judge-style wrappers (matches
    # the real false positives directly)
    "def get_completion(client, model_name, prompt):\n    response = client.chat.completions.create(\n        model=model_name,\n        messages=[{'role': 'user', 'content': prompt}],\n    )\n    return response.choices[0].message.content.strip()\n",
    "def score_response(judge_client, question, answer):\n    result = judge_client.run([{'question': question, 'answer': answer}])[0]\n    return round(result, 2)\n",
    "def embed_text(client, text):\n    response = client.embeddings.create(model='text-embedding-3-small', input=text)\n    return response.data[0].embedding\n",
    "def classify_sentiment(client, text):\n    resp = client.chat.completions.create(\n        model='gpt-4',\n        messages=[{'role': 'system', 'content': 'Classify sentiment.'}, {'role': 'user', 'content': text}],\n    )\n    return resp.choices[0].message.content\n",
    "def evaluate_batch(model, eval_set, metric_fn):\n    scores = [metric_fn(x, y) for x, y in eval_set]\n    return sum(scores) / len(scores)\n",
    "def run_pipeline(pipeline, input_data):\n    result = pipeline.run(input_data)\n    return result.output\n",

    # HTTP: params/json kwargs, not string-built URLs
    "import requests\ndef fetch_weather(city):\n    response = requests.get('https://api.example.com/weather', params={'city': city}, timeout=10)\n    response.raise_for_status()\n    return response.json()\n",
    "import requests\ndef submit_feedback(api_url, feedback):\n    response = requests.post(api_url, json={'feedback': feedback}, timeout=10)\n    return response.status_code == 200\n",

    # databases: parameterized, several variants
    "def get_user(conn, username):\n    cursor = conn.cursor()\n    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))\n    return cursor.fetchone()\n",
    "def insert_order(conn, customer_id, amount):\n    cursor = conn.cursor()\n    cursor.execute('INSERT INTO orders (customer_id, amount) VALUES (?, ?)', (customer_id, amount))\n    conn.commit()\n",
    "def find_by_email(session, email):\n    return session.query(User).filter(User.email == email).first()\n",
]

# Targets the one false-positive class that hasn't budged across every
# training round so far: 6 functions in a real repo (dspy-redteam) --
# metric, eval_program, main, judge_prompt, verdict_judge, get_response --
# have stayed flagged (in some subset) through v9-v13 regardless of what
# else changed. Two things distinguish them from every other fix in this
# file:
#
# 1. NESTED CALL CHAINS: metric() calls get_response(), verdict_judge(), and
#    judge_prompt() -- none of which do anything unsafe individually, but if
#    the model treats "calls a function that itself looks suspicious" as
#    evidence, that suspicion could cascade upward through a call chain even
#    when nothing at any level is actually dangerous. Every other curated
#    fix in this file has been single-function; these are deliberately
#    multi-function chains of the same shape (wrapper calling wrapper).
#
# 2. SECURITY-ADJACENT VOCABULARY: the real functions are full of terms like
#    "harmful_intent", "attack_prompt", "redteaming assistant" -- plausible
#    lexical overlap with real CVE fix commit messages/docstrings, which
#    could teach "this text is ABOUT security topics" rather than "this code
#    DOES something dangerous" -- two different things a surface-pattern
#    model could conflate. These examples deliberately reuse that vocabulary
#    in functionally inert contexts (logging, comparison, simple existence
#    checks) to break that association if it exists.
_LLM_ORCHESTRATION_SAFE_EXAMPLES = [
    # nested LLM-API wrapper chains (mirrors metric -> get_response /
    # verdict_judge / judge_prompt exactly, generic client/method names so
    # this doesn't just memorize the one real repo)
    (
        "def get_completion(client, model_name, prompt, inference_params=None):\n"
        "    inference_params = inference_params or {}\n"
        "    response = client.chat.completions.create(\n"
        "        model=model_name,\n"
        "        messages=[{'role': 'system', 'content': 'You are a helpful assistant.'},\n"
        "                  {'role': 'user', 'content': prompt}],\n"
        "        **inference_params,\n"
        "    )\n"
        "    return response.choices[0].message.content.strip()\n"
    ),
    (
        "def score_with_rubric(client, question, answer) -> float:\n"
        "    resp = client.chat.completions.create(\n"
        "        model='gpt-4',\n"
        "        response_model=RubricScore,\n"
        "        messages=[\n"
        "            {'role': 'system', 'content': 'You are a grading assistant.'},\n"
        "            {'role': 'user', 'content': f'Question: {question}\\nAnswer: {answer}\\nScore 0 to 1.'},\n"
        "        ],\n"
        "    )\n"
        "    return resp.score\n"
    ),
    (
        "def run_judge(judge_model, sample):\n"
        "    result = judge_model.run([Schema.of(input=sample.input, output=sample.output)])[0]\n"
        "    return result, None\n"
    ),
    (
        "def combined_metric(sample, prediction, use_rubric=True, round_result=True):\n"
        "    response = get_completion(target_client, target_model, prediction.text)\n"
        "    if use_rubric:\n"
        "        score = run_judge(judge_model, sample)[0] / 5\n"
        "    else:\n"
        "        score = score_with_rubric(instructor_client, sample.question, response)\n"
        "    if round_result:\n"
        "        score = round(score)\n"
        "    return score\n"
    ),
    (
        "def evaluate_program(program, eval_set):\n"
        "    evaluator = Evaluate(\n"
        "        devset=eval_set,\n"
        "        metric=lambda x, y: combined_metric(x, y),\n"
        "        num_threads=4,\n"
        "        display_progress=True,\n"
        "    )\n"
        "    evaluator(program)\n"
    ),

    # security-adjacent vocabulary in functionally inert code (logging,
    # comparison, list/dict operations -- no actual sink, no actual risk)
    (
        "def log_attack_attempt(attack_prompt, target_name):\n"
        "    \"\"\"Record a red-team test case for later review.\"\"\"\n"
        "    logger.info('Recorded attack attempt against %s: %s', target_name, attack_prompt[:50])\n"
        "    return {'target': target_name, 'prompt': attack_prompt}\n"
    ),
    (
        "def is_harmful_intent_flagged(harmful_intent, flagged_intents):\n"
        "    \"\"\"Check whether a harmful-intent string is already in the known set.\"\"\"\n"
        "    return harmful_intent.strip().lower() in flagged_intents\n"
    ),
    (
        "def summarize_redteam_results(results):\n"
        "    \"\"\"Aggregate red-team evaluation scores by category.\"\"\"\n"
        "    totals = {}\n"
        "    for r in results:\n"
        "        category = r.get('category', 'uncategorized')\n"
        "        totals[category] = totals.get(category, 0) + r.get('score', 0)\n"
        "    return totals\n"
    ),
    (
        "def build_vulnerability_report(findings):\n"
        "    \"\"\"Turn a list of finding dicts into a simple text summary.\"\"\"\n"
        "    lines = [f\"{f['severity']}: {f['title']}\" for f in findings]\n"
        "    return '\\n'.join(lines)\n"
    ),
]

# Ablation switch: v14 added _LLM_ORCHESTRATION_SAFE_EXAMPLES on top of v13's
# curated set and, on the tracked sanity_check.py suite, went 16/20 -> 14/20
# -- specifically REVERSING two fixes from the previous round (sql_injection,
# eval_untrusted both flipped back to failing) while the real-repo target
# problem only partially improved (2 false positives cleared, 1 new one
# appeared: AttackProgram.forward). That's a net regression, not progress,
# and it's not yet clear whether these 9 examples specifically caused it or
# it's unrelated noise. Set this to False, regenerate, and retrain to
# produce the ablation run: same setup as v14 except these 9 examples are
# excluded, which should closely reproduce v13's behavior if they're the
# cause. If sql_injection/eval_untrusted come back as RECOVERED and
# AttackProgram.forward-style new false positives don't reappear, that
# confirms it. If the regressions persist anyway, something else is going on.
INCLUDE_LLM_ORCHESTRATION_EXAMPLES = False #Changed for now to test

_HAND_CURATED_EXAMPLES = _TRIVIAL_SAFE_EXAMPLES + _SAFE_IO_EXAMPLES + (
    _LLM_ORCHESTRATION_SAFE_EXAMPLES if INCLUDE_LLM_ORCHESTRATION_EXAMPLES else []
)

# Explicit (vulnerable, safe) CONTRASTIVE PAIRS for patterns where the model
# has persistently gotten the vulnerable side wrong (sql_injection: 5
# consecutive failing runs; eval_untrusted/exec_untrusted_longer: same) even
# though the safe counterpart is handled correctly. That asymmetry is the
# tell: this isn't "needs more safe examples" (that's what _SAFE_IO_EXAMPLES
# was for, and it already includes 3 safe-DB examples) -- it's "the model
# learned cursor.execute()-with-a-DB-object reads as safe in general, and
# needs the explicit contrast of the SAME pattern done unsafely to learn
# the actual distinguishing feature (string-built query vs parameterized),
# not just another instance of the safe side reinforcing that association
# further." Written to CURATED_PAIRS_OUT_PATH, loaded as real training
# pairs by train.py (not run through the generic-negative machinery).
CURATED_PAIRS_OUT_PATH = "data/curated_vulnerable_pairs.jsonl"

_CURATED_VULNERABLE_SAFE_PAIRS: list[tuple[str, str]] = [
    (
        # vulnerable: string-concatenated query
        "def get_user(conn, username):\n    cursor = conn.cursor()\n    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n    cursor.execute(query)\n    return cursor.fetchone()\n",
        # safe: parameterized, otherwise identical
        "def get_user(conn, username):\n    cursor = conn.cursor()\n    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))\n    return cursor.fetchone()\n",
    ),
    (
        "def find_order(conn, order_id):\n    cursor = conn.cursor()\n    cursor.execute(\"SELECT * FROM orders WHERE id = \" + str(order_id))\n    return cursor.fetchone()\n",
        "def find_order(conn, order_id):\n    cursor = conn.cursor()\n    cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))\n    return cursor.fetchone()\n",
    ),
    (
        "def delete_user(conn, username):\n    cursor = conn.cursor()\n    cursor.execute(f\"DELETE FROM users WHERE username = '{username}'\")\n    conn.commit()\n",
        "def delete_user(conn, username):\n    cursor = conn.cursor()\n    cursor.execute('DELETE FROM users WHERE username = ?', (username,))\n    conn.commit()\n",
    ),
    (
        "def search_products(conn, term):\n    cursor = conn.cursor()\n    cursor.execute(\"SELECT * FROM products WHERE name LIKE '%\" + term + \"%'\")\n    return cursor.fetchall()\n",
        "def search_products(conn, term):\n    cursor = conn.cursor()\n    cursor.execute('SELECT * FROM products WHERE name LIKE %s', (f'%{term}%',))\n    return cursor.fetchall()\n",
    ),
    # eval/exec: more length/framing diversity on the VULNERABLE side,
    # mirroring what _SAFE_IO_EXAMPLES did for the safe side of I/O patterns
    (
        "def compute(expr):\n    return eval(expr)\n",
        "def compute(expr):\n    import ast\n    return ast.literal_eval(expr)\n",
    ),
    (
        "def run_plugin_code(plugin_name, plugin_source, context):\n    \"\"\"Load and execute a user-submitted plugin against the given context.\"\"\"\n    namespace = {'context': context}\n    logger.info('Loading plugin: %s', plugin_name)\n    exec(plugin_source, namespace)\n    return namespace.get('result')\n",
        "def run_plugin_code(plugin_name, plugin_func, context):\n    \"\"\"Call a pre-registered plugin function against the given context.\"\"\"\n    logger.info('Loading plugin: %s', plugin_name)\n    return plugin_func(context)\n",
    ),
    (
        "def calculate_discount(formula, price):\n    return eval(formula.replace('price', str(price)))\n",
        "def calculate_discount(discount_percent, price):\n    return price * (1 - discount_percent / 100)\n",
    ),
    (
        "def apply_user_script(script_text, data):\n    local_vars = {'data': data}\n    exec(script_text, {}, local_vars)\n    return local_vars.get('output')\n",
        "def apply_user_script(transform_name, data):\n    transform = REGISTERED_TRANSFORMS[transform_name]\n    return transform(data)\n",
    ),
]

# Try known-good mirrors in order. CodeSearchNet's own HF loading script is
# a legacy script-based dataset and can be flaky/blocked on recent `datasets`
# versions (trust_remote_code requirements, etc.) -- prefer plain parquet
# mirrors first, fall back to the canonical one.
_MIRRORS: list[tuple[str, str | None]] = [
    ("Nan-Do/code-search-net-python", None),
    ("code-search-net/code_search_net", "python"),
]

_CODE_FIELDS = ["code", "func_code_string", "whole_func_string", "content"]


def _load_first_working():
    last_err: Exception | None = None
    for name, config in _MIRRORS:
        try:
            print(f"Trying {name} ({config})...")
            ds = load_dataset(name, config, split="train") if config else load_dataset(name, split="train")
            print(f"Loaded {name}: {len(ds)} rows, columns={ds.column_names}")
            return ds
        except Exception as exc:  # noqa: BLE001 -- deliberately broad, trying multiple mirrors
            print(f"  failed: {exc}")
            last_err = exc
    raise RuntimeError(
        f"Could not load any CodeSearchNet mirror ({[m[0] for m in _MIRRORS]}). "
        f"Last error: {last_err}"
    )


def main() -> None:
    ds = _load_first_working()

    field = next((f for f in _CODE_FIELDS if f in ds.column_names), None)
    if field is None:
        raise RuntimeError(f"None of {_CODE_FIELDS} found in columns: {ds.column_names}")
    print(f"Using code field: {field!r}")

    rng = random.Random(SEED)
    indices = list(range(len(ds)))
    rng.shuffle(indices)

    kept: list[str] = []
    for i in indices:
        code = ds[i][field]
        if not code or not (MIN_CHARS <= len(code) <= MAX_CHARS):
            continue
        kept.append(code)
        if len(kept) >= TARGET_COUNT:
            break

    print(f"Kept {len(kept)} functions from CodeSearchNet (target {TARGET_COUNT})")

    os.makedirs("data", exist_ok=True)

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        for code in kept:
            f.write(json.dumps({"code": code}) + "\n")
    print(f"Wrote {OUT_PATH} ({len(kept)} CodeSearchNet samples, subject to train/val split)")

    with open(CURATED_OUT_PATH, "w", encoding="utf-8") as f:
        for code in _HAND_CURATED_EXAMPLES:
            f.write(json.dumps({"code": code}) + "\n")
    llm_orch_count = len(_LLM_ORCHESTRATION_SAFE_EXAMPLES) if INCLUDE_LLM_ORCHESTRATION_EXAMPLES else 0
    mode_note = "ABLATION MODE -- LLM-orchestration examples EXCLUDED" if not INCLUDE_LLM_ORCHESTRATION_EXAMPLES else "full set"
    print(
        f"Wrote {CURATED_OUT_PATH} [{mode_note}] ({len(_TRIVIAL_SAFE_EXAMPLES)} trivial-safe + "
        f"{len(_SAFE_IO_EXAMPLES)} safe-I/O + {llm_orch_count} LLM-orchestration = "
        f"{len(_HAND_CURATED_EXAMPLES)} total, ALWAYS trained on, never held out)"
    )

    with open(CURATED_PAIRS_OUT_PATH, "w", encoding="utf-8") as f:
        for vulnerable, safe in _CURATED_VULNERABLE_SAFE_PAIRS:
            f.write(json.dumps({"vulnerable": vulnerable, "safe": safe}) + "\n")
    print(
        f"Wrote {CURATED_PAIRS_OUT_PATH} ({len(_CURATED_VULNERABLE_SAFE_PAIRS)} "
        "vulnerable/safe contrastive pairs, ALWAYS trained on)"
    )


if __name__ == "__main__":
    main()