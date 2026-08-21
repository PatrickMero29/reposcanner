"""Checks whether Semgrep's p/security-audit ruleset (the same one
vulnscan's scanner already uses) catches the canonical vulnerable patterns
from sanity_check.py -- the ones where the ML classifier just regressed
(command_injection_short, path_traversal, yaml_unsafe_load) plus a couple
others for comparison.

Unlike the local model, Semgrep rules don't shift when you retrain --
if a rule catches os.system today, it still catches it after any future
training run. This is checking whether that safety net is already solid
for these patterns, before writing any new custom rules.

Run from anywhere with the venv active (needs `semgrep` installed, which
vulnscan already depends on):
    python check_semgrep_coverage.py
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

SNIPPETS = {
    "command_injection_short": '''import os
def run(x):
    os.system("ls " + x)
''',
    "path_traversal": '''def read_user_file(base_dir, filename):
    path = base_dir + "/" + filename
    with open(path) as f:
        return f.read()
''',
    "yaml_unsafe_load": '''import yaml
def parse_config(raw):
    return yaml.load(raw, Loader=yaml.UnsafeLoader)
''',
    "pickle_deserialize": '''import pickle
def load_session(data):
    return pickle.loads(data)
''',
    "exec_untrusted_longer": '''def run_plugin_code(plugin_name, plugin_source, context):
    """Load and execute a user-submitted plugin against the given context."""
    namespace = {"context": context}
    logger.info("Loading plugin: %s", plugin_name)
    exec(plugin_source, namespace)
    return namespace.get("result")
''',
    "sql_injection": '''def get_user(conn, username):
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
''',
}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for name, code in SNIPPETS.items():
            (tmp_path / f"{name}.py").write_text(code, encoding="utf-8")

        print("Downloading/running p/security-audit against test snippets...\n")
        result = subprocess.run(
            ["semgrep", "scan", "--config", "p/security-audit", "--json", str(tmp_path)],
            capture_output=True, text=True,
        )
        if result.returncode not in (0, 1):
            print("Semgrep failed to run:")
            print(result.stderr[-2000:])
            return

        data = json.loads(result.stdout)
        by_file: dict[str, list[str]] = {}
        for r in data.get("results", []):
            fname = Path(r["path"]).stem
            by_file.setdefault(fname, []).append(r["check_id"])

        print(f"{'Pattern':30s} {'Status':10s} Rule(s) matched")
        print("-" * 70)
        for name in SNIPPETS:
            checks = by_file.get(name, [])
            status = "CAUGHT" if checks else "MISSED"
            checks_str = ", ".join(checks) if checks else "(none)"
            print(f"{name:30s} {status:10s} {checks_str}")


if __name__ == "__main__":
    main()