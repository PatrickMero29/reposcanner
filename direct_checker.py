"""Diagnostic: reproduces training's exact eval-time computation (tokenize ->
model -> softmax over logits[:, 1]) directly against a checkpoint, bypassing
local_model/inference.py's predict() entirely.

Why: sanity_check.py goes through predict(), which may do preprocessing,
label-index handling, or score combination (e.g. with Semgrep) that differs
from what training measured. The held-out generic-negative eval during
training averaged ~1.7% probability of vulnerable; sanity_check.py's "safe"
example came back at 94% -- a ~60x gap too large to just be one hard
example. This script tells us whether that gap is in the MODEL (in which
case this script will also show high confidence on the safe snippet) or in
the INFERENCE WRAPPER (in which case this script will show something much
closer to the training-time average, and predict()/inference.py needs
inspecting for a mismatch).

Run from C:\\reposcanner with the venv active and the checkpoint dir set:
    $env:LOCAL_MODEL_CHECKPOINT_DIR = "models/vuln-classifier-v8"
    python direct_check.py
"""

from __future__ import annotations

import os

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

CHECKPOINT_DIR = os.environ.get("LOCAL_MODEL_CHECKPOINT_DIR", "models/vuln-classifier-v10")

VULNERABLE = '''import os
def run(x):
    os.system("ls " + x)
'''

SAFE = '''def add(a, b):
    return a + b
'''


def main() -> None:
    print(f"Loading checkpoint: {CHECKPOINT_DIR}")
    tokenizer = AutoTokenizer.from_pretrained(CHECKPOINT_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(CHECKPOINT_DIR)
    model.eval()

    for label, code in [("vulnerable", VULNERABLE), ("safe", SAFE)]:
        enc = tokenizer(code, truncation=True, max_length=512, return_tensors="pt")
        with torch.no_grad():
            logits = model(**enc).logits
        probs = torch.softmax(logits, dim=-1)[0]
        score = (logits[0, 1] - logits[0, 0]).item()
        print(
            f"{label:10s} -> P(vulnerable)={probs[1].item():.4f}  "
            f"P(safe)={probs[0].item():.4f}  raw_score={score:+.3f}  "
            f"raw_logits={logits[0].tolist()}"
        )


if __name__ == "__main__":
    main()