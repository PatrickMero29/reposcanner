"""Bypasses predict()'s >threshold gate to show the TRUE raw probability for
specific code, not the misleading "confidence=0%" placeholder sanity_check.py
shows for anything under threshold. Distinguishes a near-miss (e.g. 0.48,
just needs a nudge) from a genuine failure to learn the pattern (e.g. 0.02).

Run: python raw_confidence.py
"""
import sys
sys.path.insert(0, "src")
import torch
from vulnscan.local_model.inference import _load_model, _VULNERABLE_LABEL_INDEX
from vulnscan.config import settings

CASES = {
    "eval_untrusted_longer": '''def compute_user_formula(request):
    """Evaluate a user-supplied math expression from a web request."""
    expr = request.form.get("formula", "0")
    logger.info("Evaluating user formula: %s", expr)
    try:
        result = eval(expr)
    except Exception as e:
        logger.warning("Formula evaluation failed: %s", e)
        return None
    return result
''',
    "exec_untrusted_longer": '''def run_plugin_code(plugin_name, plugin_source, context):
    """Load and execute a user-submitted plugin against the given context."""
    namespace = {"context": context}
    logger.info("Loading plugin: %s", plugin_name)
    exec(plugin_source, namespace)
    return namespace.get("result")
''',
}

model, tokenizer, device = _load_model()
print(f"threshold: {settings.local_model_confidence_threshold}\n")
for name, code in CASES.items():
    inputs = tokenizer(code, truncation=True, max_length=settings.local_model_max_length, padding=True, return_tensors="pt")
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]
    raw = float(probs[_VULNERABLE_LABEL_INDEX])
    print(f"{name}: raw probability = {raw:.4f}  ({'near-miss' if raw > 0.3 else 'genuine failure to learn'})")