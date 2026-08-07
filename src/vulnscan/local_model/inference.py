"""Local, GPU-runnable vulnerability classifier — the pluggable replacement
for the (removed) Claude API call as the "AI engine" stage.

This module follows the same graceful-degradation pattern as
embedding/encoder.py and rules/semgrep_runner.py: heavy dependencies (torch,
transformers) are only imported inside functions that need them, and every
failure mode (no checkpoint trained yet, torch/transformers not installed,
a corrupt checkpoint) results in "no findings from this stage" rather than
crashing a scan. This means `vulnscan scan` works today on just the Semgrep
pre-filter, and picks up real classifier-based findings the moment you've
trained a model and it's sitting at the configured checkpoint path — no
code changes needed on your end.

NOTE — scope: the current model is a BINARY classifier (vulnerable / not
vulnerable), trained per src/vulnscan/training/. It does not predict a
specific CWE or produce a reachability justification the way the old
Claude-based analyzer did. That richer output is real future scope (see
architecture.txt's Phase 6/7 — confidence-ranked CWE classification, then
a local reasoning/explanation pass) but deliberately isn't attempted until
the narrow binary case is proven out, per the agreed sequencing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import settings
from ..schemas import Finding, Language, Severity, UndesiredOperation

logger = logging.getLogger("vulnscan.local_model")

_model = None
_tokenizer = None
_device = None
_checkpoint_missing_logged = False

# Training convention (see training/train.py): label 0 = not vulnerable
# (func_after / negative sample), label 1 = vulnerable (func_before).
_VULNERABLE_LABEL_INDEX = 1


def is_checkpoint_available() -> bool:
    """A real HuggingFace checkpoint directory has at least a config.json."""
    return (Path(settings.local_model_checkpoint_dir) / "config.json").exists()


def _resolve_device(torch_module) -> str:  # noqa: ANN001
    if settings.local_model_device != "auto":
        return settings.local_model_device
    return "cuda" if torch_module.cuda.is_available() else "cpu"


def _load_model():
    global _model, _tokenizer, _device
    if _model is not None:
        return _model, _tokenizer, _device

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "torch/transformers are not installed. Install them with "
            '`pip install -e ".[ml]"` to enable local model inference.'
        ) from exc

    checkpoint_dir = settings.local_model_checkpoint_dir
    logger.info("Loading local classifier from %s...", checkpoint_dir)
    _device = _resolve_device(torch)
    _tokenizer = AutoTokenizer.from_pretrained(checkpoint_dir)
    _model = AutoModelForSequenceClassification.from_pretrained(checkpoint_dir)
    _model.to(_device)
    _model.eval()
    logger.info("Local classifier loaded on device=%s", _device)
    return _model, _tokenizer, _device


def _severity_from_confidence(confidence: float) -> Severity:
    if confidence >= 0.9:
        return Severity.HIGH
    if confidence >= 0.7:
        return Severity.MEDIUM
    return Severity.LOW


async def predict(*, code: str, function_name: str, language: Language) -> list[Finding]:
    """Run the local classifier on one function.

    Returns [] if no checkpoint has been trained yet, or if torch/
    transformers aren't installed — never raises.
    """
    global _checkpoint_missing_logged
    if not is_checkpoint_available():
        if not _checkpoint_missing_logged:
            logger.info(
                "No trained model found at %s — scanning with Semgrep only. Run "
                "`vulnscan train-model` once you have a dataset loaded to enable this stage.",
                settings.local_model_checkpoint_dir,
            )
            _checkpoint_missing_logged = True
        return []

    try:
        model, tokenizer, device = _load_model()
        import torch

        inputs = tokenizer(
            code, truncation=True, max_length=settings.local_model_max_length,
            padding=True, return_tensors="pt",
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            logits = model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0]
        vulnerable_confidence = float(probs[_VULNERABLE_LABEL_INDEX])

        if vulnerable_confidence < settings.local_model_confidence_threshold:
            return []

        return [Finding(
            function_name=function_name,
            language=language,
            undesired_operation=UndesiredOperation(
                description=(
                    f"Local classifier flagged this function as potentially vulnerable "
                    f"(confidence {vulnerable_confidence:.0%}). This is a binary classifier "
                    f"signal — no specific CWE or reachability proof is available yet; verify manually."
                ),
                code_snippet=code[:2000],
                cwe_ids=[],
                severity=_severity_from_confidence(vulnerable_confidence),
                impact=None,
            ),
            confidence=vulnerable_confidence,
        )]
    except Exception:  # noqa: BLE001 — inference failing should never break a scan
        logger.exception("Local model inference failed — skipping this function.")
        return []
