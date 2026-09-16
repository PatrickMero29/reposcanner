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

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from ..config import settings
from ..schemas import Finding, Language, Severity, UndesiredOperation
from ..training.windows import line_token_offsets, sliding_window_offsets

logger = logging.getLogger("vulnscan.local_model")

_model = None
_tokenizer = None
_device = None
_checkpoint_missing_logged = False
_checkpoint_threshold: float | None = None

_VULNERABLE_LABEL_INDEX = 1
_WINDOW_STRIDE = 256


def is_checkpoint_available() -> bool:
    """A real HuggingFace checkpoint directory has at least a config.json."""
    return (Path(settings.local_model_checkpoint_dir) / "config.json").exists()


def _resolve_device(torch_module) -> str:  # noqa: ANN001
    if settings.local_model_device != "auto":
        return settings.local_model_device
    return "cuda" if torch_module.cuda.is_available() else "cpu"


def load_checkpoint_threshold() -> float | None:
    global _checkpoint_threshold
    if _checkpoint_threshold is not None:
        return _checkpoint_threshold
    path = Path(settings.local_model_checkpoint_dir) / "threshold.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        _checkpoint_threshold = float(payload["threshold"])
        return _checkpoint_threshold
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def resolve_threshold(*, fail_open: bool = False) -> float:
    saved = load_checkpoint_threshold()
    base = saved if saved is not None else settings.local_model_confidence_threshold
    if fail_open:
        return max(base, settings.local_model_failopen_confidence_threshold)
    return base


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


def _score_token_windows(
    window_id_lists: list[list[int]],
    *,
    model,
    tokenizer,
    device,
    torch_module,
) -> list[float]:
    if not window_id_lists:
        return []
    padded = tokenizer.pad(
        {"input_ids": window_id_lists, "attention_mask": [[1] * len(w) for w in window_id_lists]},
        padding=True,
        return_tensors="pt",
    )
    padded = {k: v.to(device) for k, v in padded.items()}
    with torch_module.no_grad():
        logits = model(**padded).logits
        probs = torch_module.softmax(logits, dim=-1)[:, _VULNERABLE_LABEL_INDEX]
    return [float(p) for p in probs]


def score_code(
    code: str,
    *,
    center_lines: list[int] | None = None,
) -> tuple[float, int]:
    """Return (P(vulnerable), n_tokens). Sliding windows with stride 256;
    P = max(window scores). Optional Semgrep line centers add a window.
    Returns (0.0, 0) if no checkpoint / load failure.
    """
    if not is_checkpoint_available():
        return 0.0, 0
    try:
        import torch
        model, tokenizer, device = _load_model()
        max_length = settings.local_model_max_length
        special = tokenizer.num_special_tokens_to_add(pair=False)
        budget = max(8, max_length - special)
        raw_ids = tokenizer(code, add_special_tokens=False, truncation=False)["input_ids"]
        n_tokens = len(raw_ids) + special
        cls_id = tokenizer.cls_token_id
        sep_id = tokenizer.sep_token_id
        starts = sliding_window_offsets(len(raw_ids), budget, _WINDOW_STRIDE)
        if center_lines:
            offsets = line_token_offsets(code, tokenizer)
            for lineno in center_lines:
                idx = max(0, min(int(lineno) - 1, len(offsets) - 1)) if offsets else 0
                tok = offsets[idx] if offsets else 0
                centered = max(0, min(tok - budget // 2, max(0, len(raw_ids) - budget)))
                if centered not in starts:
                    starts.append(centered)
        windows = []
        for start in starts:
            piece = raw_ids[start:start + budget]
            if cls_id is not None and sep_id is not None:
                windows.append([cls_id] + piece + [sep_id])
            else:
                windows.append(piece)
        scores = _score_token_windows(
            windows, model=model, tokenizer=tokenizer, device=device, torch_module=torch,
        )
        return (max(scores) if scores else 0.0), n_tokens
    except Exception:
        logger.exception("Local model scoring failed — treating as not vulnerable.")
        return 0.0, 0


@dataclass
class PredictResult:
    findings: list[Finding]
    prob_vuln: float
    n_tokens: int


def predict_detailed(
    *,
    code: str,
    function_name: str,
    language: Language,
    confidence_threshold: float | None = None,
    center_lines: list[int] | None = None,
    fail_open: bool = False,
) -> PredictResult:
    global _checkpoint_missing_logged
    if not is_checkpoint_available():
        if not _checkpoint_missing_logged:
            logger.info(
                "No trained model found at %s — scanning with Semgrep only. Run "
                "`vulnscan train-model` once you have a dataset loaded to enable this stage.",
                settings.local_model_checkpoint_dir,
            )
            _checkpoint_missing_logged = True
        return PredictResult(findings=[], prob_vuln=0.0, n_tokens=0)

    threshold = (
        confidence_threshold if confidence_threshold is not None
        else resolve_threshold(fail_open=fail_open)
    )
    try:
        prob, n_tokens = score_code(code, center_lines=center_lines)
        if prob < threshold:
            return PredictResult(findings=[], prob_vuln=prob, n_tokens=n_tokens)
        return PredictResult(
            findings=[Finding(
                function_name=function_name,
                language=language,
                undesired_operation=UndesiredOperation(
                    description=(
                        f"Local classifier flagged this function as potentially vulnerable "
                        f"(confidence {prob:.0%}). This is a binary classifier "
                        f"signal — no specific CWE or reachability proof is available yet; verify manually."
                    ),
                    code_snippet=code[:2000],
                    cwe_ids=[],
                    severity=_severity_from_confidence(prob),
                    impact=None,
                ),
                confidence=prob,
            )],
            prob_vuln=prob,
            n_tokens=n_tokens,
        )
    except Exception:
        logger.exception("Local model inference failed — skipping this function.")
        return PredictResult(findings=[], prob_vuln=0.0, n_tokens=0)


async def predict(
    *,
    code: str,
    function_name: str,
    language: Language,
    confidence_threshold: float | None = None,
    center_lines: list[int] | None = None,
    fail_open: bool = False,
) -> list[Finding]:
    """Run the local classifier on one function.

    Returns [] if no checkpoint has been trained yet, or if torch/
    transformers aren't installed — never raises.
    """
    return predict_detailed(
        code=code,
        function_name=function_name,
        language=language,
        confidence_threshold=confidence_threshold,
        center_lines=center_lines,
        fail_open=fail_open,
    ).findings
