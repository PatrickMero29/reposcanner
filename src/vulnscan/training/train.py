"""Fine-tune a local binary vulnerability classifier on your loaded dataset.

Runs on GPU automatically if one is available (via `transformers.Trainer` /
`accelerate` device placement), falls back to CPU otherwise. This is the
"AI engine" training counterpart to local_model/inference.py — train here,
the checkpoint this writes is what inference.py loads at scan time.

Requires the `ml` install extra: `pip install -e ".[ml]"` (torch +
transformers + datasets + scikit-learn + accelerate). Heavy imports are
kept inside train_model() rather than at module level, so importing this
file (e.g. from cli.py) doesn't require torch to be installed until you
actually run training.

Usage:
    vulnscan train-model --dataset-db data/cvefixes.duckdb --out models/vuln-classifier
"""

from __future__ import annotations

import logging

from .dataset import Example, build_examples, train_val_split

logger = logging.getLogger("vulnscan.training")


def _filter_truncation_collisions(
    examples: list[Example], tokenizer, max_length: int
) -> list[Example]:
    """Drops (before, after) pairs that tokenize to an identical sequence
    once truncated to max_length. func_before/func_after differ by only a
    handful of lines by construction (see dataset.py) — if that difference
    falls past the truncation point, both sides collapse to the same input
    while keeping opposite labels, i.e. directly contradictory training
    examples. Confirmed via check_truncation.py to affect ~11.8% of pairs
    in the real CVEfixes v2 dataset — a large enough fraction to plausibly
    explain non-convergence on its own, separate from any architecture
    question. Singleton examples (a pair_id with only one side present)
    are kept as-is since there's nothing to collide with.
    """
    by_pair: dict[str, dict[int, Example]] = {}
    for e in examples:
        by_pair.setdefault(e.pair_id, {})[e.label] = e

    kept: list[Example] = []
    dropped_pairs = 0
    for pair_id, by_label in by_pair.items():
        before = by_label.get(1)
        after = by_label.get(0)
        if before is not None and after is not None:
            before_ids = tokenizer(before.code, truncation=True, max_length=max_length)["input_ids"]
            after_ids = tokenizer(after.code, truncation=True, max_length=max_length)["input_ids"]
            if before_ids == after_ids:
                dropped_pairs += 1
                continue
        kept.extend(by_label.values())

    if dropped_pairs:
        logger.info(
            "Filtered out %d/%d pairs that collapse to an identical input after "
            "%d-token truncation (contradictory before/after labels).",
            dropped_pairs, len(by_pair), max_length,
        )
    return kept


def train_model(
    *,
    dataset_db_path: str,
    out_dir: str,
    base_model: str = "microsoft/codebert-base",
    language: str = "python",
    epochs: int = 3,
    batch_size: int = 8,
    # Bumped from 2e-5 -> 5e-5: the v2 run's loss never moved off ln(2) even
    # a little across 3 full epochs, and a post-training sanity check showed
    # near-identical ~51% confidence on two maximally different snippets —
    # i.e. no discriminative signal learned at all, not just "underfit".
    # 5e-5 is the cheapest thing to rule out before assuming this needs a
    # different training setup entirely. Override freely.
    learning_rate: float = 5e-5,
    val_fraction: float = 0.15,
    max_length: int = 512,
    # Diagnostic controls. Set logging_steps=1 for a short run to see
    # per-step loss from the very first step — if it's still dead flat
    # there, that's a much stronger signal of a frozen-gradient problem
    # than of "just needs more data/epochs".
    logging_steps: int = 10,
    warmup_ratio: float = 0.06,
    # See _filter_truncation_collisions — drops pairs whose before/after
    # collapse to an identical input once truncated, which otherwise teach
    # the model contradictory labels for the same input. Confirmed to
    # affect ~11.8% of the real dataset via check_truncation.py.
    filter_truncation_collisions: bool = True,
) -> str:
    try:
        import numpy as np
        import torch
        from sklearn.metrics import precision_recall_fscore_support
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise RuntimeError(
            "torch/transformers/scikit-learn are not installed. Install them with "
            '`pip install -e ".[ml]"` to train a model.'
        ) from exc

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    examples = build_examples(dataset_db_path, language=language)
    if not examples:
        raise ValueError(
            f"No examples found in {dataset_db_path} for language={language!r}. "
            "Load a dataset first with `vulnscan bench-load`."
        )
    if filter_truncation_collisions:
        examples = _filter_truncation_collisions(examples, tokenizer, max_length)
        if not examples:
            raise ValueError(
                "All examples were filtered out as truncation collisions — "
                "check max_length and the dataset."
            )
    train_examples, val_examples = train_val_split(examples, val_fraction=val_fraction)
    logger.info(
        "Training on %d examples (%d vulnerable, %d not), validating on %d (%d vulnerable, %d not)",
        len(train_examples), sum(e.label for e in train_examples),
        sum(1 for e in train_examples if e.label == 0),
        len(val_examples), sum(e.label for e in val_examples),
        sum(1 for e in val_examples if e.label == 0),
    )

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Training device: %s%s", device, " (no GPU detected — this will be slow)" if device == "cpu" else "")

    model = AutoModelForSequenceClassification.from_pretrained(base_model, num_labels=2)

    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    logger.info(
        "Model loaded: %d total params, %d trainable (%.1f%%). If trainable is 0 or "
        "suspiciously small relative to total, the encoder is frozen and that alone "
        "would explain flat loss regardless of learning rate.",
        total_params, trainable_params, 100 * trainable_params / total_params,
    )

    def _to_torch_dataset(examples: list[Example]):
        encodings = tokenizer(
            [e.code for e in examples], truncation=True, max_length=max_length, padding=True,
        )
        labels = [e.label for e in examples]

        class _Dataset(torch.utils.data.Dataset):
            def __len__(self) -> int:
                return len(labels)

            def __getitem__(self, idx: int) -> dict:
                item = {k: torch.tensor(v[idx]) for k, v in encodings.items()}
                item["labels"] = torch.tensor(labels[idx])
                return item

        return _Dataset()

    train_dataset = _to_torch_dataset(train_examples)
    val_dataset = _to_torch_dataset(val_examples) if val_examples else None

    def compute_metrics(eval_pred) -> dict:  # noqa: ANN001
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, preds, average="binary", zero_division=0
        )
        return {"precision": precision, "recall": recall, "f1": f1}

    training_args = TrainingArguments(
        output_dir=out_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        learning_rate=learning_rate,
        eval_strategy="epoch" if val_dataset else "no",
        save_strategy="epoch",
        save_total_limit=1,
        logging_steps=logging_steps,
        logging_first_step=True,
        warmup_ratio=warmup_ratio,
        load_best_model_at_end=bool(val_dataset),
        metric_for_best_model="f1" if val_dataset else None,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics if val_dataset else None,
    )

    trainer.train()

    if val_dataset:
        final_metrics = trainer.evaluate()
        logger.info("Final validation metrics: %s", final_metrics)

    trainer.save_model(out_dir)
    tokenizer.save_pretrained(out_dir)
    logger.info("Model + tokenizer saved to %s", out_dir)
    return out_dir


def train_model_pairwise(
    *,
    dataset_db_path: str,
    out_dir: str,
    base_model: str = "microsoft/codebert-base",
    language: str = "python",
    epochs: int = 3,
    batch_size: int = 8,
    learning_rate: float = 2e-5,
    val_fraction: float = 0.15,
    max_length: int = 512,
    margin: float = 1.0,
    filter_truncation_collisions: bool = True,
    log_every: int = 10,
    seed: int = 42,
) -> str:
    """Trains the classifier with a pairwise margin-ranking objective instead
    of train_model()'s independent binary classification.

    Why: train_model() classifies func_before and func_after as two
    unrelated, independent examples. But every "not vulnerable" example in
    this dataset IS a specific "vulnerable" example, 1-3 lines later, after
    the fix -- the model never sees a broadly diverse population of unrelated
    safe code, only "this exact code, minus its one bug." Three separate
    real training runs (see HANDOFF.md) converged to loss stuck near ln(2)
    and degenerate always-one-class predictions even after fixing a real
    truncation-collision data bug -- the independent-classification framing
    itself isn't giving the model enough to learn from given ~2.4k pairs.

    This instead trains the model so that, for every pair,
    score(before) > score(after), using both halves of the pair together in
    one loss (MarginRankingLoss). This gives the model direct access to the
    one signal it was being denied -- a same-function contrast -- instead of
    asking it to find an absolute decision boundary from isolated snippets.

    Compatibility note: this does NOT change inference. The saved checkpoint
    is loaded and used identically to train_model()'s output --
    local_model/inference.py scores one function at a time either way. Only
    the training *objective* changes; the model's input/output shape is the
    same AutoModelForSequenceClassification with num_labels=2 as before.

    "vulnerable score" here is logits[:, 1] - logits[:, 0] (the margin
    between the two classes), not a plain single-class logit -- keeps the
    score well-defined and comparable across both training and inference.
    """
    try:
        import torch
        from torch.utils.data import DataLoader, Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            get_linear_schedule_with_warmup,
        )
    except ImportError as exc:
        raise RuntimeError(
            "torch/transformers are not installed. Install them with "
            '`pip install -e ".[ml]"` to train a model.'
        ) from exc

    from .dataset import build_pairs, train_val_split_pairs

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    pairs = build_pairs(dataset_db_path, language=language)
    if not pairs:
        raise ValueError(
            f"No pairs found in {dataset_db_path} for language={language!r}. "
            "Load a dataset first with `vulnscan bench-load`."
        )

    if filter_truncation_collisions:
        kept, dropped = [], 0
        for p in pairs:
            before_ids = tokenizer(p.before_code, truncation=True, max_length=max_length)["input_ids"]
            after_ids = tokenizer(p.after_code, truncation=True, max_length=max_length)["input_ids"]
            if before_ids == after_ids:
                dropped += 1
                continue
            kept.append(p)
        if dropped:
            logger.info(
                "Filtered out %d/%d pairs that collapse to an identical input after "
                "%d-token truncation.", dropped, len(pairs), max_length,
            )
        pairs = kept
        if not pairs:
            raise ValueError("All pairs were filtered out as truncation collisions.")

    train_pairs, val_pairs = train_val_split_pairs(pairs, val_fraction=val_fraction, seed=seed)
    logger.info("Training on %d pairs, validating on %d pairs.", len(train_pairs), len(val_pairs))

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Training device: %s%s", device, " (no GPU detected — this will be slow)" if device == "cpu" else "")

    model = AutoModelForSequenceClassification.from_pretrained(base_model, num_labels=2).to(device)

    class _PairDataset(Dataset):
        def __init__(self, pairs: list) -> None:
            self.pairs = pairs

        def __len__(self) -> int:
            return len(self.pairs)

        def __getitem__(self, idx: int):
            return self.pairs[idx]

    def _collate(batch):
        before_enc = tokenizer(
            [p.before_code for p in batch], truncation=True, max_length=max_length,
            padding=True, return_tensors="pt",
        )
        after_enc = tokenizer(
            [p.after_code for p in batch], truncation=True, max_length=max_length,
            padding=True, return_tensors="pt",
        )
        return before_enc, after_enc

    train_loader = DataLoader(_PairDataset(train_pairs), batch_size=batch_size, shuffle=True, collate_fn=_collate)
    val_loader = (
        DataLoader(_PairDataset(val_pairs), batch_size=batch_size, shuffle=False, collate_fn=_collate)
        if val_pairs else None
    )

    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    total_steps = max(1, len(train_loader) * epochs)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=int(0.06 * total_steps), num_training_steps=total_steps,
    )
    loss_fn = torch.nn.MarginRankingLoss(margin=margin)

    def _vuln_score(logits):
        return logits[:, 1] - logits[:, 0]

    def _run_eval(loader) -> tuple[float, float]:
        model.eval()
        total_loss, correct, total = 0.0, 0, 0
        with torch.no_grad():
            for before_enc, after_enc in loader:
                before_enc = {k: v.to(device) for k, v in before_enc.items()}
                after_enc = {k: v.to(device) for k, v in after_enc.items()}
                before_score = _vuln_score(model(**before_enc).logits)
                after_score = _vuln_score(model(**after_enc).logits)
                target = torch.ones_like(before_score)
                total_loss += loss_fn(before_score, after_score, target).item()
                correct += (before_score > after_score).sum().item()
                total += before_score.numel()
        model.train()
        avg_loss = total_loss / max(1, len(loader))
        # Fraction of held-out pairs the model correctly ranks vulnerable > fixed.
        # This is the meaningful metric for a ranking objective -- there's no
        # single-example precision/recall here since nothing is classified
        # independently. 0.5 = chance, 1.0 = perfect ranking.
        ranking_accuracy = correct / total if total else 0.0
        return avg_loss, ranking_accuracy

    step = 0
    for epoch in range(epochs):
        model.train()
        epoch_losses = []
        for before_enc, after_enc in train_loader:
            before_enc = {k: v.to(device) for k, v in before_enc.items()}
            after_enc = {k: v.to(device) for k, v in after_enc.items()}

            before_score = _vuln_score(model(**before_enc).logits)
            after_score = _vuln_score(model(**after_enc).logits)
            target = torch.ones_like(before_score)
            loss = loss_fn(before_score, after_score, target)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            scheduler.step()

            epoch_losses.append(loss.item())
            step += 1
            if step % log_every == 0:
                logger.info(
                    "step %d (epoch %.3f) loss=%.4f lr=%.3e",
                    step, epoch + (step % len(train_loader)) / len(train_loader),
                    loss.item(), scheduler.get_last_lr()[0],
                )

        train_loss = sum(epoch_losses) / len(epoch_losses)
        summary = f"Epoch {epoch + 1}/{epochs}: train_loss={train_loss:.4f}"
        if val_loader:
            val_loss, val_ranking_acc = _run_eval(val_loader)
            summary += f", val_loss={val_loss:.4f}, val_ranking_accuracy={val_ranking_acc:.4f}"
        logger.info(summary)

    model.save_pretrained(out_dir)
    tokenizer.save_pretrained(out_dir)
    logger.info("Model + tokenizer saved to %s", out_dir)
    return out_dir