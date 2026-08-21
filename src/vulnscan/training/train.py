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

import json
import logging
import random
from pathlib import Path

from .dataset import Example, PairExample, build_examples, train_val_split

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
    generic_negatives_path: str | None = None,
    generic_negative_ratio: float = 1.0,
    # Weight on the absolute cross-entropy anchor term (see docstring below).
    # 0.0 reproduces the pure-ranking v5/v6 behavior; don't set it to 0 unless
    # you specifically want to reproduce that calibration-drift failure mode.
    ce_weight: float = 1.0,
    # DataLoader workers for the (now-cheap) collate step. Default 0 is safest
    # on Windows -- if you raise this, the script calling train_model_pairwise
    # must be guarded with `if __name__ == "__main__":`, since Windows uses
    # spawn-based multiprocessing and will otherwise re-import (and re-run)
    # your whole script in each worker process.
    num_workers: int = 0,
    # Mixed precision on CUDA (torch.autocast + GradScaler) -- roughly halves
    # step time on modern NVIDIA GPUs with no accuracy trade-off; loss scaling
    # handles the numerical stability. Auto-disabled on CPU regardless of
    # this flag. None = auto (on for CUDA, off for CPU).
    use_amp: bool | None = None,
    # Which epoch's checkpoint ends up saved at out_dir. Every past run just
    # kept whichever epoch happened to run last -- v10's held-out metrics
    # weren't even monotonically improving epoch-to-epoch, so "last" and
    # "best" aren't the same thing. Doesn't cost extra disk: only ever one
    # checkpoint is written to out_dir, overwritten in place whenever a
    # later epoch's score beats the best-so-far -- not one dir per epoch.
    # "composite" = average of val_ranking_accuracy (fine-grained CVE-pair
    # discrimination) and held-out generic ranking_accuracy (does this
    # generalize to arbitrary code) -- the two things that matter and can
    # trade off against each other, per the v9/v10 regression discussion.
    best_epoch_metric: str = "composite",
    # v11 picked epoch 2 (composite=0.8569) over epoch 5 (composite=0.8550)
    # -- a 0.0019 difference on a 756-example held-out set, i.e. ~3 examples
    # flipping either way. That's noise, not signal, and epoch 2 was
    # meaningfully less converged (train_loss 1.51 vs epoch 5's 0.87). A
    # later epoch within `best_epoch_tolerance` of the current best score
    # is now preferred over an earlier one, since more training exposure is
    # independent evidence it's more converged even when these two coarse
    # held-out metrics can't tell them apart. Only a genuinely larger score
    # improvement moves the "best" epoch backward in time.
    best_epoch_tolerance: float = 0.01,
) -> str:
    """Trains the classifier with a pairwise margin-ranking objective PLUS an
    absolute cross-entropy anchor, instead of train_model()'s independent
    binary classification.

    History (see HANDOFF.md and this conversation for the full trail):
    train_model() classifies func_before/func_after independently and never
    converged -- every "not vulnerable" example IS a specific "vulnerable"
    example, 1-3 lines later, after the fix, so the model never saw a
    diverse population of unrelated safe code. Pure margin-ranking
    (train_model_pairwise v5/v6) fixed convergence -- val_ranking_accuracy
    reached ~0.73 -- but a real problem then showed up in sanity_check.py:
    both a vulnerable AND a trivially-safe snippet came back flagged at
    94-99%. MarginRankingLoss only constrains RELATIVE order within a pair
    (score(before) > score(after)); nothing stops both scores drifting
    upward together, satisfying the loss while destroying any absolute
    "this is safe" signal.

    The `ce_weight` term fixes that: alongside the ranking loss, it also
    trains before_logits toward class 1 and after_logits toward class 0 in
    the ordinary cross-entropy sense. This anchors the absolute scale while
    keeping the ranking loss's benefit of exploiting the near-duplicate
    structure for the fine-grained before/after cases. Set ce_weight=0.0
    only if you want to deliberately reproduce the v6 drift for comparison.

    Compatibility note: this does NOT change inference. The saved checkpoint
    is loaded and used identically to train_model()'s output --
    local_model/inference.py scores one function at a time either way. Only
    the training *objective* changes; the model's input/output shape is the
    same AutoModelForSequenceClassification with num_labels=2 as before.

    Performance note: unlike the earlier version of this function, all
    tokenization happens ONCE up front (two batched tokenizer calls total,
    not one per batch per epoch), before/after pairs are combined into a
    single forward pass per step instead of two sequential ones, and mixed
    precision is on by default on CUDA. Same computation, none of it
    repeated unnecessarily.
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

    # `seed` was already used for data shuffling (Python's random module) but
    # never for torch -- meaning the classifier head's random initialization
    # (and dropout) differed on every run regardless of this parameter.
    # v9/v10/v11 were never a clean apples-to-apples comparison because of
    # this; seeding here makes re-running with the same config actually
    # reproducible.
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

    from .dataset import build_pairs, load_generic_negatives, train_val_split_pairs

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

    val_generic_pairs: list[PairExample] = []
    if generic_negatives_path:
        rng = random.Random(seed)
        generic_negatives = load_generic_negatives(generic_negatives_path)
        if not generic_negatives:
            raise ValueError(f"No negatives loaded from {generic_negatives_path!r}.")

        # Hold out a slice of negatives that NEVER appears in training, so we
        # get a real held-out measurement of generalization to generic code
        # instead of relying on sanity_check.py's two anecdotal examples,
        # which only tell you about those two specific snippets and can't be
        # tracked epoch-over-epoch.
        rng.shuffle(generic_negatives)
        n_val_negatives = max(1, round(val_fraction * len(generic_negatives)))
        val_negatives = generic_negatives[:n_val_negatives]
        train_negatives = generic_negatives[n_val_negatives:]
        if not train_negatives:
            raise ValueError(
                f"Only {len(generic_negatives)} negatives loaded -- not enough left for "
                "training after holding out a validation slice."
            )

        n_synthetic = round(generic_negative_ratio * len(train_pairs))
        vulnerable_pool = [p.before_code for p in train_pairs]
        synthetic = [
            PairExample(
                pair_id=f"synthetic:{i}",
                before_code=rng.choice(vulnerable_pool),
                after_code=rng.choice(train_negatives),
            )
            for i in range(n_synthetic)
        ]
        logger.info(
            "Augmenting training set with %d synthetic (real-vulnerable, generic-safe) "
            "pairs from %s (%d train negatives, %d held out for validation).",
            n_synthetic, generic_negatives_path, len(train_negatives), len(val_negatives),
        )
        train_pairs = train_pairs + synthetic

        # Held-out generic validation set: real held-out vulnerable code
        # (from val_pairs, never trained on) vs held-out generic negatives
        # (also never trained on). This is the metric that actually answers
        # "does this generalize to arbitrary unrelated code", which neither
        # val_ranking_accuracy nor a 2-example sanity check can.
        val_vulnerable_pool = [p.before_code for p in val_pairs]
        if val_vulnerable_pool and val_negatives:
            val_generic_pairs = [
                PairExample(
                    pair_id=f"val_generic:{i}",
                    before_code=rng.choice(val_vulnerable_pool),
                    after_code=neg,
                )
                for i, neg in enumerate(val_negatives)
            ]

    logger.info(
        "Training on %d pairs, validating on %d CVE pairs + %d generic-negative pairs.",
        len(train_pairs), len(val_pairs), len(val_generic_pairs),
    )

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Training device: %s%s", device, " (no GPU detected — this will be slow)" if device == "cpu" else "")
    if use_amp is None:
        use_amp = device == "cuda"
    elif use_amp and device != "cuda":
        logger.info("use_amp=True has no effect on CPU; disabling.")
        use_amp = False

    model = AutoModelForSequenceClassification.from_pretrained(base_model, num_labels=2).to(device)

    # Tokenize everything ONCE, up front, with two batched tokenizer calls
    # per split (before-side, after-side) rather than per-batch-per-epoch.
    # The Rust tokenizer is much faster batched than called example-by-example.
    def _pretokenize(pairs: list) -> tuple[list[dict], list[dict]]:
        before_batch = tokenizer([p.before_code for p in pairs], truncation=True, max_length=max_length)
        after_batch = tokenizer([p.after_code for p in pairs], truncation=True, max_length=max_length)
        before_list = [
            {"input_ids": before_batch["input_ids"][i], "attention_mask": before_batch["attention_mask"][i]}
            for i in range(len(pairs))
        ]
        after_list = [
            {"input_ids": after_batch["input_ids"][i], "attention_mask": after_batch["attention_mask"][i]}
            for i in range(len(pairs))
        ]
        return before_list, after_list

    train_before, train_after = _pretokenize(train_pairs)
    val_before, val_after = _pretokenize(val_pairs) if val_pairs else ([], [])
    val_generic_before, val_generic_after = _pretokenize(val_generic_pairs) if val_generic_pairs else ([], [])

    class _PairDataset(Dataset):
        def __init__(self, before_list: list[dict], after_list: list[dict]) -> None:
            self.before_list = before_list
            self.after_list = after_list

        def __len__(self) -> int:
            return len(self.before_list)

        def __getitem__(self, idx: int):
            return self.before_list[idx], self.after_list[idx]

    def _collate(batch):
        # Combine before+after into ONE padded batch of size 2*len(batch), so
        # the model does a single forward pass per step instead of two. Only
        # padding happens here (cheap); tokenization already happened above.
        combined_input_ids = [b["input_ids"] for b, _ in batch] + [a["input_ids"] for _, a in batch]
        combined_attn = [b["attention_mask"] for b, _ in batch] + [a["attention_mask"] for _, a in batch]
        padded = tokenizer.pad(
            {"input_ids": combined_input_ids, "attention_mask": combined_attn},
            padding=True, return_tensors="pt",
        )
        return padded, len(batch)

    loader_kwargs = dict(
        collate_fn=_collate, num_workers=num_workers,
        pin_memory=(device == "cuda"), persistent_workers=(num_workers > 0),
    )
    train_loader = DataLoader(_PairDataset(train_before, train_after), batch_size=batch_size, shuffle=True, **loader_kwargs)
    val_loader = (
        DataLoader(_PairDataset(val_before, val_after), batch_size=batch_size, shuffle=False, **loader_kwargs)
        if val_pairs else None
    )
    val_generic_loader = (
        DataLoader(_PairDataset(val_generic_before, val_generic_after), batch_size=batch_size, shuffle=False, **loader_kwargs)
        if val_generic_pairs else None
    )

    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    total_steps = max(1, len(train_loader) * epochs)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=int(0.06 * total_steps), num_training_steps=total_steps,
    )
    rank_loss_fn = torch.nn.MarginRankingLoss(margin=margin)
    ce_loss_fn = torch.nn.CrossEntropyLoss()
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)

    def _vuln_score(logits):
        return logits[:, 1] - logits[:, 0]

    def _forward_combined(padded: dict, batch_size_b: int):
        """One forward pass over the combined [before; after] batch, split
        back into before/after halves. Returns logits, not loss, so both the
        train step and eval step can share this."""
        logits = model(**padded).logits
        return logits[:batch_size_b], logits[batch_size_b:]

    def _compute_loss(before_logits, after_logits):
        before_score = _vuln_score(before_logits)
        after_score = _vuln_score(after_logits)
        target = torch.ones_like(before_score)
        rank_loss = rank_loss_fn(before_score, after_score, target)

        ones = torch.ones(before_logits.size(0), dtype=torch.long, device=before_logits.device)
        zeros = torch.zeros(after_logits.size(0), dtype=torch.long, device=after_logits.device)
        ce_loss = (ce_loss_fn(before_logits, ones) + ce_loss_fn(after_logits, zeros)) / 2

        loss = rank_loss + ce_weight * ce_loss
        return loss, rank_loss, ce_loss, before_score, after_score

    def _run_eval(loader) -> dict:
        model.eval()
        total_loss, correct, total = 0.0, 0, 0
        before_probs, after_probs = [], []
        with torch.no_grad():
            for padded, b in loader:
                padded = {k: v.to(device, non_blocking=True) for k, v in padded.items()}
                with torch.autocast(device_type="cuda", enabled=use_amp):
                    before_logits, after_logits = _forward_combined(padded, b)
                    loss, *_ = _compute_loss(before_logits, after_logits)
                before_score = _vuln_score(before_logits)
                after_score = _vuln_score(after_logits)
                total_loss += loss.item()
                correct += (before_score > after_score).sum().item()
                total += before_score.numel()
                # Calibration diagnostic: mean P(vulnerable) in the absolute
                # sense, not just relative ranking -- this is exactly what
                # caught the v6 drift (both landing near 1.0 regardless of
                # which side of the pair they were).
                before_probs.append(torch.softmax(before_logits, dim=-1)[:, 1].mean().item())
                after_probs.append(torch.softmax(after_logits, dim=-1)[:, 1].mean().item())
        model.train()
        n_batches = max(1, len(loader))
        return {
            "loss": total_loss / n_batches,
            "ranking_accuracy": correct / total if total else 0.0,
            "avg_before_prob_vuln": sum(before_probs) / n_batches,
            "avg_after_prob_vuln": sum(after_probs) / n_batches,
        }

    def _composite_score(epoch_metrics: dict) -> float:
        cve_acc = epoch_metrics.get("val_ranking_accuracy")
        generic_acc = epoch_metrics.get("held_out_generic_ranking_accuracy")
        if best_epoch_metric == "val_ranking_accuracy":
            return cve_acc if cve_acc is not None else float("-inf")
        if best_epoch_metric == "generic_ranking_accuracy":
            return generic_acc if generic_acc is not None else float("-inf")
        if best_epoch_metric == "composite":
            vals = [v for v in (cve_acc, generic_acc) if v is not None]
            return sum(vals) / len(vals) if vals else float("-inf")
        raise ValueError(
            f"Unknown best_epoch_metric={best_epoch_metric!r}, expected one of "
            "'composite', 'val_ranking_accuracy', 'generic_ranking_accuracy'."
        )

    step = 0
    history: list[dict] = []
    best_score = float("-inf")
    best_epoch = None
    for epoch in range(epochs):
        model.train()
        epoch_losses = []
        for padded, b in train_loader:
            padded = {k: v.to(device, non_blocking=True) for k, v in padded.items()}

            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type="cuda", enabled=use_amp):
                before_logits, after_logits = _forward_combined(padded, b)
                loss, rank_loss, ce_loss, *_ = _compute_loss(before_logits, after_logits)

            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()

            epoch_losses.append(loss.item())
            step += 1
            if step % log_every == 0:
                logger.info(
                    "step %d (epoch %.3f) loss=%.4f (rank=%.4f, ce=%.4f) lr=%.3e",
                    step, epoch + (step % len(train_loader)) / len(train_loader),
                    loss.item(), rank_loss.item(), ce_loss.item(), scheduler.get_last_lr()[0],
                )

        train_loss = sum(epoch_losses) / len(epoch_losses)
        epoch_metrics: dict = {"epoch": epoch + 1, "train_loss": train_loss}
        summary = f"Epoch {epoch + 1}/{epochs}: train_loss={train_loss:.4f}"
        if val_loader:
            m = _run_eval(val_loader)
            epoch_metrics.update({
                "val_loss": m["loss"],
                "val_ranking_accuracy": m["ranking_accuracy"],
                "val_avg_before_prob_vuln": m["avg_before_prob_vuln"],
                "val_avg_after_prob_vuln": m["avg_after_prob_vuln"],
            })
            summary += (
                f", val_loss={m['loss']:.4f}, val_ranking_accuracy={m['ranking_accuracy']:.4f}, "
                f"val_avg_prob_vuln(before/after)={m['avg_before_prob_vuln']:.3f}/{m['avg_after_prob_vuln']:.3f}"
            )
        if val_generic_loader:
            g = _run_eval(val_generic_loader)
            epoch_metrics.update({
                "held_out_generic_ranking_accuracy": g["ranking_accuracy"],
                "held_out_generic_avg_before_prob_vuln": g["avg_before_prob_vuln"],
                "held_out_generic_avg_after_prob_vuln": g["avg_after_prob_vuln"],
            })
            # This is the number that answers "does this generalize to
            # arbitrary unrelated code" -- neither before/after here has ever
            # been seen in training. before = held-out real vulnerable code,
            # after = held-out generic negative (never-trained-on
            # CodeSearchNet function). Want after_prob_vuln low and
            # ranking_accuracy high; sanity_check.py's cases are a spot check
            # on this, not a substitute for it.
            summary += (
                f" | held-out generic: ranking_accuracy={g['ranking_accuracy']:.4f}, "
                f"avg_prob_vuln(vuln/generic_negative)={g['avg_before_prob_vuln']:.3f}/{g['avg_after_prob_vuln']:.3f}"
            )

        score = _composite_score(epoch_metrics)
        epoch_metrics["selection_score"] = score
        # A later epoch wins if it's strictly better, OR if it's within
        # tolerance of the best-so-far -- since it's later, it's had strictly
        # more training and that's independent evidence of being at least as
        # converged, even when these two coarse held-out numbers can't
        # distinguish them. Only a real (>tolerance) drop keeps the earlier
        # epoch's checkpoint in place.
        is_best = score > best_score - best_epoch_tolerance
        if is_best:
            improved = score > best_score
            best_score = max(score, best_score)
            best_epoch = epoch + 1
            model.save_pretrained(out_dir)
            tokenizer.save_pretrained(out_dir)
            tag = "NEW BEST" if improved else "KEPT (within tolerance of best, later epoch preferred)"
            summary += f" -> {tag} (score={score:.4f}, best={best_score:.4f}), saved to {out_dir}"
        history.append(epoch_metrics)
        logger.info(summary)

    if best_epoch is None:
        # No val data to score against (val_loader/val_generic_loader both
        # empty) -- fall back to saving whatever the last epoch produced,
        # same behavior as before this change.
        model.save_pretrained(out_dir)
        tokenizer.save_pretrained(out_dir)
        best_epoch = epochs
        logger.info("No validation data available to pick a best epoch -- saved final epoch instead.")

    history_path = Path(out_dir) / "training_history.json"
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(
            {"best_epoch": best_epoch, "best_epoch_metric": best_epoch_metric, "epochs": history},
            f, indent=2,
        )
    logger.info(
        "Training complete. Best epoch: %d/%d (by %s, score=%.4f). "
        "Full per-epoch history: %s",
        best_epoch, epochs, best_epoch_metric, best_score, history_path,
    )
    return out_dir