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


def train_model(
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

    examples = build_examples(dataset_db_path, language=language)
    if not examples:
        raise ValueError(
            f"No examples found in {dataset_db_path} for language={language!r}. "
            "Load a dataset first with `vulnscan bench-load`."
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

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForSequenceClassification.from_pretrained(base_model, num_labels=2)

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
        logging_steps=10,
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
