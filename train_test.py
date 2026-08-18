import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

from vulnscan.training.train import train_model_pairwise
train_model_pairwise(
    dataset_db_path='data/cvefixes_v2.duckdb',
    out_dir='models/vuln-classifier-v6',
    epochs=6,  # last run hadn't plateaued yet, worth extending too
    generic_negatives_path='data/codesearchnet_negatives.jsonl',
)