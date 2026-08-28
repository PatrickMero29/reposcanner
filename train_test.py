import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

from vulnscan.training.train import train_model_pairwise
train_model_pairwise(
    dataset_db_path='data/cvefixes.duckdb',   
    out_dir='models/vuln-classifier-v18',     
    epochs=6,
    generic_negatives_path='data/codesearchnet_negatives.jsonl',
    curated_negatives_path='data/curated_negatives.jsonl',
    curated_pairs_path='data/curated_vulnerable_pairs.jsonl',
)