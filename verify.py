from vulnscan.dataset.cvefixes_loader import inspect_cvefixes_schema
print(inspect_cvefixes_schema('CVEfixes.db'))

from vulnscan.dataset.cvefixes_loader import load_from_cvefixes_sqlite
load_from_cvefixes_sqlite('CVEfixes.db', 'data/cvefixes_v2.duckdb')