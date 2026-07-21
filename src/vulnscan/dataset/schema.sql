-- Generic schema for vulnerable/fixed function pairs, dataset-agnostic.
-- Any CVE-labeled dataset (CVEfixes, Big-Vul, PrimeVul, a hand-built CSV...)
-- gets converted into this shape before the benchmark pipeline touches it,
-- so run_analysis.py / diff_judge.py / judge.py never need to know which
-- upstream dataset produced the rows.

CREATE TABLE IF NOT EXISTS pairs (
    pair_id         VARCHAR PRIMARY KEY,
    cve_id          VARCHAR,
    cwe_ids         VARCHAR,   -- comma-separated, e.g. "CWE-89,CWE-20"
    language        VARCHAR NOT NULL,
    repo            VARCHAR,
    file_path       VARCHAR,
    function_name   VARCHAR,
    func_before      VARCHAR NOT NULL,  -- vulnerable version
    func_after       VARCHAR NOT NULL,  -- fixed version
    commit_message  VARCHAR,
    nvd_url         VARCHAR
);
