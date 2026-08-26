import duckdb
from transformers import AutoTokenizer

tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")
con = duckdb.connect("data/cvefixes.duckdb", read_only=True)
rows = con.execute("SELECT pair_id, func_before FROM pairs WHERE language='python'").fetchall()
con.close()

lengths = [(pid, len(tok.encode(code))) for pid, code in rows]
over_512 = [pid for pid, l in lengths if l > 512]
print(f"total pairs: {len(lengths)}")
print(f"truncated at max_length=512: {len(over_512)} ({100*len(over_512)/len(lengths):.1f}%)")
print(f"median tokens: {sorted(l for _, l in lengths)[len(lengths)//2]}")