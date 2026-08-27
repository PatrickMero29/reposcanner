import duckdb, os

path = "data/cvefixes_v2.duckdb"
if not os.path.exists(path):
    print(f"{path} does not exist on this machine.")
else:
    con = duckdb.connect(path, read_only=True)
    total = con.execute("SELECT count(*) FROM pairs WHERE language='python'").fetchone()
    null_name = con.execute("SELECT count(*) FROM pairs WHERE language='python' AND (function_name IS NULL OR function_name='')").fetchone()
    non_py = con.execute("SELECT count(*) FROM pairs WHERE language='python' AND file_path NOT LIKE '%.py'").fetchone()
    print("total python pairs:", total)
    print("null/empty function_name:", null_name)
    print("non-.py file_path:", non_py)
    print(con.execute("SELECT pair_id, function_name, file_path, func_before FROM pairs WHERE language='python' LIMIT 1").fetchone())
    con.close()