import duckdb

con = duckdb.connect('data/cvefixes.duckdb', read_only=True)
print("total python pairs:", con.execute("SELECT count(*) FROM pairs WHERE language='python'").fetchone())
print("null/empty function_name:", con.execute("SELECT count(*) FROM pairs WHERE function_name IS NULL OR function_name=''").fetchone())
print("non-.py file_path:", con.execute("SELECT count(*) FROM pairs WHERE file_path NOT LIKE '%.py'").fetchone())
print(con.execute("SELECT pair_id, function_name, file_path, func_before FROM pairs LIMIT 1").fetchone())
con.close()