import gzip, sqlite3
with gzip.open('CVEfixes_v1.0.8.sql.gz', 'rt', encoding='utf-8') as f:
    sql_script = f.read()
con = sqlite3.connect('CVEfixes.db')
con.executescript(sql_script)
con.commit()
con.close()