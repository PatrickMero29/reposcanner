import gzip
import sqlite3

def convert_cve_db():
    print("Connecting to database...")
    con = sqlite3.connect('CVEfixes.db')
    cursor = con.cursor()

    buffer = ""
    print("Decompressing and executing SQL script...")
    
    # Process the file line-by-line to prevent RAM exhaustion
    with gzip.open('CVEfixes_v1.0.8.sql.gz', 'rt', encoding='utf-8') as f:
        for line in f:
            # Skip empty lines and single-line comments to speed up parsing
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith('--'):
                continue
                
            buffer += line
            
            # Once the buffer contains a complete SQL statement (ends with ';'), execute it
            if sqlite3.complete_statement(buffer):
                try:
                    cursor.execute(buffer)
                except sqlite3.Error as e:
                    print(f"Error executing statement: {e}")
                
                # Clear the buffer for the next statement
                buffer = "" 

    print("Committing changes...")
    con.commit()
    con.close()
    print("Database built successfully.")

if __name__ == "__main__":
    convert_cve_db()