import sqlite3

try:
    conn = sqlite3.connect('db.sqlite3')
except sqlite3.OperationalError:
    print("You need to create the database - python database.py")
else:
    cursor = conn.cursor()
    count = cursor.execute("SELECT COUNT(*) FROM track").fetchone()[0]
    print(f"There are {count} records in the Track table")
finally:
    conn.close()