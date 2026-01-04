import sqlite3

def bad(user_input):
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % user_input)
    return cur.fetchall()