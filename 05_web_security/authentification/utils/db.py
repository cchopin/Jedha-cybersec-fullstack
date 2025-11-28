import sqlite3
from flask import g
from config import DATABASE_PATH

def get_db_connection():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db_connection(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def execute_query(query, params=(), fetch_one=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        if fetch_one:
            result = cursor.fetchone()
        else:
            result = cursor.fetchall()
        if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
            conn.commit()
        return result
    except Exception as e:
        conn.rollback()
        raise e
