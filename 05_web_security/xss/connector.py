import sqlite3
import os
from flask import g


def init_db():
    if not os.path.exists('guestbook.db'):
        conn = sqlite3.connect('guestbook.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                message TEXT NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("guestbook.db")
        g.db.row_factory = sqlite3.Row  # This allows dict-like access to rows
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def read_all(table):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM {table}")
    rows = cursor.fetchall()
    return rows


def search_comment(query):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM comments WHERE message LIKE ?", ('%' + query + '%',))
    rows = cursor.fetchall()
    return rows


def add_comment(name, message):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"INSERT INTO comments (name, message) VALUES (?,?)", (name, message,))
    db.commit()


def delete_comment(comment_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"DELETE FROM comments WHERE id = ? ", (comment_id,))
    db.commit()