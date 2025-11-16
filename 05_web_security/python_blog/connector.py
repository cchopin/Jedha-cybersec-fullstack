import sqlite3
from flask import g


def get_db():
    """Get a database connection for the current request context."""
    if 'db' not in g:
        g.db = sqlite3.connect("blog.db")
        g.db.row_factory = sqlite3.Row  # This allows dict-like access to rows
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def read_all(table):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM {table}")
    rows = cursor.fetchall()
    return rows


def read_one(table, id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM {table} WHERE Id = ?", (id,))
    row = cursor.fetchone()
    return row


def add_post(title, content):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"INSERT INTO POSTS (Title, Content) VALUES (?,?)", (title, content,))
    db.commit()


def delete_post(id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"DELETE FROM POSTS WHERE ID = ? ", (id,))
    db.commit()