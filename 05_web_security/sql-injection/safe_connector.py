import sqlite3
from flask import g

DB_NAME = 'injection.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_NAME)
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# ============== STATS ==============
def get_stats():
    db = get_db()
    cursor = db.cursor()
    stats = {}
    stats['users'] = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    stats['products'] = cursor.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    stats['orders'] = cursor.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    stats['categories'] = cursor.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
    return stats


# ============== LOGIN ==============
def login(username, password):
    """SECURE: Parameterized query"""
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE name=? AND password=?"
    cursor.execute(query, (username, password))
    query_display = f"SELECT * FROM users WHERE name='{username}' AND password='{password}' (PARAMETREE)"
    return cursor.fetchone(), query_display


# ============== USERS ==============
def get_all_users():
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM users"
    cursor.execute(query)
    return cursor.fetchall(), query


def search_users(search):
    """SECURE: Parameterized query with LIKE"""
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE name LIKE ? OR email LIKE ?"
    search_param = f"%{search}%"
    cursor.execute(query, (search_param, search_param))
    query_display = f"SELECT * FROM users WHERE name LIKE '%{search}%' OR email LIKE '%{search}%' (PARAMETREE)"
    return cursor.fetchall(), query_display


# ============== PRODUCTS ==============
def get_all_products():
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM products"
    cursor.execute(query)
    return cursor.fetchall(), query


def search_products(search=None, category=None):
    """SECURE: Parameterized queries"""
    db = get_db()
    cursor = db.cursor()

    if search and category:
        query = "SELECT * FROM products WHERE name LIKE ? AND fk_category = ?"
        search_param = f"%{search}%"
        cursor.execute(query, (search_param, category))
        query_display = f"SELECT * FROM products WHERE name LIKE '%{search}%' AND fk_category = {category} (PARAMETREE)"
    elif search:
        query = "SELECT * FROM products WHERE name LIKE ?"
        search_param = f"%{search}%"
        cursor.execute(query, (search_param,))
        query_display = f"SELECT * FROM products WHERE name LIKE '%{search}%' (PARAMETREE)"
    elif category:
        query = "SELECT * FROM products WHERE fk_category = ?"
        cursor.execute(query, (category,))
        query_display = f"SELECT * FROM products WHERE fk_category = {category} (PARAMETREE)"
    else:
        query = "SELECT * FROM products"
        cursor.execute(query)
        query_display = query

    return cursor.fetchall(), query_display


# ============== ORDERS ==============
def get_all_orders():
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM orders"
    cursor.execute(query)
    return cursor.fetchall(), query


def search_orders(user_id=None, product_id=None):
    """SECURE: Parameterized queries"""
    db = get_db()
    cursor = db.cursor()

    if user_id and product_id:
        query = "SELECT * FROM orders WHERE fk_user = ? AND fk_product = ?"
        cursor.execute(query, (user_id, product_id))
        query_display = f"SELECT * FROM orders WHERE fk_user = {user_id} AND fk_product = {product_id} (PARAMETREE)"
    elif user_id:
        query = "SELECT * FROM orders WHERE fk_user = ?"
        cursor.execute(query, (user_id,))
        query_display = f"SELECT * FROM orders WHERE fk_user = {user_id} (PARAMETREE)"
    elif product_id:
        query = "SELECT * FROM orders WHERE fk_product = ?"
        cursor.execute(query, (product_id,))
        query_display = f"SELECT * FROM orders WHERE fk_product = {product_id} (PARAMETREE)"
    else:
        query = "SELECT * FROM orders"
        cursor.execute(query)
        query_display = query

    return cursor.fetchall(), query_display


# ============== BLIND INJECTION ==============
def check_user_exists(username):
    """SECURE: Parameterized query for boolean-based check"""
    db = get_db()
    cursor = db.cursor()
    query = "SELECT 1 FROM users WHERE name=? LIMIT 1"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    query_display = f"SELECT 1 FROM users WHERE name='{username}' LIMIT 1 (PARAMETREE)"
    return result is not None, query_display


def check_user_by_id(user_id):
    """SECURE: Parameterized query for time-based check"""
    db = get_db()
    cursor = db.cursor()
    query = "SELECT 1 FROM users WHERE id=? LIMIT 1"
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()
    query_display = f"SELECT 1 FROM users WHERE id={user_id} LIMIT 1 (PARAMETREE)"
    return result is not None, query_display


# ============== OUT-OF-BAND ==============
def attach_database_exploit(filepath, table_to_steal):
    """SECURE: Blocked - ATTACH DATABASE not allowed"""
    query_display = "OPERATION BLOQUEE - ATTACH DATABASE non autorise (SECURE)"
    return "Operation bloquee: ATTACH DATABASE est desactive en mode securise", query_display


def extract_table_to_file(table_name):
    """SECURE: Parameterized - but still writes to file for demo"""
    # En production, on n'autoriserait pas l'ecriture de fichiers du tout
    query_display = "OPERATION BLOQUEE - Extraction vers fichier non autorisee (SECURE)"
    return "Operation bloquee: L'extraction vers fichier est desactivee en mode securise", query_display


# ============== STORED/SECOND-ORDER INJECTION ==============
def add_user_secure(name, email, password):
    """Insert user - parameterized query"""
    db = get_db()
    cursor = db.cursor()
    query = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)"
    cursor.execute(query, (name, email, password))
    db.commit()
    query_display = f"INSERT INTO users (name, email, password) VALUES ('{name}', '{email}', '{password}') (PARAMETREE)"
    return "Utilisateur cree avec succes", query_display


def search_user_by_name_unsafe(name):
    """SECURE: Parameterized query for search"""
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (name,))
    query_display = f"SELECT * FROM users WHERE name = '{name}' (PARAMETREE)"
    return cursor.fetchall(), query_display


def login_with_stored_name(username, password):
    """SECURE: Parameterized query for login"""
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE name=? AND password=?"
    cursor.execute(query, (username, password))
    query_display = f"SELECT * FROM users WHERE name='{username}' AND password='{password}' (PARAMETREE)"
    return cursor.fetchone(), query_display
