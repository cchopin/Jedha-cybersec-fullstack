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
    """VULNERABLE: SQL Injection via string concatenation"""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT * FROM users WHERE name='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone(), query


# ============== USERS ==============
def get_all_users():
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM users"
    cursor.execute(query)
    return cursor.fetchall(), query


def search_users(search):
    """VULNERABLE: SQL Injection via LIKE clause"""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT * FROM users WHERE name LIKE '%{search}%' OR email LIKE '%{search}%'"
    cursor.execute(query)
    return cursor.fetchall(), query


# ============== PRODUCTS ==============
def get_all_products():
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM products"
    cursor.execute(query)
    return cursor.fetchall(), query


def search_products(search=None, category=None):
    """VULNERABLE: SQL Injection via multiple parameters"""
    db = get_db()
    cursor = db.cursor()

    if search and category:
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%' AND fk_category = {category}"
    elif search:
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
    elif category:
        query = f"SELECT * FROM products WHERE fk_category = {category}"
    else:
        query = "SELECT * FROM products"

    cursor.execute(query)
    return cursor.fetchall(), query


# ============== ORDERS ==============
def get_all_orders():
    db = get_db()
    cursor = db.cursor()
    query = "SELECT * FROM orders"
    cursor.execute(query)
    return cursor.fetchall(), query


def search_orders(user_id=None, product_id=None):
    """VULNERABLE: SQL Injection via numeric parameters"""
    db = get_db()
    cursor = db.cursor()

    if user_id and product_id:
        query = f"SELECT * FROM orders WHERE fk_user = {user_id} AND fk_product = {product_id}"
    elif user_id:
        query = f"SELECT * FROM orders WHERE fk_user = {user_id}"
    elif product_id:
        query = f"SELECT * FROM orders WHERE fk_product = {product_id}"
    else:
        query = "SELECT * FROM orders"

    cursor.execute(query)
    return cursor.fetchall(), query


# ============== BLIND INJECTION ==============
def check_user_exists(username):
    """VULNERABLE: Boolean-based blind injection"""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT 1 FROM users WHERE name='{username}' LIMIT 1"
    cursor.execute(query)
    result = cursor.fetchone()
    return result is not None, query


def check_user_by_id(user_id):
    """VULNERABLE: Time-based blind injection"""
    db = get_db()
    cursor = db.cursor()
    query = f"SELECT 1 FROM users WHERE id={user_id} LIMIT 1"
    cursor.execute(query)
    result = cursor.fetchone()
    return result is not None, query


# ============== OUT-OF-BAND ==============
def attach_database_exploit(filepath, table_to_steal):
    """VULNERABLE: Out-of-band via ATTACH DATABASE - ecrit les donnees dans un fichier externe"""
    db = get_db()
    cursor = db.cursor()

    # ATTACH DATABASE permet d'ecrire dans n'importe quel fichier accessible
    query = f"ATTACH DATABASE '{filepath}' AS exfil; CREATE TABLE IF NOT EXISTS exfil.stolen AS SELECT * FROM {table_to_steal};"

    try:
        cursor.executescript(query)
        return f"Base exfiltree vers: {filepath}", query
    except Exception as e:
        return f"Erreur: {str(e)}", query


def extract_table_to_file(table_name):
    """VULNERABLE: Extract table data to file - injection dans le nom de table"""
    db = get_db()
    cursor = db.cursor()

    # Query vulnerable - le nom de table est injecte directement
    query = f"SELECT * FROM {table_name}"

    try:
        cursor.execute(query)
        results = cursor.fetchall()

        # Ecrire les resultats dans un fichier
        filepath = f"/tmp/extract_data.txt"
        with open(filepath, 'w') as f:
            for row in results:
                f.write(str(row) + '\n')

        return f"Donnees extraites vers: {filepath} ({len(results)} lignes)", query
    except Exception as e:
        return f"Erreur: {str(e)}", query


# ============== STORED/SECOND-ORDER INJECTION ==============
def add_user_secure(name, email, password):
    """Insert user - using parameterized query (safe insert)"""
    db = get_db()
    cursor = db.cursor()
    # L'insertion est securisee, mais la valeur sera utilisee de maniere non securisee plus tard
    query = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)"
    cursor.execute(query, (name, email, password))
    db.commit()
    query_display = f"INSERT INTO users (name, email, password) VALUES ('{name}', '{email}', '{password}') (PARAMETREE)"
    return "Utilisateur cree avec succes", query_display


def search_user_by_name_unsafe(name):
    """VULNERABLE: Second-order injection - uses stored value unsafely"""
    db = get_db()
    cursor = db.cursor()
    # La valeur 'name' vient de la base et est utilisee sans echappement
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall(), query


def login_with_stored_name(username, password):
    """VULNERABLE: Second-order injection in login - uses stored username unsafely"""
    db = get_db()
    cursor = db.cursor()
    # Le username peut contenir du SQL malveillant stocke precedemment
    query = f"SELECT * FROM users WHERE name='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone(), query
