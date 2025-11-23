from flask import Flask, request, render_template, redirect, url_for
from db_init import init_db
import vuln_connector
import safe_connector
import time
import os
import glob

app = Flask(__name__)

app.teardown_appcontext(vuln_connector.close_db)

# ============== HOME ==============
@app.route('/')
def home():
    return render_template('home.html')

# ============== VULNERABLE ROUTES ==============
@app.route('/vulnerable')
@app.route('/vulnerable/')
def vuln_index():
    return render_template('index.html', mode='VULNERABLE', stats=vuln_connector.get_stats(), prefix='/vulnerable')

@app.route('/vulnerable/login', methods=['GET', 'POST'])
def vuln_login():
    error = None
    success = None
    query = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        try:
            user, query = vuln_connector.login(username, password)
            if user:
                success = f"Bienvenue, {user[1]}! (ID: {user[0]}, Email: {user[2]})"
            else:
                error = "Identifiants invalides"
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('login.html', mode='VULNERABLE', error=error, success=success, query=query, prefix='/vulnerable')

@app.route('/vulnerable/users')
def vuln_users():
    search_query = request.args.get('search', '')
    error = None
    users_list = []
    query = None

    try:
        if search_query:
            users_list, query = vuln_connector.search_users(search_query)
        else:
            users_list, query = vuln_connector.get_all_users()
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('users.html', mode='VULNERABLE', users=users_list,
                         search_query=search_query, query=query, error=error, prefix='/vulnerable')

@app.route('/vulnerable/products')
def vuln_products():
    search_query = request.args.get('search', '')
    category_query = request.args.get('category', '')
    error = None
    products_list = []
    query = None

    try:
        products_list, query = vuln_connector.search_products(
            search=search_query if search_query else None,
            category=category_query if category_query else None
        )
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('products.html', mode='VULNERABLE', products=products_list,
                         search_query=search_query, category_query=category_query,
                         query=query, error=error, prefix='/vulnerable')

@app.route('/vulnerable/orders')
def vuln_orders():
    user_id = request.args.get('user_id', '')
    product_id = request.args.get('product_id', '')
    error = None
    orders_list = []
    query = None

    try:
        orders_list, query = vuln_connector.search_orders(
            user_id=user_id if user_id else None,
            product_id=product_id if product_id else None
        )
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('orders.html', mode='VULNERABLE', orders=orders_list,
                         user_id=user_id, product_id=product_id,
                         query=query, error=error, prefix='/vulnerable')

@app.route('/vulnerable/blind')
def vuln_blind():
    username = request.args.get('username', '')
    result = None
    query = None
    error = None

    if username:
        try:
            result, query = vuln_connector.check_user_exists(username)
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('blind.html', mode='VULNERABLE', username=username,
                         result=result, query=query, error=error,
                         time_result=None, time_query=None, response_time=None,
                         user_id='', prefix='/vulnerable')

@app.route('/vulnerable/blind-time')
def vuln_blind_time():
    user_id = request.args.get('id', '')
    time_result = None
    time_query = None
    response_time = None
    error = None

    if user_id:
        try:
            start = time.time()
            time_result, time_query = vuln_connector.check_user_by_id(user_id)
            response_time = round(time.time() - start, 3)
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('blind.html', mode='VULNERABLE', username='',
                         result=None, query=None, error=error,
                         time_result=time_result, time_query=time_query,
                         response_time=response_time, user_id=user_id, prefix='/vulnerable')

@app.route('/vulnerable/outofband', methods=['GET', 'POST'])
def vuln_outofband():
    filepath = ''
    table_to_steal = ''
    result = None
    query = None
    error = None
    files = []

    if request.method == 'POST':
        filepath = request.form.get('filepath', '')
        table_to_steal = request.form.get('table', '')

        if filepath and table_to_steal:
            try:
                result, query = vuln_connector.attach_database_exploit(filepath, table_to_steal)
            except Exception as e:
                error = f"Erreur: {str(e)}"

    # List created files
    for f in glob.glob('/tmp/*.db'):
        files.append({'name': f, 'content': None})

    return render_template('outofband.html', mode='VULNERABLE', filepath=filepath,
                         table_to_steal=table_to_steal, result=result, query=query,
                         error=error, files=files, extract_result=None,
                         extract_query=None, table_name='', prefix='/vulnerable')

@app.route('/vulnerable/outofband-extract')
def vuln_outofband_extract():
    table_name = request.args.get('table', '')
    extract_result = None
    extract_query = None
    error = None
    files = []

    if table_name:
        try:
            extract_result, extract_query = vuln_connector.extract_table_to_file(table_name)
        except Exception as e:
            error = f"Erreur: {str(e)}"

    # List created files
    for f in glob.glob('/tmp/*.db'):
        files.append({'name': f, 'content': None})

    return render_template('outofband.html', mode='VULNERABLE', filename='',
                         file_content='', result=None, query=None,
                         error=error, files=files, extract_result=extract_result,
                         extract_query=extract_query, table_name=table_name, prefix='/vulnerable')

@app.route('/vulnerable/stored', methods=['GET', 'POST'])
def vuln_stored():
    name = ''
    email = ''
    password = ''
    insert_result = None
    insert_query = None
    error = None

    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        if name and email and password:
            try:
                insert_result, insert_query = vuln_connector.add_user_secure(name, email, password)
            except Exception as e:
                error = f"Erreur: {str(e)}"

    return render_template('stored.html', mode='VULNERABLE', name=name,
                         email=email, password=password, insert_result=insert_result,
                         insert_query=insert_query, error=error,
                         login_username='', login_result=None, login_success=False,
                         login_query=None, results=None,
                         prefix='/vulnerable')

@app.route('/vulnerable/stored-login', methods=['POST'])
def vuln_stored_login():
    login_username = request.form.get('username', '')
    login_password = request.form.get('password', '')
    login_result = None
    login_success = False
    login_query = None
    error = None

    if login_username:
        try:
            user, login_query = vuln_connector.login_with_stored_name(login_username, login_password)
            if user:
                login_success = True
                login_result = f"Connecte en tant que: {user[1]} (ID: {user[0]}, Email: {user[2]})"
            else:
                login_result = "Echec de connexion"
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('stored.html', mode='VULNERABLE', name='',
                         email='', password='', insert_result=None, insert_query=None,
                         error=error, login_username=login_username,
                         login_result=login_result, login_success=login_success,
                         login_query=login_query, results=None,
                         prefix='/vulnerable')

# ============== SECURE ROUTES ==============
@app.route('/secure')
@app.route('/secure/')
def safe_index():
    return render_template('index.html', mode='SECURE', stats=safe_connector.get_stats(), prefix='/secure')

@app.route('/secure/login', methods=['GET', 'POST'])
def safe_login():
    error = None
    success = None
    query = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        try:
            user, query = safe_connector.login(username, password)
            if user:
                success = f"Bienvenue, {user[1]}! (ID: {user[0]}, Email: {user[2]})"
            else:
                error = "Identifiants invalides"
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('login.html', mode='SECURE', error=error, success=success, query=query, prefix='/secure')

@app.route('/secure/users')
def safe_users():
    search_query = request.args.get('search', '')
    error = None
    users_list = []
    query = None

    try:
        if search_query:
            users_list, query = safe_connector.search_users(search_query)
        else:
            users_list, query = safe_connector.get_all_users()
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('users.html', mode='SECURE', users=users_list,
                         search_query=search_query, query=query, error=error, prefix='/secure')

@app.route('/secure/products')
def safe_products():
    search_query = request.args.get('search', '')
    category_query = request.args.get('category', '')
    error = None
    products_list = []
    query = None

    try:
        products_list, query = safe_connector.search_products(
            search=search_query if search_query else None,
            category=category_query if category_query else None
        )
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('products.html', mode='SECURE', products=products_list,
                         search_query=search_query, category_query=category_query,
                         query=query, error=error, prefix='/secure')

@app.route('/secure/orders')
def safe_orders():
    user_id = request.args.get('user_id', '')
    product_id = request.args.get('product_id', '')
    error = None
    orders_list = []
    query = None

    try:
        orders_list, query = safe_connector.search_orders(
            user_id=user_id if user_id else None,
            product_id=product_id if product_id else None
        )
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('orders.html', mode='SECURE', orders=orders_list,
                         user_id=user_id, product_id=product_id,
                         query=query, error=error, prefix='/secure')

@app.route('/secure/blind')
def safe_blind():
    username = request.args.get('username', '')
    result = None
    query = None
    error = None

    if username:
        try:
            result, query = safe_connector.check_user_exists(username)
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('blind.html', mode='SECURE', username=username,
                         result=result, query=query, error=error,
                         time_result=None, time_query=None, response_time=None,
                         user_id='', prefix='/secure')

@app.route('/secure/blind-time')
def safe_blind_time():
    user_id = request.args.get('id', '')
    time_result = None
    time_query = None
    response_time = None
    error = None

    if user_id:
        try:
            start = time.time()
            time_result, time_query = safe_connector.check_user_by_id(user_id)
            response_time = round(time.time() - start, 3)
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('blind.html', mode='SECURE', username='',
                         result=None, query=None, error=error,
                         time_result=time_result, time_query=time_query,
                         response_time=response_time, user_id=user_id, prefix='/secure')

@app.route('/secure/outofband', methods=['GET', 'POST'])
def safe_outofband():
    filepath = ''
    table_to_steal = ''
    result = None
    query = None
    error = None
    files = []

    if request.method == 'POST':
        filepath = request.form.get('filepath', '')
        table_to_steal = request.form.get('table', '')

        if filepath and table_to_steal:
            result, query = safe_connector.attach_database_exploit(filepath, table_to_steal)

    return render_template('outofband.html', mode='SECURE', filepath=filepath,
                         table_to_steal=table_to_steal, result=result, query=query,
                         error=error, files=files, extract_result=None,
                         extract_query=None, table_name='', prefix='/secure')

@app.route('/secure/outofband-extract')
def safe_outofband_extract():
    table_name = request.args.get('table', '')
    extract_result = None
    extract_query = None
    error = None
    files = []

    if table_name:
        extract_result, extract_query = safe_connector.extract_table_to_file(table_name)

    return render_template('outofband.html', mode='SECURE', filename='',
                         file_content='', result=None, query=None,
                         error=error, files=files, extract_result=extract_result,
                         extract_query=extract_query, table_name=table_name, prefix='/secure')

@app.route('/secure/stored', methods=['GET', 'POST'])
def safe_stored():
    name = ''
    email = ''
    password = ''
    insert_result = None
    insert_query = None
    error = None

    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        if name and email and password:
            try:
                insert_result, insert_query = safe_connector.add_user_secure(name, email, password)
            except Exception as e:
                error = f"Erreur: {str(e)}"

    return render_template('stored.html', mode='SECURE', name=name,
                         email=email, password=password, insert_result=insert_result,
                         insert_query=insert_query, error=error,
                         login_username='', login_result=None, login_success=False,
                         login_query=None, results=None,
                         prefix='/secure')

@app.route('/secure/stored-login', methods=['POST'])
def safe_stored_login():
    login_username = request.form.get('username', '')
    login_password = request.form.get('password', '')
    login_result = None
    login_success = False
    login_query = None
    error = None

    if login_username:
        try:
            user, login_query = safe_connector.login_with_stored_name(login_username, login_password)
            if user:
                login_success = True
                login_result = f"Connecte en tant que: {user[1]} (ID: {user[0]}, Email: {user[2]})"
            else:
                login_result = "Echec de connexion - requete parametree empeche l'injection"
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('stored.html', mode='SECURE', name='',
                         email='', password='', insert_result=None, insert_query=None,
                         error=error, login_username=login_username,
                         login_result=login_result, login_success=login_success,
                         login_query=login_query, results=None,
                         prefix='/secure')

if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("SQL Injection Demo")
    print("=" * 50)
    print("\nOuvrez http://localhost:5001 dans votre navigateur")
    print("\nRoutes disponibles:")
    print("  - /              : Page d'accueil")
    print("  - /vulnerable/*  : Site vulnerable")
    print("  - /secure/*      : Site securise")
    print("=" * 50)
    app.run(debug=True, port=5001)
