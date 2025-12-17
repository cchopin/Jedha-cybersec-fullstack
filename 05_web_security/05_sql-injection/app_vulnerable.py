from flask import Flask, request, render_template
from db_init import init_db
import vuln_connector as db

app = Flask(__name__)
MODE = 'VULNERABLE'

app.teardown_appcontext(db.close_db)

@app.route('/')
def index():
    return render_template('index.html', mode=MODE, stats=db.get_stats())

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    success = None
    query = None

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        try:
            user, query = db.login(username, password)

            if user:
                success = f"Bienvenue, {user[1]}! (ID: {user[0]}, Email: {user[2]})"
            else:
                error = "Identifiants invalides"
        except Exception as e:
            error = f"Erreur SQL: {str(e)}"

    return render_template('login.html', mode=MODE, error=error, success=success, query=query)

@app.route('/users')
def users():
    search_query = request.args.get('search', '')
    error = None
    users_list = []
    query = None

    try:
        if search_query:
            users_list, query = db.search_users(search_query)
        else:
            users_list, query = db.get_all_users()
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('users.html', mode=MODE, users=users_list,
                         search_query=search_query, query=query, error=error)

@app.route('/products')
def products():
    search_query = request.args.get('search', '')
    category_query = request.args.get('category', '')
    error = None
    products_list = []
    query = None

    try:
        products_list, query = db.search_products(
            search=search_query if search_query else None,
            category=category_query if category_query else None
        )
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('products.html', mode=MODE, products=products_list,
                         search_query=search_query, category_query=category_query,
                         query=query, error=error)

@app.route('/orders')
def orders():
    user_id = request.args.get('user_id', '')
    product_id = request.args.get('product_id', '')
    error = None
    orders_list = []
    query = None

    try:
        orders_list, query = db.search_orders(
            user_id=user_id if user_id else None,
            product_id=product_id if product_id else None
        )
    except Exception as e:
        error = f"Erreur SQL: {str(e)}"

    return render_template('orders.html', mode=MODE, orders=orders_list,
                         user_id=user_id, product_id=product_id,
                         query=query, error=error)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
