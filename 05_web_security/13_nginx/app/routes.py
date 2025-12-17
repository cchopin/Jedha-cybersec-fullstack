from flask import Blueprint, render_template, request, redirect, url_for, session, flash

# Create a Blueprint with /app prefix
bp = Blueprint('main', __name__, url_prefix='/app')

# Fake user database
USERS = {
    'admin': 'tavern2025',
    'merchant': 'crypto123'
}

# Crypto inventory
CRYPTO_INVENTORY = [
    {'name': 'Bitcoin', 'symbol': 'BTC', 'price': 45000, 'stock': 5},
    {'name': 'Ethereum', 'symbol': 'ETH', 'price': 3000, 'stock': 10},
    {'name': 'Cardano', 'symbol': 'ADA', 'price': 1.5, 'stock': 100},
    {'name': 'Solana', 'symbol': 'SOL', 'price': 100, 'stock': 25},
    {'name': 'Polkadot', 'symbol': 'DOT', 'price': 25, 'stock': 50},
]

@bp.route('/')
def index():
    return redirect(url_for('main.login'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in USERS and USERS[username] == password:
            session['username'] = username
            flash(f'Welcome to the Crypto Tavern, {username}!', 'success')
            return redirect(url_for('main.tavern'))
        else:
            flash('Invalid credentials. Try again!', 'error')

    return render_template('login.html')

@bp.route('/tavern')
def tavern():
    if 'username' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('main.login'))

    return render_template('tavern.html',
                         username=session['username'],
                         inventory=CRYPTO_INVENTORY)

@bp.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))
