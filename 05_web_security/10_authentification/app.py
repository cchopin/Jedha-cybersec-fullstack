#!/usr/bin/python3
from flask import Flask
from config import SECRET_KEY, SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE, PERMANENT_SESSION_LIFETIME
from routes.main import main_bp
from routes.auth import auth_bp
from utils.db import close_db_connection

app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_HTTPONLY'] = SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SAMESITE'] = SESSION_COOKIE_SAMESITE
app.config['PERMANENT_SESSION_LIFETIME'] = PERMANENT_SESSION_LIFETIME

app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)

app.teardown_appcontext(close_db_connection)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
