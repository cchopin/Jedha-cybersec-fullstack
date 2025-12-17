#!/usr/bin/python3

from flask import Blueprint, session, redirect, url_for, render_template
from functools import wraps
from models.user import get_user_by_id, get_all_users

main_bp = Blueprint('main', __name__)

def is_logged_in():
    return 'user_id' in session

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@main_bp.route('/')
def home():
    if is_logged_in():
        return redirect(url_for('main.dashboard'))
    return render_template('how_it_works.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    from flask import request, current_app
    user = get_user_by_id(session['user_id'])
    session_cookie = request.cookies.get('session', 'N/A')
    return render_template('dashboard.html', user=user, session_cookie=session_cookie, config=current_app.config)

@main_bp.route('/users')
@login_required
def users():
    all_users = get_all_users()
    total_users = len(all_users) if all_users else 0
    active_sessions = 1 if 'user_id' in session else 0
    return render_template('users.html', users=all_users, total_users=total_users, active_sessions=active_sessions)

@main_bp.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')
