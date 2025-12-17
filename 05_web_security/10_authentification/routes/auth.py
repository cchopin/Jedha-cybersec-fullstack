#!/usr/bin/python3
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.routing import ValidationError
from models.user import create_user, get_user_by_username, verify_password

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        password_confirm = request.form.get('password_confirm', '').strip()
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('register.html')
        if password != password_confirm:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        try:
            create_user(username, password)
            flash(f'Account created successfully for {username}!', 'success')
            return redirect(url_for('auth.login'))
        except ValidationError as e:
            flash(str(e), 'danger')
            return render_template('register.html')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return render_template('register.html')
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        user = get_user_by_username(username)
        if not user:
            flash('Invalid credentials', 'danger')
            return render_template('login.html')
        if verify_password(password, user['password_hash']):
            session['user_id'] = user['id_user']
            session['username'] = user['username']
            session.permanent = True
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('main.home'))
