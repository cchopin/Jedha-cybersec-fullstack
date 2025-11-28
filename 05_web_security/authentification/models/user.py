#!/usr/bin/python3
import sys
import os
import utils.db

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.routing import ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from config import PASSWORD_MIN_LENGTH, USERNAME_MIN_LENGTH

def create_user(username, password):
    if len(username) < USERNAME_MIN_LENGTH:
        raise ValidationError(f"Username must be at least {USERNAME_MIN_LENGTH} characters long")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValidationError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
    password_hash = generate_password_hash(password, method='scrypt', salt_length=16)
    if utils.db.execute_query(f"SELECT username FROM users WHERE username = ?", (username,)):
        raise ValidationError(f"Username '{username}' already exists")
    utils.db.execute_query(f"INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
    return utils.db.execute_query(f"SELECT id_user FROM users WHERE username = ?", (username,), fetch_one=True)

def get_user_by_username(username):
    return utils.db.execute_query(f"SELECT id_user, username, password_hash FROM users WHERE username = ?", (username,), fetch_one=True)

def get_user_by_id(id_user):
    return utils.db.execute_query(f"SELECT id_user, username, password_hash, created_at FROM users WHERE id_user = ?", (id_user,), fetch_one=True)

def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)

def get_all_users():
    return utils.db.execute_query(f"SELECT id_user, username, password_hash FROM users")
