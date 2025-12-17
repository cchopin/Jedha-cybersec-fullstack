#!/usr/bin/python3
import secrets
from datetime import datetime
import utils.db
from config import PERMANENT_SESSION_LIFETIME

def create_session_token(user_id):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + PERMANENT_SESSION_LIFETIME
    utils.db.execute_query("INSERT INTO sessions (fk_user_id, token, expires_at) VALUES (?, ?, ?)", (user_id, token, expires_at.isoformat()))
    return token

def validate_session_token(token):
    return utils.db.execute_query("SELECT id_session FROM sessions WHERE token = ? AND expires_at > ?", (token, datetime.now()))

def delete_session_token(token):
    utils.db.execute_query("DELETE FROM sessions WHERE token = ?", (token,))

def cleanup_expired_sessions():
    utils.db.execute_query("DELETE FROM sessions WHERE expires_at < ?", (datetime.now().isoformat(),))
