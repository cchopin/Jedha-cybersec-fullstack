import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Initialiser l'extension
db = SQLAlchemy()

def create_app():
    # Créer l'application Flask
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = 'dev_key_todo_app_2025'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/todo_db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialiser les extensions
    db.init_app(app)
    
    # Importer les modèles
    from app.models import Todo
    # Enregistrer les blueprints
    from app.routes import main_bp
    app.register_blueprint(main_bp)
    
    # Créer les tables si elles n'existent pas
    with app.app_context():
        db.create_all()
    
    return app
