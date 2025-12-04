from flask import Flask, render_template
import os

app = Flask(__name__, static_url_path='/app/static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['APPLICATION_ROOT'] = os.environ.get('APPLICATION_ROOT', '/app')

from app.routes import bp
app.register_blueprint(bp)

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html',
                         error_code=404,
                         error_message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html',
                         error_code=500,
                         error_message='Internal server error'), 500
