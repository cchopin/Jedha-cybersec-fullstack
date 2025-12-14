import logging
import os
from functools import wraps

import boto3
from botocore.exceptions import ClientError
from flask import Flask, jsonify, redirect, render_template, request, Response, g

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'creativeflow-secret-key-change-in-prod')

# Configuration
BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'creativeflow-docs')
AWS_REGION = os.environ.get('AWS_REGION', 'eu-west-3')

# Initialize S3 client (will use IAM role credentials)
s3_client = boto3.client('s3', region_name=AWS_REGION)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Authentication
# =============================================================================

USERS = {
    'developer': {
        'password': 'dev123',
        'role': 'developer'
    },
    'contributor': {
        'password': 'contrib123',
        'role': 'contributor'
    }
}

def check_auth(username, password):
    """Verify username and password"""
    if username in USERS and USERS[username]['password'] == password:
        return True
    return False

def get_user_role(username):
    """Get the role for a user"""
    if username in USERS:
        return USERS[username]['role']
    return None

def authenticate():
    """Send 401 response for authentication"""
    return Response(
        'Authentification requise.\n'
        'Utilisateurs: developer/dev123 ou contributor/contrib123',
        401,
        {'WWW-Authenticate': 'Basic realm="CreativeFlow"'}
    )

def requires_auth(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        g.username = auth.username
        g.user_role = get_user_role(auth.username)
        return f(*args, **kwargs)
    return decorated

def requires_developer(f):
    """Decorator for routes requiring developer role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        g.username = auth.username
        g.user_role = get_user_role(auth.username)
        if g.user_role != 'developer':
            return jsonify({
                'error': 'Acces refuse - Role developer requis',
                'access': 'denied'
            }), 403
        return f(*args, **kwargs)
    return decorated

# =============================================================================
# Routes
# =============================================================================

@app.route('/')
@requires_auth
def index():
    """Main page showing upload interface and file list"""
    try:
        files = list_uploaded_files()
        iam_role = get_current_iam_role()
        return render_template('index.html',
                             files=files,
                             role=iam_role,
                             username=g.username,
                             user_role=g.user_role)
    except Exception as e:
        logger.error(f"Error loading index: {str(e)}")
        return render_template('index.html',
                             files=[],
                             error=str(e),
                             username=g.username,
                             user_role=g.user_role)

@app.route('/upload', methods=['POST'])
@requires_auth
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier selectionne'}), 400

    file = request.files['file']
    category = request.form.get('category', 'drafts')

    if file.filename == '':
        return jsonify({'error': 'Aucun fichier selectionne'}), 400

    try:
        key = f"uploads/{category}/{file.filename}"
        s3_client.upload_fileobj(file, BUCKET_NAME, key)

        log_message = f"File uploaded: {key} by user: {g.username} (role: {g.user_role})"
        logger.info(log_message)

        return jsonify({
            'message': 'Fichier uploade avec succes',
            'file': file.filename,
            'category': category
        })
    except ClientError as e:
        error_msg = f"Echec de l'upload: {str(e)}"
        logger.error(error_msg)
        return jsonify({'error': error_msg}), 500

@app.route('/download/<path:filename>')
@requires_auth
def download_file(filename):
    """Generate presigned URL for file download"""
    try:
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET_NAME, 'Key': f"uploads/{filename}"},
            ExpiresIn=3600
        )
        logger.info(f"File downloaded: {filename} by user: {g.username}")
        return redirect(url)
    except ClientError as e:
        logger.error(f"Download failed: {str(e)}")
        return jsonify({'error': 'Echec du telechargement'}), 500

@app.route('/files')
@requires_auth
def list_files():
    """API endpoint to list files"""
    try:
        files = list_uploaded_files()
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logs')
@requires_developer
def view_logs():
    """View application logs (developers only)"""
    try:
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix='app-logs/'
        )

        logs = [obj['Key'] for obj in response.get('Contents', [])]
        return jsonify({'logs': logs, 'access': 'granted', 'user': g.username})

    except ClientError as e:
        if 'AccessDenied' in str(e):
            return jsonify({
                'error': 'Acces refuse - Role developer requis',
                'access': 'denied'
            }), 403
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint (no auth required)"""
    return jsonify({'status': 'healthy'})

# =============================================================================
# Helper functions
# =============================================================================

def list_uploaded_files():
    """List all files in uploads folder"""
    try:
        response = s3_client.list_objects_v2(
            Bucket=BUCKET_NAME,
            Prefix='uploads/'
        )

        files = []
        for obj in response.get('Contents', []):
            if not obj['Key'].endswith('/'):
                files.append({
                    'name': obj['Key'].split('/')[-1],
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat()
                })

        return files
    except ClientError as e:
        logger.error(f"Failed to list files: {str(e)}")
        return []

def get_current_iam_role():
    """Get current IAM role information"""
    try:
        sts_client = boto3.client('sts')
        identity = sts_client.get_caller_identity()
        return identity.get('Arn', 'Unknown')
    except:
        return 'Unknown'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
