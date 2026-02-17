#!/bin/bash
# =============================================================================
# CreativeFlow - Script User Data EC2 (template Terraform)
# =============================================================================

set -e

S3_BUCKET_NAME="${s3_bucket_name}"
AWS_REGION="${aws_region}"

# [1/6] Mise a jour du systeme
yum update -y

# [2/6] Installation de Python et dependances
yum install -y python3 python3-pip git

# [3/6] Creation du repertoire de l'application
mkdir -p /opt/creativeflow/templates

# [4/6] Creation de l'application Flask
cat > /opt/creativeflow/app.py << 'APPEOF'
import logging
import os
from functools import wraps

import boto3
from botocore.exceptions import ClientError
from flask import Flask, jsonify, redirect, render_template, request, Response, g

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'creativeflow-secret-key-change-in-prod')

BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'creativeflow-docs')
AWS_REGION = os.environ.get('AWS_REGION', 'eu-west-3')

s3_client = boto3.client('s3', region_name=AWS_REGION)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    if username in USERS and USERS[username]['password'] == password:
        return True
    return False

def get_user_role(username):
    if username in USERS:
        return USERS[username]['role']
    return None

def authenticate():
    return Response(
        'Authentification requise.\n'
        'Utilisateurs: developer/dev123 ou contributor/contrib123',
        401,
        {'WWW-Authenticate': 'Basic realm="CreativeFlow"'}
    )

def requires_auth(f):
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

@app.route('/')
@requires_auth
def index():
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
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier selectionne'}), 400

    file = request.files['file']
    category = request.form.get('category', 'drafts')

    if file.filename == '':
        return jsonify({'error': 'Aucun fichier selectionne'}), 400

    try:
        key = f"uploads/{category}/{file.filename}"
        s3_client.upload_fileobj(file, BUCKET_NAME, key)
        logger.info(f"File uploaded: {key} by user: {g.username} (role: {g.user_role})")
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
    try:
        files = list_uploaded_files()
        return jsonify({'files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logs')
@requires_developer
def view_logs():
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
    return jsonify({'status': 'healthy'})

def list_uploaded_files():
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
    try:
        sts_client = boto3.client('sts')
        identity = sts_client.get_caller_identity()
        return identity.get('Arn', 'Unknown')
    except:
        return 'Unknown'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
APPEOF

# Creation du template HTML
cat > /opt/creativeflow/templates/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
  <head>
    <title>CreativeFlow - Portail Documentaire</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
      .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
      h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
      .upload-area { border: 2px dashed #007bff; padding: 20px; margin: 20px 0; border-radius: 8px; background: #f8f9fa; }
      .file-list { margin: 20px 0; }
      .file-item { padding: 12px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
      .file-item:hover { background: #f8f9fa; }
      .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 5px; margin: 10px 0; }
      .success { color: #155724; background: #d4edda; padding: 10px; border-radius: 5px; margin: 10px 0; }
      .info-box { padding: 15px; margin: 15px 0; border-radius: 5px; }
      .user-info { background: #d4edda; border-left: 4px solid #28a745; }
      .role-info { background: #e7f3ff; border-left: 4px solid #007bff; }
      button { padding: 10px 20px; margin: 5px; border: none; border-radius: 5px; cursor: pointer; }
      button[type="submit"] { background: #007bff; color: white; }
      button[type="submit"]:hover { background: #0056b3; }
      .btn-test { background: #6c757d; color: white; }
      .btn-test:hover { background: #545b62; }
      .btn-refresh { background: #28a745; color: white; }
      .btn-refresh:hover { background: #1e7e34; }
      select, input[type="file"] { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 5px; }
      a { color: #007bff; text-decoration: none; }
      a:hover { text-decoration: underline; }
      .test-buttons { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; }
      .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
      .badge-developer { background: #ffc107; color: #000; }
      .badge-contributor { background: #6c757d; color: #fff; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>CreativeFlow - Portail Documentaire</h1>

      <div class="info-box user-info">
        <strong>Utilisateur connecte :</strong> {{ username }}
        <span class="badge badge-{{ user_role }}">{{ user_role }}</span>
      </div>

      <div class="info-box role-info">
        <strong>Role IAM EC2 :</strong> {{ role }}
      </div>

      {% if error %}
      <div class="error">Erreur : {{ error }}</div>
      {% endif %}

      <div class="upload-area">
        <h3>Uploader un Document</h3>
        <form id="uploadForm" enctype="multipart/form-data">
          <input type="file" id="fileInput" name="file" required />
          <select name="category" id="category">
            <option value="drafts">Brouillons</option>
            <option value="final">Finaux</option>
            <option value="client-assets">Fichiers Clients</option>
          </select>
          <button type="submit">Uploader</button>
        </form>
        <div id="message"></div>
      </div>

      <div class="file-list">
        <h3>Fichiers uploades</h3>
        <div id="filesList">
          {% for file in files %}
          <div class="file-item">
            <span><strong>{{ file.name }}</strong> ({{ file.size }} octets)</span>
            <a href="/download/{{ file.key.replace('uploads/', '') }}">Telecharger</a>
          </div>
          {% endfor %}
          {% if not files %}
          <p>Aucun fichier uploade.</p>
          {% endif %}
        </div>
      </div>

      <div class="test-buttons">
        <h3>Tests de Controle d'Acces</h3>
        <p>
          <strong>Utilisateur actuel :</strong> {{ username }} ({{ user_role }})<br>
          <small>Les logs sont accessibles uniquement aux developers.</small>
        </p>
        <button class="btn-test" onclick="testLogAccess()">Tester Acces aux Logs</button>
        <button class="btn-refresh" onclick="refreshFiles()">Actualiser</button>
        <div id="testResults"></div>
      </div>
    </div>

    <script>
      document.getElementById("uploadForm").addEventListener("submit", async function (e) {
        e.preventDefault();
        const formData = new FormData();
        const fileInput = document.getElementById("fileInput");
        const category = document.getElementById("category").value;
        formData.append("file", fileInput.files[0]);
        formData.append("category", category);

        try {
          const response = await fetch("/upload", { method: "POST", body: formData });
          const result = await response.json();
          const messageDiv = document.getElementById("message");

          if (response.ok) {
            messageDiv.innerHTML = '<div class="success">' + result.message + '</div>';
            setTimeout(() => location.reload(), 1500);
          } else {
            messageDiv.innerHTML = '<div class="error">' + result.error + '</div>';
          }
        } catch (error) {
          document.getElementById("message").innerHTML = '<div class="error">Echec : ' + error + '</div>';
        }
      });

      async function testLogAccess() {
        try {
          const response = await fetch("/logs");
          const result = await response.json();
          const resultsDiv = document.getElementById("testResults");

          if (response.ok) {
            resultsDiv.innerHTML = '<div class="success">Acces aux logs accorde - Role developer confirme</div>';
          } else {
            resultsDiv.innerHTML = '<div class="error">Acces aux logs refuse - ' + result.error + '</div>';
          }
        } catch (error) {
          document.getElementById("testResults").innerHTML = '<div class="error">Echec du test : ' + error + '</div>';
        }
      }

      function refreshFiles() { location.reload(); }
    </script>
  </body>
</html>
HTMLEOF

# [5/6] Installation des paquets Python
cat > /opt/creativeflow/requirements.txt << 'REQEOF'
flask
boto3
gunicorn
REQEOF

pip3 install -r /opt/creativeflow/requirements.txt

# [6/6] Creation du service systemd
cat > /etc/systemd/system/creativeflow.service << SERVICEEOF
[Unit]
Description=Application Flask CreativeFlow
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/creativeflow
Environment="S3_BUCKET_NAME=$S3_BUCKET_NAME"
Environment="AWS_REGION=$AWS_REGION"
ExecStart=/usr/local/bin/gunicorn --bind 0.0.0.0:5000 --workers 2 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable creativeflow
systemctl start creativeflow

echo "============================================="
echo "Application CreativeFlow Deployee !"
echo "Bucket S3: $S3_BUCKET_NAME"
echo "Region: $AWS_REGION"
echo "============================================="
