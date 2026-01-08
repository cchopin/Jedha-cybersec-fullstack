#!/usr/bin/env python3
"""
============================================
SCRIPT DE DEMONSTRATION - Operations S3
============================================
Ce script montre les operations S3 de base avec Boto3 :
- Creer un bucket
- Uploader des fichiers
- Lister les fichiers
- Telecharger des fichiers
- Generer des URLs presignees
- Nettoyer

Usage:
    python3 demo_s3.py create
    python3 demo_s3.py upload
    python3 demo_s3.py list
    python3 demo_s3.py download
    python3 demo_s3.py url
    python3 demo_s3.py cleanup
============================================
"""

import boto3
import sys
import os
import json
from datetime import datetime
from botocore.exceptions import ClientError

# Configuration
REGION = 'eu-west-3'
# Generer un nom unique avec timestamp
BUCKET_NAME = f"demo-tutoriel-{datetime.now().strftime('%Y%m%d%H%M%S')}"
CONFIG_FILE = 's3_config.json'


def save_config(bucket_name):
    """Sauvegarde la configuration dans un fichier JSON."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump({'bucket_name': bucket_name, 'region': REGION}, f)
    print(f"Configuration sauvegardee dans {CONFIG_FILE}")


def load_config():
    """Charge la configuration depuis le fichier JSON."""
    if not os.path.exists(CONFIG_FILE):
        print(f"Erreur: {CONFIG_FILE} non trouve. Lancez d'abord 'create'.")
        sys.exit(1)
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)


def create_bucket():
    """Cree un bucket S3 avec les bonnes pratiques de securite."""
    print("=== CREATION DU BUCKET S3 ===\n")

    s3 = boto3.client('s3', region_name=REGION)

    # 1. Creer le bucket
    print(f"1. Creation du bucket: {BUCKET_NAME}")
    try:
        s3.create_bucket(
            Bucket=BUCKET_NAME,
            CreateBucketConfiguration={'LocationConstraint': REGION}
        )
        print(f"   Bucket cree avec succes!")
    except ClientError as e:
        print(f"   Erreur: {e}")
        return

    # 2. Activer le versioning
    print("\n2. Activation du versioning...")
    s3.put_bucket_versioning(
        Bucket=BUCKET_NAME,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    print("   Versioning active!")

    # 3. Bloquer l'acces public
    print("\n3. Blocage de l'acces public...")
    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    print("   Acces public bloque!")

    # 4. Ajouter des tags
    print("\n4. Ajout des tags...")
    s3.put_bucket_tagging(
        Bucket=BUCKET_NAME,
        Tagging={
            'TagSet': [
                {'Key': 'Project', 'Value': 'DemoTutoriel'},
                {'Key': 'Environment', 'Value': 'Development'}
            ]
        }
    )
    print("   Tags ajoutes!")

    # Sauvegarder la config
    save_config(BUCKET_NAME)

    print("\n=== BUCKET CREE AVEC SUCCES ===")
    print(f"\nBucket: {BUCKET_NAME}")
    print(f"Region: {REGION}")
    print("\nProchaines etapes:")
    print("  python3 demo_s3.py upload    # Uploader des fichiers")
    print("  python3 demo_s3.py list      # Lister les fichiers")
    print("  python3 demo_s3.py cleanup   # Supprimer le bucket")


def upload_files():
    """Upload des fichiers de demonstration."""
    config = load_config()
    bucket_name = config['bucket_name']

    print(f"=== UPLOAD DE FICHIERS VERS {bucket_name} ===\n")

    s3 = boto3.client('s3', region_name=REGION)

    # Creer des fichiers de test
    test_files = {
        'hello.txt': 'Hello, AWS S3!',
        'data/config.json': '{"setting": "value", "debug": true}',
        'data/notes.txt': 'Ceci est un fichier de notes.\nLigne 2.\nLigne 3.',
        'images/placeholder.txt': 'Placeholder pour une image'
    }

    for key, content in test_files.items():
        print(f"Upload: {key}")
        s3.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=content.encode('utf-8'),
            ContentType='text/plain'
        )

    print(f"\n{len(test_files)} fichiers uploades avec succes!")
    print("\nPour voir les fichiers: python3 demo_s3.py list")


def list_files():
    """Liste tous les fichiers du bucket."""
    config = load_config()
    bucket_name = config['bucket_name']

    print(f"=== CONTENU DU BUCKET {bucket_name} ===\n")

    s3 = boto3.client('s3', region_name=REGION)

    # Utiliser un paginator pour les gros buckets
    paginator = s3.get_paginator('list_objects_v2')

    total_size = 0
    file_count = 0

    for page in paginator.paginate(Bucket=bucket_name):
        if 'Contents' not in page:
            print("Le bucket est vide.")
            return

        for obj in page['Contents']:
            size = obj['Size']
            total_size += size
            file_count += 1

            # Formater la taille
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size/(1024*1024):.1f} MB"

            print(f"  {obj['Key']:<40} {size_str:>10}  {obj['LastModified']}")

    print(f"\nTotal: {file_count} fichiers, {total_size} bytes")


def download_files():
    """Telecharge les fichiers du bucket."""
    config = load_config()
    bucket_name = config['bucket_name']

    print(f"=== TELECHARGEMENT DEPUIS {bucket_name} ===\n")

    s3 = boto3.client('s3', region_name=REGION)

    # Creer un dossier local
    download_dir = 'downloaded_files'
    os.makedirs(download_dir, exist_ok=True)

    # Lister et telecharger
    response = s3.list_objects_v2(Bucket=bucket_name)

    if 'Contents' not in response:
        print("Aucun fichier a telecharger.")
        return

    for obj in response['Contents']:
        key = obj['Key']

        # Creer les sous-dossiers si necessaire
        local_path = os.path.join(download_dir, key)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        print(f"Telechargement: {key} -> {local_path}")

        # Lire le contenu
        response = s3.get_object(Bucket=bucket_name, Key=key)
        content = response['Body'].read()

        with open(local_path, 'wb') as f:
            f.write(content)

    print(f"\nFichiers telecharges dans: {download_dir}/")


def generate_presigned_url():
    """Genere une URL presignee pour un fichier."""
    config = load_config()
    bucket_name = config['bucket_name']

    print(f"=== GENERATION D'URL PRESIGNEE ===\n")

    s3 = boto3.client('s3', region_name=REGION)

    # Lister les fichiers disponibles
    response = s3.list_objects_v2(Bucket=bucket_name)

    if 'Contents' not in response:
        print("Aucun fichier dans le bucket.")
        return

    print("Fichiers disponibles:")
    for i, obj in enumerate(response['Contents']):
        print(f"  {i+1}. {obj['Key']}")

    # Utiliser le premier fichier pour la demo
    key = response['Contents'][0]['Key']

    print(f"\nGeneration d'une URL pour: {key}")

    url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket_name, 'Key': key},
        ExpiresIn=3600  # 1 heure
    )

    print(f"\nURL presignee (valide 1 heure):")
    print(f"  {url}")
    print("\nCette URL permet de telecharger le fichier sans credentials AWS.")


def cleanup():
    """Supprime le bucket et son contenu."""
    config = load_config()
    bucket_name = config['bucket_name']

    print(f"=== SUPPRESSION DU BUCKET {bucket_name} ===\n")

    s3 = boto3.client('s3', region_name=REGION)
    s3_resource = boto3.resource('s3', region_name=REGION)

    bucket = s3_resource.Bucket(bucket_name)

    # 1. Supprimer tous les objets (y compris les versions)
    print("1. Suppression de tous les objets...")
    try:
        bucket.object_versions.delete()
        print("   Objets et versions supprimes!")
    except Exception as e:
        print(f"   Note: {e}")

    # 2. Supprimer le bucket
    print("\n2. Suppression du bucket...")
    try:
        bucket.delete()
        print("   Bucket supprime!")
    except ClientError as e:
        print(f"   Erreur: {e}")
        return

    # 3. Supprimer le fichier de config
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)

    # 4. Supprimer le dossier downloaded_files s'il existe
    if os.path.exists('downloaded_files'):
        import shutil
        shutil.rmtree('downloaded_files')
        print("\n3. Dossier downloaded_files supprime")

    print("\n=== NETTOYAGE TERMINE ===")


def show_help():
    """Affiche l'aide."""
    print(__doc__)
    print("\nCommandes disponibles:")
    print("  create    - Creer un nouveau bucket S3")
    print("  upload    - Uploader des fichiers de test")
    print("  list      - Lister les fichiers du bucket")
    print("  download  - Telecharger les fichiers")
    print("  url       - Generer une URL presignee")
    print("  cleanup   - Supprimer le bucket et son contenu")
    print("  help      - Afficher cette aide")


def main():
    if len(sys.argv) < 2:
        show_help()
        return

    command = sys.argv[1].lower()

    commands = {
        'create': create_bucket,
        'upload': upload_files,
        'list': list_files,
        'download': download_files,
        'url': generate_presigned_url,
        'cleanup': cleanup,
        'clean': cleanup,
        'delete': cleanup,
        'help': show_help,
        '-h': show_help,
        '--help': show_help
    }

    if command in commands:
        commands[command]()
    else:
        print(f"Commande inconnue: {command}")
        show_help()


if __name__ == '__main__':
    main()
