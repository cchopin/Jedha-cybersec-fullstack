#!/bin/bash
# =============================================================================
# CreativeFlow - Script de Configuration du Bucket S3
# Crée le bucket S3 avec la structure et les configurations de sécurité appropriées
# =============================================================================

set -e  # Arrêter en cas d'erreur

# Configuration - MODIFIER CES VALEURS
BUCKET_NAME="${S3_BUCKET_NAME:-creativeflow-docs-$(date +%s)}"
AWS_REGION="${AWS_REGION:-eu-west-3}"

echo "============================================="
echo "Configuration du Bucket S3 CreativeFlow"
echo "============================================="
echo "Nom du Bucket: $BUCKET_NAME"
echo "Région: $AWS_REGION"
echo "============================================="

# Créer le bucket S3
echo "[1/5] Création du bucket S3..."
if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$AWS_REGION"
else
    aws s3api create-bucket \
        --bucket "$BUCKET_NAME" \
        --region "$AWS_REGION" \
        --create-bucket-configuration LocationConstraint="$AWS_REGION"
fi

echo "[2/5] Activation du versioning..."
aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled

echo "[3/5] Blocage de l'accès public..."
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "[4/5] Création de la structure des dossiers..."
# Créer les marqueurs de dossiers
aws s3api put-object --bucket "$BUCKET_NAME" --key "uploads/drafts/" --content-length 0
aws s3api put-object --bucket "$BUCKET_NAME" --key "uploads/final/" --content-length 0
aws s3api put-object --bucket "$BUCKET_NAME" --key "uploads/client-assets/" --content-length 0
aws s3api put-object --bucket "$BUCKET_NAME" --key "app-logs/" --content-length 0

echo "[5/5] Application de la politique du bucket..."
# Créer la politique du bucket
cat > /tmp/bucket-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EnforceSSLOnly",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::${BUCKET_NAME}",
                "arn:aws:s3:::${BUCKET_NAME}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
EOF

aws s3api put-bucket-policy \
    --bucket "$BUCKET_NAME" \
    --policy file:///tmp/bucket-policy.json

rm /tmp/bucket-policy.json

echo ""
echo "============================================="
echo "Configuration du Bucket S3 Terminée !"
echo "============================================="
echo "Bucket: $BUCKET_NAME"
echo "Région: $AWS_REGION"
echo ""
echo "Structure créée:"
echo "  - uploads/drafts/       (travaux en cours)"
echo "  - uploads/final/        (travaux terminés)"
echo "  - uploads/client-assets/(fichiers clients)"
echo "  - app-logs/             (logs applicatifs)"
echo ""
echo "Fonctionnalités de sécurité activées:"
echo "  - Versioning activé"
echo "  - Accès public bloqué"
echo "  - SSL/TLS imposé"
echo "============================================="
echo ""
echo "Exporter cette variable pour les autres scripts:"
echo "export S3_BUCKET_NAME=$BUCKET_NAME"
