#!/bin/bash
# =============================================================================
# CreativeFlow - Script de Déploiement EC2
# Lance une instance EC2 avec l'application Flask
# =============================================================================

set -e  # Arrêter en cas d'erreur

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration - MODIFIER CES VALEURS
AWS_REGION="${AWS_REGION:-eu-west-3}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t2.micro}"
KEY_NAME="${KEY_NAME:-}"  # Nom de votre paire de clés SSH
S3_BUCKET_NAME="${S3_BUCKET_NAME:-}"
SECURITY_GROUP_ID="${SECURITY_GROUP_ID:-}"
IAM_ROLE="${IAM_ROLE:-CreativeFlow-Developer}"  # ou CreativeFlow-Contributor

echo "============================================="
echo "Déploiement EC2 CreativeFlow"
echo "============================================="

# Valider les paramètres requis
if [ -z "$KEY_NAME" ]; then
    echo "Erreur: KEY_NAME est requis"
    echo "Usage: KEY_NAME=votre-keypair S3_BUCKET_NAME=votre-bucket SECURITY_GROUP_ID=sg-xxx ./deploy-ec2.sh"
    exit 1
fi

if [ -z "$S3_BUCKET_NAME" ]; then
    echo "Erreur: S3_BUCKET_NAME est requis"
    exit 1
fi

if [ -z "$SECURITY_GROUP_ID" ]; then
    echo "Erreur: SECURITY_GROUP_ID est requis"
    exit 1
fi

echo "Région: $AWS_REGION"
echo "Type d'instance: $INSTANCE_TYPE"
echo "Paire de clés: $KEY_NAME"
echo "Bucket S3: $S3_BUCKET_NAME"
echo "Security Group: $SECURITY_GROUP_ID"
echo "Rôle IAM: $IAM_ROLE"
echo "============================================="

# Récupérer la dernière AMI Amazon Linux 2023
echo "[1/4] Recherche de la dernière AMI Amazon Linux 2023..."
AMI_ID=$(aws ec2 describe-images \
    --region "$AWS_REGION" \
    --owners amazon \
    --filters \
        "Name=name,Values=al2023-ami-2023*-x86_64" \
        "Name=state,Values=available" \
    --query "Images | sort_by(@, &CreationDate) | [-1].ImageId" \
    --output text)

if [ -z "$AMI_ID" ] || [ "$AMI_ID" = "None" ]; then
    echo "Essai avec Amazon Linux 2..."
    AMI_ID=$(aws ec2 describe-images \
        --region "$AWS_REGION" \
        --owners amazon \
        --filters \
            "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" \
            "Name=state,Values=available" \
        --query "Images | sort_by(@, &CreationDate) | [-1].ImageId" \
        --output text)
fi

echo "Utilisation de l'AMI: $AMI_ID"

# Préparer le script user-data
echo "[2/4] Préparation du script user-data..."
USER_DATA=$(cat "$SCRIPT_DIR/user-data.sh" | \
    sed "s|__S3_BUCKET_NAME__|$S3_BUCKET_NAME|g" | \
    sed "s|__AWS_REGION__|$AWS_REGION|g")

# Lancer l'instance EC2
echo "[3/4] Lancement de l'instance EC2..."
INSTANCE_ID=$(aws ec2 run-instances \
    --region "$AWS_REGION" \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SECURITY_GROUP_ID" \
    --iam-instance-profile Name="$IAM_ROLE" \
    --user-data "$USER_DATA" \
    --tag-specifications \
        "ResourceType=instance,Tags=[{Key=Name,Value=CreativeFlow-WebApp},{Key=Project,Value=CreativeFlow},{Key=Role,Value=$IAM_ROLE}]" \
    --query "Instances[0].InstanceId" \
    --output text)

echo "Instance lancée: $INSTANCE_ID"

# Attendre que l'instance soit en cours d'exécution
echo "[4/4] Attente du démarrage de l'instance..."
aws ec2 wait instance-running \
    --region "$AWS_REGION" \
    --instance-ids "$INSTANCE_ID"

# Récupérer l'IP publique
PUBLIC_IP=$(aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].PublicIpAddress" \
    --output text)

PUBLIC_DNS=$(aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].PublicDnsName" \
    --output text)

echo ""
echo "============================================="
echo "Instance EC2 Déployée !"
echo "============================================="
echo ""
echo "ID de l'instance: $INSTANCE_ID"
echo "IP Publique: $PUBLIC_IP"
echo "DNS Public: $PUBLIC_DNS"
echo "Rôle IAM: $IAM_ROLE"
echo ""
echo "Accéder à l'application:"
echo "  http://$PUBLIC_IP:5000"
echo ""
echo "Se connecter en SSH à l'instance:"
echo "  ssh -i ~/.ssh/$KEY_NAME.pem ec2-user@$PUBLIC_IP"
echo ""
echo "Note: L'application peut prendre 2-3 minutes à démarrer"
echo "après que l'instance soit en cours d'exécution."
echo ""
echo "============================================="
echo ""
echo "Pour déployer avec un rôle différent, exécuter:"
echo "  IAM_ROLE=CreativeFlow-Contributor ./deploy-ec2.sh"
echo ""
echo "Pour terminer cette instance:"
echo "  aws ec2 terminate-instances --instance-ids $INSTANCE_ID"
