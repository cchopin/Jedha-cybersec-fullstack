#!/bin/bash
# =============================================================================
# CreativeFlow - Script de Configuration du Security Group
# Crée le Security Group EC2 avec les règles entrantes/sortantes appropriées
# =============================================================================

set -e  # Arrêter en cas d'erreur

# Configuration
SG_NAME="${SG_NAME:-creativeflow-webapp-sg}"
AWS_REGION="${AWS_REGION:-eu-west-3}"
MY_IP="${MY_IP:-$(curl -s https://checkip.amazonaws.com)}"

echo "============================================="
echo "Configuration du Security Group CreativeFlow"
echo "============================================="
echo "Security Group: $SG_NAME"
echo "Région: $AWS_REGION"
echo "Votre IP: $MY_IP"
echo "============================================="

# Récupérer l'ID du VPC par défaut
echo "[1/4] Récupération du VPC par défaut..."
VPC_ID=$(aws ec2 describe-vpcs \
    --region "$AWS_REGION" \
    --filters "Name=isDefault,Values=true" \
    --query "Vpcs[0].VpcId" \
    --output text)

if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
    echo "Erreur: Aucun VPC par défaut trouvé. Veuillez en créer un ou spécifier un ID de VPC."
    exit 1
fi

echo "Utilisation du VPC: $VPC_ID"

# Vérifier si le security group existe déjà
echo "[2/4] Vérification du security group existant..."
EXISTING_SG=$(aws ec2 describe-security-groups \
    --region "$AWS_REGION" \
    --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query "SecurityGroups[0].GroupId" \
    --output text 2>/dev/null || echo "None")

if [ "$EXISTING_SG" != "None" ] && [ -n "$EXISTING_SG" ]; then
    echo "Le security group existe déjà: $EXISTING_SG"
    SG_ID=$EXISTING_SG
else
    # Créer le security group
    echo "[3/4] Création du security group..."
    SG_ID=$(aws ec2 create-security-group \
        --region "$AWS_REGION" \
        --group-name "$SG_NAME" \
        --description "Security group for CreativeFlow web application" \
        --vpc-id "$VPC_ID" \
        --query "GroupId" \
        --output text)

    echo "Security group créé: $SG_ID"
fi

# Configurer les règles entrantes
echo "[4/4] Configuration des règles de sécurité..."

# Fonction pour ajouter une règle si elle n'existe pas
add_ingress_rule() {
    local PROTOCOL=$1
    local PORT=$2
    local CIDR=$3
    local DESC=$4

    # Essayer d'ajouter la règle, ignorer si elle existe déjà
    aws ec2 authorize-security-group-ingress \
        --region "$AWS_REGION" \
        --group-id "$SG_ID" \
        --protocol "$PROTOCOL" \
        --port "$PORT" \
        --cidr "$CIDR" \
        --tag-specifications "ResourceType=security-group-rule,Tags=[{Key=Description,Value=\"$DESC\"}]" \
        2>/dev/null || echo "  Règle déjà existante: $DESC"
}

echo "Ajout des règles entrantes..."

# Accès SSH - restreint à votre IP uniquement
add_ingress_rule "tcp" "22" "${MY_IP}/32" "Accès SSH depuis IP admin"

# Accès HTTP - pour l'application web (port 5000 Flask)
add_ingress_rule "tcp" "5000" "0.0.0.0/0" "Accès application Flask"

# Accès HTTPS (si utilisation d'un reverse proxy)
add_ingress_rule "tcp" "443" "0.0.0.0/0" "Accès HTTPS"

# Accès HTTP (pour redirection vers HTTPS)
add_ingress_rule "tcp" "80" "0.0.0.0/0" "Accès HTTP"

# Ajouter les tags au security group
aws ec2 create-tags \
    --region "$AWS_REGION" \
    --resources "$SG_ID" \
    --tags Key=Name,Value="$SG_NAME" Key=Project,Value=CreativeFlow Key=Environment,Value=Production

echo ""
echo "============================================="
echo "Configuration du Security Group Terminée !"
echo "============================================="
echo ""
echo "Security Group ID: $SG_ID"
echo "Nom du Security Group: $SG_NAME"
echo ""
echo "Règles Entrantes:"
echo "  - SSH (22)    : ${MY_IP}/32 (admin uniquement)"
echo "  - Flask (5000): 0.0.0.0/0"
echo "  - HTTP (80)   : 0.0.0.0/0"
echo "  - HTTPS (443) : 0.0.0.0/0"
echo ""
echo "Règles Sortantes:"
echo "  - Tout le trafic : 0.0.0.0/0 (par défaut)"
echo ""
echo "============================================="
echo ""
echo "Exporter cette variable pour les autres scripts:"
echo "export SECURITY_GROUP_ID=$SG_ID"
