#!/bin/bash
# ============================================
# SCRIPT DE DEMONSTRATION - Creation d'un VPC
# ============================================
# Ce script cree un VPC complet avec :
# - Un VPC
# - Un subnet public
# - Un Internet Gateway
# - Un Security Group
#
# Usage: ./demo_vpc.sh
# Cleanup: ./demo_vpc.sh cleanup
# ============================================

set -e  # Arreter en cas d'erreur

# Configuration
REGION="eu-west-3"
VPC_CIDR="10.0.0.0/16"
SUBNET_CIDR="10.0.1.0/24"
PROJECT_NAME="DemoTutoriel"

# Fichier pour sauvegarder les IDs
IDS_FILE="vpc_ids.txt"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction d'affichage
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================
# FONCTION DE NETTOYAGE
# ============================================
cleanup() {
    log_info "=== NETTOYAGE DES RESSOURCES ==="

    if [ ! -f "$IDS_FILE" ]; then
        log_error "Fichier $IDS_FILE non trouve. Rien a nettoyer."
        exit 1
    fi

    # Charger les IDs
    source "$IDS_FILE"

    # 1. Supprimer le Security Group
    if [ -n "$SG_ID" ]; then
        log_info "Suppression du Security Group $SG_ID..."
        aws ec2 delete-security-group --group-id "$SG_ID" --region "$REGION" 2>/dev/null || true
    fi

    # 2. Supprimer le subnet
    if [ -n "$SUBNET_ID" ]; then
        log_info "Suppression du Subnet $SUBNET_ID..."
        aws ec2 delete-subnet --subnet-id "$SUBNET_ID" --region "$REGION" 2>/dev/null || true
    fi

    # 3. Detacher et supprimer l'IGW
    if [ -n "$IGW_ID" ] && [ -n "$VPC_ID" ]; then
        log_info "Detachement de l'IGW $IGW_ID..."
        aws ec2 detach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" --region "$REGION" 2>/dev/null || true
        log_info "Suppression de l'IGW $IGW_ID..."
        aws ec2 delete-internet-gateway --internet-gateway-id "$IGW_ID" --region "$REGION" 2>/dev/null || true
    fi

    # 4. Supprimer le VPC
    if [ -n "$VPC_ID" ]; then
        log_info "Suppression du VPC $VPC_ID..."
        aws ec2 delete-vpc --vpc-id "$VPC_ID" --region "$REGION" 2>/dev/null || true
    fi

    # Supprimer le fichier d'IDs
    rm -f "$IDS_FILE"

    log_info "=== NETTOYAGE TERMINE ==="
}

# ============================================
# FONCTION DE CREATION
# ============================================
create() {
    log_info "=== CREATION DU VPC ==="
    log_info "Region: $REGION"
    log_info "VPC CIDR: $VPC_CIDR"
    log_info ""

    # 1. Creer le VPC
    log_info "1. Creation du VPC..."
    VPC_ID=$(aws ec2 create-vpc \
        --cidr-block "$VPC_CIDR" \
        --region "$REGION" \
        --query 'Vpc.VpcId' \
        --output text)

    aws ec2 create-tags \
        --resources "$VPC_ID" \
        --tags Key=Name,Value="$PROJECT_NAME-VPC" \
        --region "$REGION"

    log_info "   VPC cree: $VPC_ID"

    # Activer DNS hostnames
    aws ec2 modify-vpc-attribute \
        --vpc-id "$VPC_ID" \
        --enable-dns-hostnames '{"Value": true}' \
        --region "$REGION"

    aws ec2 modify-vpc-attribute \
        --vpc-id "$VPC_ID" \
        --enable-dns-support '{"Value": true}' \
        --region "$REGION"

    log_info "   DNS hostnames actives"

    # 2. Creer le subnet
    log_info "2. Creation du Subnet public..."
    SUBNET_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block "$SUBNET_CIDR" \
        --availability-zone "${REGION}a" \
        --region "$REGION" \
        --query 'Subnet.SubnetId' \
        --output text)

    aws ec2 create-tags \
        --resources "$SUBNET_ID" \
        --tags Key=Name,Value="$PROJECT_NAME-PublicSubnet" \
        --region "$REGION"

    # Activer l'auto-assign IP publique
    aws ec2 modify-subnet-attribute \
        --subnet-id "$SUBNET_ID" \
        --map-public-ip-on-launch \
        --region "$REGION"

    log_info "   Subnet cree: $SUBNET_ID"

    # 3. Creer l'Internet Gateway
    log_info "3. Creation de l'Internet Gateway..."
    IGW_ID=$(aws ec2 create-internet-gateway \
        --region "$REGION" \
        --query 'InternetGateway.InternetGatewayId' \
        --output text)

    aws ec2 create-tags \
        --resources "$IGW_ID" \
        --tags Key=Name,Value="$PROJECT_NAME-IGW" \
        --region "$REGION"

    log_info "   IGW cree: $IGW_ID"

    # Attacher l'IGW au VPC
    aws ec2 attach-internet-gateway \
        --internet-gateway-id "$IGW_ID" \
        --vpc-id "$VPC_ID" \
        --region "$REGION"

    log_info "   IGW attache au VPC"

    # 4. Configurer la route table
    log_info "4. Configuration de la Route Table..."
    RT_ID=$(aws ec2 describe-route-tables \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --region "$REGION" \
        --query 'RouteTables[0].RouteTableId' \
        --output text)

    aws ec2 create-route \
        --route-table-id "$RT_ID" \
        --destination-cidr-block 0.0.0.0/0 \
        --gateway-id "$IGW_ID" \
        --region "$REGION" > /dev/null

    log_info "   Route vers Internet ajoutee"

    # 5. Creer le Security Group
    log_info "5. Creation du Security Group..."
    SG_ID=$(aws ec2 create-security-group \
        --group-name "$PROJECT_NAME-SG" \
        --description "Security Group pour demo tutoriel" \
        --vpc-id "$VPC_ID" \
        --region "$REGION" \
        --query 'GroupId' \
        --output text)

    aws ec2 create-tags \
        --resources "$SG_ID" \
        --tags Key=Name,Value="$PROJECT_NAME-SG" \
        --region "$REGION"

    # Ajouter regles SSH et HTTP
    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0 \
        --region "$REGION" > /dev/null

    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 80 \
        --cidr 0.0.0.0/0 \
        --region "$REGION" > /dev/null

    log_info "   Security Group cree: $SG_ID"
    log_info "   Regles: SSH (22) et HTTP (80) ouvertes"

    # Sauvegarder les IDs
    cat > "$IDS_FILE" << EOF
VPC_ID="$VPC_ID"
SUBNET_ID="$SUBNET_ID"
IGW_ID="$IGW_ID"
SG_ID="$SG_ID"
RT_ID="$RT_ID"
REGION="$REGION"
EOF

    log_info ""
    log_info "=== VPC CREE AVEC SUCCES ==="
    log_info ""
    log_info "Ressources creees:"
    log_info "  - VPC:     $VPC_ID"
    log_info "  - Subnet:  $SUBNET_ID"
    log_info "  - IGW:     $IGW_ID"
    log_info "  - SG:      $SG_ID"
    log_info ""
    log_info "IDs sauvegardes dans: $IDS_FILE"
    log_info ""
    log_info "Pour nettoyer: $0 cleanup"
}

# ============================================
# MAIN
# ============================================
case "${1:-create}" in
    cleanup|clean|delete)
        cleanup
        ;;
    create|*)
        create
        ;;
esac
