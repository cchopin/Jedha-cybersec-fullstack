#!/bin/bash
# =============================================================================
# StartupExcuses - Script de Nettoyage
# Supprime toutes les ressources AWS creees
# =============================================================================

set -e

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
SCRIPT_DIR="$(dirname "$0")"
RESOURCE_FILE="$SCRIPT_DIR/../resources-ids.txt"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=============================================${NC}"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_step() {
    echo -e "\n${BLUE}[$1]${NC} $2"
}

# Charger les IDs
load_resource_ids() {
    if [ -f "$RESOURCE_FILE" ]; then
        source "$RESOURCE_FILE"
        print_success "IDs charges depuis $RESOURCE_FILE"
    else
        print_warning "Fichier $RESOURCE_FILE non trouve"
        print_info "Recherche des ressources par tags..."
        find_resources_by_tags
    fi
}

find_resources_by_tags() {
    VPC_ID=$(aws ec2 describe-vpcs \
        --region "$AWS_REGION" \
        --filters "Name=tag:Project,Values=StartupExcuses" \
        --query "Vpcs[0].VpcId" \
        --output text 2>/dev/null || echo "None")

    if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
        echo "Aucune ressource StartupExcuses trouvee dans $AWS_REGION"
        exit 0
    fi

    # Trouver l'instance EC2
    INSTANCE_ID=$(aws ec2 describe-instances \
        --region "$AWS_REGION" \
        --filters "Name=tag:Project,Values=StartupExcuses" "Name=instance-state-name,Values=running,pending,stopped" \
        --query "Reservations[0].Instances[0].InstanceId" \
        --output text 2>/dev/null || echo "None")
}

print_header "Nettoyage StartupExcuses"
echo "Region: $AWS_REGION"
echo ""
echo -e "${RED}ATTENTION: Ceci supprimera definitivement toutes les ressources!${NC}"
echo ""
read -p "Etes-vous sur de vouloir continuer ? (oui/non) : " CONFIRM

if [ "$CONFIRM" != "oui" ]; then
    echo "Nettoyage annule."
    exit 0
fi

load_resource_ids

# =============================================================================
# PHASE 1: TERMINER L'INSTANCE EC2
# =============================================================================
print_step "1/8" "Terminaison de l'instance EC2..."

if [ -n "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "None" ]; then
    aws ec2 terminate-instances \
        --region "$AWS_REGION" \
        --instance-ids "$INSTANCE_ID" > /dev/null 2>&1 || true

    print_info "Attente de la terminaison..."
    aws ec2 wait instance-terminated \
        --region "$AWS_REGION" \
        --instance-ids "$INSTANCE_ID" 2>/dev/null || true

    print_success "Instance EC2 terminee: $INSTANCE_ID"
else
    print_info "Pas d'instance EC2 a terminer"
fi

# =============================================================================
# PHASE 2: SUPPRIMER L'INSTANCE RDS
# =============================================================================
print_step "2/8" "Suppression de l'instance RDS..."

DB_IDENTIFIER="${DB_IDENTIFIER:-startupexcuses-db}"

if aws rds describe-db-instances \
    --region "$AWS_REGION" \
    --db-instance-identifier "$DB_IDENTIFIER" > /dev/null 2>&1; then

    aws rds delete-db-instance \
        --region "$AWS_REGION" \
        --db-instance-identifier "$DB_IDENTIFIER" \
        --skip-final-snapshot \
        --delete-automated-backups > /dev/null 2>&1

    print_info "RDS en cours de suppression (peut prendre 5-10 minutes)..."
    aws rds wait db-instance-deleted \
        --region "$AWS_REGION" \
        --db-instance-identifier "$DB_IDENTIFIER" 2>/dev/null || true

    print_success "Instance RDS supprimee: $DB_IDENTIFIER"
else
    print_info "Pas d'instance RDS a supprimer"
fi

# =============================================================================
# PHASE 3: SUPPRIMER LE DB SUBNET GROUP
# =============================================================================
print_step "3/8" "Suppression du DB Subnet Group..."

aws rds delete-db-subnet-group \
    --region "$AWS_REGION" \
    --db-subnet-group-name "startupexcuses-subnet-group" 2>/dev/null && \
    print_success "DB Subnet Group supprime" || \
    print_info "Pas de DB Subnet Group a supprimer"

# =============================================================================
# PHASE 4: SUPPRIMER LES SECURITY GROUPS
# =============================================================================
print_step "4/8" "Suppression des Security Groups..."

# Trouver les SGs par nom si pas dans le fichier
if [ -z "$WEB_SG" ] || [ "$WEB_SG" = "None" ]; then
    WEB_SG=$(aws ec2 describe-security-groups \
        --region "$AWS_REGION" \
        --filters "Name=group-name,Values=WebServerSecurityGroup" "Name=vpc-id,Values=$VPC_ID" \
        --query "SecurityGroups[0].GroupId" \
        --output text 2>/dev/null || echo "None")
fi

if [ -z "$DB_SG" ] || [ "$DB_SG" = "None" ]; then
    DB_SG=$(aws ec2 describe-security-groups \
        --region "$AWS_REGION" \
        --filters "Name=group-name,Values=DatabaseSecurityGroup" "Name=vpc-id,Values=$VPC_ID" \
        --query "SecurityGroups[0].GroupId" \
        --output text 2>/dev/null || echo "None")
fi

for SG_ID in "$DB_SG" "$WEB_SG"; do
    if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
        aws ec2 delete-security-group \
            --region "$AWS_REGION" \
            --group-id "$SG_ID" 2>/dev/null && \
            print_success "Security Group supprime: $SG_ID" || \
            print_warning "Impossible de supprimer SG: $SG_ID"
    fi
done

# =============================================================================
# PHASE 5: SUPPRIMER LA ROUTE TABLE
# =============================================================================
print_step "5/8" "Suppression des Route Tables..."

if [ -n "$PUBLIC_RT" ] && [ "$PUBLIC_RT" != "None" ]; then
    # Dissocier les subnets
    ASSOCS=$(aws ec2 describe-route-tables \
        --region "$AWS_REGION" \
        --route-table-ids "$PUBLIC_RT" \
        --query "RouteTables[0].Associations[?!Main].RouteTableAssociationId" \
        --output text 2>/dev/null)

    for ASSOC in $ASSOCS; do
        aws ec2 disassociate-route-table \
            --region "$AWS_REGION" \
            --association-id "$ASSOC" 2>/dev/null || true
    done

    aws ec2 delete-route-table \
        --region "$AWS_REGION" \
        --route-table-id "$PUBLIC_RT" 2>/dev/null && \
        print_success "Route Table supprimee: $PUBLIC_RT" || \
        print_warning "Impossible de supprimer RT"
else
    print_info "Pas de Route Table a supprimer"
fi

# =============================================================================
# PHASE 6: SUPPRIMER L'INTERNET GATEWAY
# =============================================================================
print_step "6/8" "Suppression de l'Internet Gateway..."

if [ -n "$IGW_ID" ] && [ "$IGW_ID" != "None" ]; then
    aws ec2 detach-internet-gateway \
        --region "$AWS_REGION" \
        --internet-gateway-id "$IGW_ID" \
        --vpc-id "$VPC_ID" 2>/dev/null || true

    aws ec2 delete-internet-gateway \
        --region "$AWS_REGION" \
        --internet-gateway-id "$IGW_ID" 2>/dev/null && \
        print_success "Internet Gateway supprime: $IGW_ID" || \
        print_warning "Impossible de supprimer IGW"
else
    print_info "Pas d'Internet Gateway a supprimer"
fi

# =============================================================================
# PHASE 7: SUPPRIMER LES SUBNETS ET LE VPC
# =============================================================================
print_step "7/8" "Suppression des Subnets..."

for SUBNET_ID in "$PUBLIC_SUBNET_1" "$PUBLIC_SUBNET_2" "$PRIVATE_SUBNET_1" "$PRIVATE_SUBNET_2"; do
    if [ -n "$SUBNET_ID" ] && [ "$SUBNET_ID" != "None" ]; then
        aws ec2 delete-subnet \
            --region "$AWS_REGION" \
            --subnet-id "$SUBNET_ID" 2>/dev/null && \
            print_success "Subnet supprime: $SUBNET_ID" || \
            print_warning "Impossible de supprimer Subnet: $SUBNET_ID"
    fi
done

print_step "8/8" "Suppression du VPC..."

if [ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
    aws ec2 delete-vpc \
        --region "$AWS_REGION" \
        --vpc-id "$VPC_ID" 2>/dev/null && \
        print_success "VPC supprime: $VPC_ID" || \
        print_warning "Impossible de supprimer VPC"
else
    print_info "Pas de VPC a supprimer"
fi

# Supprimer la key pair
KEY_PAIR_NAME="${KEY_PAIR_NAME:-StartupExcusesKeyPair}"
aws ec2 delete-key-pair \
    --region "$AWS_REGION" \
    --key-name "$KEY_PAIR_NAME" 2>/dev/null && \
    print_success "Key Pair supprimee: $KEY_PAIR_NAME" || \
    print_info "Pas de Key Pair a supprimer"

# Supprimer le fichier .pem local
KEY_FILE="$SCRIPT_DIR/../$KEY_PAIR_NAME.pem"
if [ -f "$KEY_FILE" ]; then
    rm -f "$KEY_FILE"
    print_info "Fichier $KEY_FILE supprime"
fi

# Supprimer le fichier de ressources
if [ -f "$RESOURCE_FILE" ]; then
    rm -f "$RESOURCE_FILE"
    print_info "Fichier $RESOURCE_FILE supprime"
fi

print_header "Nettoyage Termine!"
echo ""
echo "Toutes les ressources StartupExcuses ont ete supprimees."
echo ""
