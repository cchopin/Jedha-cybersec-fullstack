#!/bin/bash
# =============================================================================
# AWS Network Security Services - Script de Nettoyage
# Supprime toutes les ressources VPC creees par setup-vpc-infrastructure.sh
# =============================================================================

set -e

# Configuration
AWS_REGION="${AWS_REGION:-eu-west-3}"
RESOURCE_FILE="$(dirname "$0")/../resources-ids.txt"

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

# Charger les IDs depuis le fichier
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

# Trouver les ressources par tags si le fichier n'existe pas
find_resources_by_tags() {
    VPC_ID=$(aws ec2 describe-vpcs \
        --region "$AWS_REGION" \
        --filters "Name=tag:Project,Values=NetworkSecurityLab" \
        --query "Vpcs[0].VpcId" \
        --output text 2>/dev/null || echo "None")

    if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
        echo "Aucune ressource NetworkSecurityLab trouvee dans la region $AWS_REGION"
        exit 0
    fi
}

print_header "Nettoyage de l'Infrastructure VPC"
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
# PHASE 1: SUPPRESSION DES NACL PERSONNALISES
# =============================================================================
print_step "1/8" "Suppression des Network ACLs personnalises..."

if [ -n "$DB_NACL" ] && [ "$DB_NACL" != "None" ]; then
    # D'abord, reassocier les subnets au NACL par defaut
    DEFAULT_NACL=$(aws ec2 describe-network-acls \
        --region "$AWS_REGION" \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=default,Values=true" \
        --query "NetworkAcls[0].NetworkAclId" \
        --output text 2>/dev/null)

    if [ -n "$DEFAULT_NACL" ]; then
        # Obtenir les associations du NACL personnalise
        ASSOCS=$(aws ec2 describe-network-acls \
            --region "$AWS_REGION" \
            --network-acl-ids "$DB_NACL" \
            --query "NetworkAcls[0].Associations[].NetworkAclAssociationId" \
            --output text 2>/dev/null)

        for ASSOC in $ASSOCS; do
            aws ec2 replace-network-acl-association \
                --region "$AWS_REGION" \
                --association-id "$ASSOC" \
                --network-acl-id "$DEFAULT_NACL" 2>/dev/null || true
        done
    fi

    aws ec2 delete-network-acl \
        --region "$AWS_REGION" \
        --network-acl-id "$DB_NACL" 2>/dev/null && \
        print_success "Database-NACL supprime: $DB_NACL" || \
        print_warning "Impossible de supprimer Database-NACL"
else
    print_info "Pas de NACL personnalise a supprimer"
fi

# =============================================================================
# PHASE 2: SUPPRESSION DES SECURITY GROUPS
# =============================================================================
print_step "2/8" "Suppression des Security Groups..."

# Supprimer dans l'ordre inverse des dependances
for SG_ID in "$DB_SG" "$APP_SG" "$WEB_SG"; do
    if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
        aws ec2 delete-security-group \
            --region "$AWS_REGION" \
            --group-id "$SG_ID" 2>/dev/null && \
            print_success "Security Group supprime: $SG_ID" || \
            print_warning "Impossible de supprimer SG: $SG_ID"
    fi
done

# =============================================================================
# PHASE 3: SUPPRESSION DU NAT GATEWAY
# =============================================================================
print_step "3/8" "Suppression du NAT Gateway..."

if [ -n "$NAT_GW_ID" ] && [ "$NAT_GW_ID" != "None" ]; then
    aws ec2 delete-nat-gateway \
        --region "$AWS_REGION" \
        --nat-gateway-id "$NAT_GW_ID" 2>/dev/null

    print_info "NAT Gateway en cours de suppression: $NAT_GW_ID"
    print_info "Attente de la suppression (peut prendre 1-2 minutes)..."

    aws ec2 wait nat-gateway-deleted \
        --region "$AWS_REGION" \
        --nat-gateway-ids "$NAT_GW_ID" 2>/dev/null || true

    print_success "NAT Gateway supprime"
else
    print_info "Pas de NAT Gateway a supprimer"
fi

# =============================================================================
# PHASE 4: SUPPRESSION DES ROUTE TABLES
# =============================================================================
print_step "4/8" "Suppression des Route Tables..."

for RT_ID in "$PUBLIC_RT" "$PRIVATE_APP_RT" "$PRIVATE_DB_RT"; do
    if [ -n "$RT_ID" ] && [ "$RT_ID" != "None" ]; then
        # D'abord supprimer les associations
        ASSOCS=$(aws ec2 describe-route-tables \
            --region "$AWS_REGION" \
            --route-table-ids "$RT_ID" \
            --query "RouteTables[0].Associations[?!Main].RouteTableAssociationId" \
            --output text 2>/dev/null)

        for ASSOC in $ASSOCS; do
            aws ec2 disassociate-route-table \
                --region "$AWS_REGION" \
                --association-id "$ASSOC" 2>/dev/null || true
        done

        aws ec2 delete-route-table \
            --region "$AWS_REGION" \
            --route-table-id "$RT_ID" 2>/dev/null && \
            print_success "Route Table supprimee: $RT_ID" || \
            print_warning "Impossible de supprimer RT: $RT_ID"
    fi
done

# =============================================================================
# PHASE 5: DETACHEMENT ET SUPPRESSION DE L'INTERNET GATEWAY
# =============================================================================
print_step "5/8" "Suppression de l'Internet Gateway..."

if [ -n "$IGW_ID" ] && [ "$IGW_ID" != "None" ]; then
    # Detacher d'abord
    aws ec2 detach-internet-gateway \
        --region "$AWS_REGION" \
        --internet-gateway-id "$IGW_ID" \
        --vpc-id "$VPC_ID" 2>/dev/null || true

    # Puis supprimer
    aws ec2 delete-internet-gateway \
        --region "$AWS_REGION" \
        --internet-gateway-id "$IGW_ID" 2>/dev/null && \
        print_success "Internet Gateway supprime: $IGW_ID" || \
        print_warning "Impossible de supprimer IGW"
else
    print_info "Pas d'Internet Gateway a supprimer"
fi

# =============================================================================
# PHASE 6: SUPPRESSION DES SUBNETS
# =============================================================================
print_step "6/8" "Suppression des Subnets..."

for SUBNET_ID in "$PUBLIC_SUBNET_1" "$PUBLIC_SUBNET_2" "$PRIVATE_APP_SUBNET_1" "$PRIVATE_APP_SUBNET_2" "$PRIVATE_DB_SUBNET_1" "$PRIVATE_DB_SUBNET_2"; do
    if [ -n "$SUBNET_ID" ] && [ "$SUBNET_ID" != "None" ]; then
        aws ec2 delete-subnet \
            --region "$AWS_REGION" \
            --subnet-id "$SUBNET_ID" 2>/dev/null && \
            print_success "Subnet supprime: $SUBNET_ID" || \
            print_warning "Impossible de supprimer Subnet: $SUBNET_ID"
    fi
done

# =============================================================================
# PHASE 7: LIBERATION DE L'ELASTIC IP
# =============================================================================
print_step "7/8" "Liberation de l'Elastic IP..."

if [ -n "$EIP_ALLOC" ] && [ "$EIP_ALLOC" != "None" ]; then
    aws ec2 release-address \
        --region "$AWS_REGION" \
        --allocation-id "$EIP_ALLOC" 2>/dev/null && \
        print_success "Elastic IP liberee: $EIP_ALLOC" || \
        print_warning "Impossible de liberer l'Elastic IP"
else
    print_info "Pas d'Elastic IP a liberer"
fi

# =============================================================================
# PHASE 8: SUPPRESSION DU VPC
# =============================================================================
print_step "8/8" "Suppression du VPC..."

if [ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
    aws ec2 delete-vpc \
        --region "$AWS_REGION" \
        --vpc-id "$VPC_ID" 2>/dev/null && \
        print_success "VPC supprime: $VPC_ID" || \
        print_warning "Impossible de supprimer le VPC (verifiez les ressources restantes)"
else
    print_info "Pas de VPC a supprimer"
fi

# Supprimer le fichier de ressources
if [ -f "$RESOURCE_FILE" ]; then
    rm "$RESOURCE_FILE"
    print_info "Fichier $RESOURCE_FILE supprime"
fi

print_header "Nettoyage Termine!"
echo ""
echo "Toutes les ressources ont ete supprimees."
echo ""
