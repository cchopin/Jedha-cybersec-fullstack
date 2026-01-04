#!/bin/bash
# =============================================================================
# AWS Network Security Services - Script de Creation d'Infrastructure VPC
# Cree une architecture trois tiers complete avec VPC, subnets, gateways,
# route tables, security groups et NACLs
# =============================================================================

set -e  # Arreter en cas d'erreur

# Configuration
AWS_REGION="${AWS_REGION:-eu-west-3}"
VPC_NAME="${VPC_NAME:-MyCustomVPC-Manual}"
VPC_CIDR="10.0.0.0/16"

# Fichier pour stocker les IDs des ressources creees
OUTPUT_FILE="$(dirname "$0")/../resources-ids.txt"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=============================================${NC}"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_step() {
    echo -e "\n${BLUE}[$1]${NC} $2"
}

save_resource_id() {
    echo "$1=$2" >> "$OUTPUT_FILE"
}

# =============================================================================
# PHASE 1: CREATION DU VPC
# =============================================================================
print_header "AWS Network Security Services - Infrastructure VPC"
echo "Region: $AWS_REGION"
echo "VPC Name: $VPC_NAME"
echo "VPC CIDR: $VPC_CIDR"

# Initialiser le fichier de sortie
echo "# Ressources AWS creees le $(date)" > "$OUTPUT_FILE"
echo "AWS_REGION=$AWS_REGION" >> "$OUTPUT_FILE"

print_step "1/12" "Creation du VPC..."

VPC_ID=$(aws ec2 create-vpc \
    --region "$AWS_REGION" \
    --cidr-block "$VPC_CIDR" \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$VPC_NAME},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "Vpc.VpcId" \
    --output text)

# Activer les DNS hostnames pour le VPC
aws ec2 modify-vpc-attribute \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --enable-dns-hostnames

print_success "VPC cree: $VPC_ID"
save_resource_id "VPC_ID" "$VPC_ID"

# =============================================================================
# PHASE 2: CREATION DES SUBNETS
# =============================================================================
print_step "2/12" "Creation des subnets publics..."

# Obtenir les AZs disponibles
AZ1=$(aws ec2 describe-availability-zones \
    --region "$AWS_REGION" \
    --query "AvailabilityZones[0].ZoneName" \
    --output text)

AZ2=$(aws ec2 describe-availability-zones \
    --region "$AWS_REGION" \
    --query "AvailabilityZones[1].ZoneName" \
    --output text)

print_info "Utilisation des AZs: $AZ1 et $AZ2"

# Public Subnet 1
PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.1.0/24" \
    --availability-zone "$AZ1" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Public-Subnet-AZ1},{Key=Project,Value=NetworkSecurityLab},{Key=Tier,Value=Public}]" \
    --query "Subnet.SubnetId" \
    --output text)

# Activer l'auto-assign public IP
aws ec2 modify-subnet-attribute \
    --region "$AWS_REGION" \
    --subnet-id "$PUBLIC_SUBNET_1" \
    --map-public-ip-on-launch

print_success "Public-Subnet-AZ1 cree: $PUBLIC_SUBNET_1 (10.0.1.0/24)"
save_resource_id "PUBLIC_SUBNET_1" "$PUBLIC_SUBNET_1"

# Public Subnet 2
PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.2.0/24" \
    --availability-zone "$AZ2" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Public-Subnet-AZ2},{Key=Project,Value=NetworkSecurityLab},{Key=Tier,Value=Public}]" \
    --query "Subnet.SubnetId" \
    --output text)

aws ec2 modify-subnet-attribute \
    --region "$AWS_REGION" \
    --subnet-id "$PUBLIC_SUBNET_2" \
    --map-public-ip-on-launch

print_success "Public-Subnet-AZ2 cree: $PUBLIC_SUBNET_2 (10.0.2.0/24)"
save_resource_id "PUBLIC_SUBNET_2" "$PUBLIC_SUBNET_2"

print_step "3/12" "Creation des subnets prives (App Tier)..."

# Private App Subnet 1
PRIVATE_APP_SUBNET_1=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.3.0/24" \
    --availability-zone "$AZ1" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Private-App-Subnet-AZ1},{Key=Project,Value=NetworkSecurityLab},{Key=Tier,Value=App}]" \
    --query "Subnet.SubnetId" \
    --output text)

print_success "Private-App-Subnet-AZ1 cree: $PRIVATE_APP_SUBNET_1 (10.0.3.0/24)"
save_resource_id "PRIVATE_APP_SUBNET_1" "$PRIVATE_APP_SUBNET_1"

# Private App Subnet 2
PRIVATE_APP_SUBNET_2=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.4.0/24" \
    --availability-zone "$AZ2" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Private-App-Subnet-AZ2},{Key=Project,Value=NetworkSecurityLab},{Key=Tier,Value=App}]" \
    --query "Subnet.SubnetId" \
    --output text)

print_success "Private-App-Subnet-AZ2 cree: $PRIVATE_APP_SUBNET_2 (10.0.4.0/24)"
save_resource_id "PRIVATE_APP_SUBNET_2" "$PRIVATE_APP_SUBNET_2"

print_step "4/12" "Creation des subnets prives (Database Tier)..."

# Private DB Subnet 1
PRIVATE_DB_SUBNET_1=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.5.0/24" \
    --availability-zone "$AZ1" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Private-DB-Subnet-AZ1},{Key=Project,Value=NetworkSecurityLab},{Key=Tier,Value=Database}]" \
    --query "Subnet.SubnetId" \
    --output text)

print_success "Private-DB-Subnet-AZ1 cree: $PRIVATE_DB_SUBNET_1 (10.0.5.0/24)"
save_resource_id "PRIVATE_DB_SUBNET_1" "$PRIVATE_DB_SUBNET_1"

# Private DB Subnet 2
PRIVATE_DB_SUBNET_2=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.6.0/24" \
    --availability-zone "$AZ2" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Private-DB-Subnet-AZ2},{Key=Project,Value=NetworkSecurityLab},{Key=Tier,Value=Database}]" \
    --query "Subnet.SubnetId" \
    --output text)

print_success "Private-DB-Subnet-AZ2 cree: $PRIVATE_DB_SUBNET_2 (10.0.6.0/24)"
save_resource_id "PRIVATE_DB_SUBNET_2" "$PRIVATE_DB_SUBNET_2"

# =============================================================================
# PHASE 3: CREATION DE L'INTERNET GATEWAY
# =============================================================================
print_step "5/12" "Creation de l'Internet Gateway..."

IGW_ID=$(aws ec2 create-internet-gateway \
    --region "$AWS_REGION" \
    --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=MyCustomVPC-IGW},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "InternetGateway.InternetGatewayId" \
    --output text)

# Attacher l'IGW au VPC
aws ec2 attach-internet-gateway \
    --region "$AWS_REGION" \
    --internet-gateway-id "$IGW_ID" \
    --vpc-id "$VPC_ID"

print_success "Internet Gateway cree et attache: $IGW_ID"
save_resource_id "IGW_ID" "$IGW_ID"

# =============================================================================
# PHASE 4: CREATION DU NAT GATEWAY
# =============================================================================
print_step "6/12" "Creation du NAT Gateway..."

# Allouer une Elastic IP
EIP_ALLOC=$(aws ec2 allocate-address \
    --region "$AWS_REGION" \
    --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=MyCustomVPC-NAT-EIP},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "AllocationId" \
    --output text)

print_info "Elastic IP allouee: $EIP_ALLOC"
save_resource_id "EIP_ALLOC" "$EIP_ALLOC"

# Creer le NAT Gateway dans le subnet public 1
NAT_GW_ID=$(aws ec2 create-nat-gateway \
    --region "$AWS_REGION" \
    --subnet-id "$PUBLIC_SUBNET_1" \
    --allocation-id "$EIP_ALLOC" \
    --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=MyCustomVPC-NAT},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "NatGateway.NatGatewayId" \
    --output text)

print_info "NAT Gateway en cours de creation: $NAT_GW_ID"
print_info "Attente de la disponibilite du NAT Gateway (cela peut prendre 1-2 minutes)..."

aws ec2 wait nat-gateway-available \
    --region "$AWS_REGION" \
    --nat-gateway-ids "$NAT_GW_ID"

print_success "NAT Gateway disponible: $NAT_GW_ID"
save_resource_id "NAT_GW_ID" "$NAT_GW_ID"

# =============================================================================
# PHASE 5: CREATION DES ROUTE TABLES
# =============================================================================
print_step "7/12" "Creation de la Route Table publique..."

# Public Route Table
PUBLIC_RT=$(aws ec2 create-route-table \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=Public-Route-Table},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "RouteTable.RouteTableId" \
    --output text)

# Ajouter la route vers Internet Gateway
aws ec2 create-route \
    --region "$AWS_REGION" \
    --route-table-id "$PUBLIC_RT" \
    --destination-cidr-block "0.0.0.0/0" \
    --gateway-id "$IGW_ID"

# Associer les subnets publics
aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PUBLIC_RT" \
    --subnet-id "$PUBLIC_SUBNET_1" > /dev/null

aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PUBLIC_RT" \
    --subnet-id "$PUBLIC_SUBNET_2" > /dev/null

print_success "Public Route Table creee: $PUBLIC_RT (route 0.0.0.0/0 -> IGW)"
save_resource_id "PUBLIC_RT" "$PUBLIC_RT"

print_step "8/12" "Creation de la Route Table privee (App Tier)..."

# Private App Route Table
PRIVATE_APP_RT=$(aws ec2 create-route-table \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=Private-App-Route-Table},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "RouteTable.RouteTableId" \
    --output text)

# Ajouter la route vers NAT Gateway
aws ec2 create-route \
    --region "$AWS_REGION" \
    --route-table-id "$PRIVATE_APP_RT" \
    --destination-cidr-block "0.0.0.0/0" \
    --nat-gateway-id "$NAT_GW_ID"

# Associer les subnets app
aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PRIVATE_APP_RT" \
    --subnet-id "$PRIVATE_APP_SUBNET_1" > /dev/null

aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PRIVATE_APP_RT" \
    --subnet-id "$PRIVATE_APP_SUBNET_2" > /dev/null

print_success "Private App Route Table creee: $PRIVATE_APP_RT (route 0.0.0.0/0 -> NAT)"
save_resource_id "PRIVATE_APP_RT" "$PRIVATE_APP_RT"

print_step "9/12" "Creation de la Route Table privee (Database Tier)..."

# Private DB Route Table (pas de route internet)
PRIVATE_DB_RT=$(aws ec2 create-route-table \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=Private-DB-Route-Table},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "RouteTable.RouteTableId" \
    --output text)

# Associer les subnets database
aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PRIVATE_DB_RT" \
    --subnet-id "$PRIVATE_DB_SUBNET_1" > /dev/null

aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PRIVATE_DB_RT" \
    --subnet-id "$PRIVATE_DB_SUBNET_2" > /dev/null

print_success "Private DB Route Table creee: $PRIVATE_DB_RT (local VPC uniquement)"
save_resource_id "PRIVATE_DB_RT" "$PRIVATE_DB_RT"

# =============================================================================
# PHASE 6: CREATION DES SECURITY GROUPS
# =============================================================================
print_step "10/12" "Creation des Security Groups..."

# Obtenir l'IP publique pour SSH
MY_IP=$(curl -s https://checkip.amazonaws.com 2>/dev/null || echo "0.0.0.0")
print_info "Votre IP publique: $MY_IP"

# Web Tier Security Group
WEB_SG=$(aws ec2 create-security-group \
    --region "$AWS_REGION" \
    --group-name "Web-Tier-SG" \
    --description "Security group for web servers in public subnets" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=Web-Tier-SG},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "GroupId" \
    --output text)

# Regles entrantes Web Tier
aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$WEB_SG" \
    --protocol tcp \
    --port 80 \
    --cidr "0.0.0.0/0" > /dev/null

aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$WEB_SG" \
    --protocol tcp \
    --port 443 \
    --cidr "0.0.0.0/0" > /dev/null

aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$WEB_SG" \
    --protocol tcp \
    --port 22 \
    --cidr "${MY_IP}/32" > /dev/null

print_success "Web-Tier-SG cree: $WEB_SG (HTTP/HTTPS: 0.0.0.0/0, SSH: $MY_IP)"
save_resource_id "WEB_SG" "$WEB_SG"

# App Tier Security Group
APP_SG=$(aws ec2 create-security-group \
    --region "$AWS_REGION" \
    --group-name "App-Tier-SG" \
    --description "Security group for application servers in private subnets" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=App-Tier-SG},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "GroupId" \
    --output text)

# Regles entrantes App Tier (depuis Web Tier uniquement)
aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$APP_SG" \
    --protocol tcp \
    --port 8080 \
    --source-group "$WEB_SG" > /dev/null

aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$APP_SG" \
    --protocol tcp \
    --port 22 \
    --source-group "$WEB_SG" > /dev/null

print_success "App-Tier-SG cree: $APP_SG (port 8080 et SSH depuis Web-Tier-SG)"
save_resource_id "APP_SG" "$APP_SG"

# Database Tier Security Group
DB_SG=$(aws ec2 create-security-group \
    --region "$AWS_REGION" \
    --group-name "Database-Tier-SG" \
    --description "Security group for database servers" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=Database-Tier-SG},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "GroupId" \
    --output text)

# Regles entrantes Database Tier (depuis App Tier uniquement)
aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$DB_SG" \
    --protocol tcp \
    --port 3306 \
    --source-group "$APP_SG" > /dev/null

print_success "Database-Tier-SG cree: $DB_SG (MySQL 3306 depuis App-Tier-SG)"
save_resource_id "DB_SG" "$DB_SG"

# =============================================================================
# PHASE 7: CREATION DES NETWORK ACLs
# =============================================================================
print_step "11/12" "Creation du Network ACL pour les subnets Database..."

# Database NACL
DB_NACL=$(aws ec2 create-network-acl \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=network-acl,Tags=[{Key=Name,Value=Database-NACL},{Key=Project,Value=NetworkSecurityLab}]" \
    --query "NetworkAcl.NetworkAclId" \
    --output text)

# Regles entrantes NACL (MySQL depuis subnets App: 10.0.3.0/24 et 10.0.4.0/24)
aws ec2 create-network-acl-entry \
    --region "$AWS_REGION" \
    --network-acl-id "$DB_NACL" \
    --rule-number 100 \
    --protocol tcp \
    --port-range From=3306,To=3306 \
    --cidr-block "10.0.3.0/24" \
    --rule-action allow \
    --ingress

aws ec2 create-network-acl-entry \
    --region "$AWS_REGION" \
    --network-acl-id "$DB_NACL" \
    --rule-number 110 \
    --protocol tcp \
    --port-range From=3306,To=3306 \
    --cidr-block "10.0.4.0/24" \
    --rule-action allow \
    --ingress

# Regles sortantes NACL (ports ephemeres pour le retour)
aws ec2 create-network-acl-entry \
    --region "$AWS_REGION" \
    --network-acl-id "$DB_NACL" \
    --rule-number 100 \
    --protocol tcp \
    --port-range From=1024,To=65535 \
    --cidr-block "10.0.3.0/24" \
    --rule-action allow \
    --egress

aws ec2 create-network-acl-entry \
    --region "$AWS_REGION" \
    --network-acl-id "$DB_NACL" \
    --rule-number 110 \
    --protocol tcp \
    --port-range From=1024,To=65535 \
    --cidr-block "10.0.4.0/24" \
    --rule-action allow \
    --egress

print_success "Database-NACL cree: $DB_NACL"
save_resource_id "DB_NACL" "$DB_NACL"

print_step "12/12" "Association du NACL aux subnets Database..."

# Obtenir les associations actuelles des subnets DB
OLD_ASSOC_1=$(aws ec2 describe-network-acls \
    --region "$AWS_REGION" \
    --filters "Name=association.subnet-id,Values=$PRIVATE_DB_SUBNET_1" \
    --query "NetworkAcls[0].Associations[?SubnetId=='$PRIVATE_DB_SUBNET_1'].NetworkAclAssociationId" \
    --output text)

OLD_ASSOC_2=$(aws ec2 describe-network-acls \
    --region "$AWS_REGION" \
    --filters "Name=association.subnet-id,Values=$PRIVATE_DB_SUBNET_2" \
    --query "NetworkAcls[0].Associations[?SubnetId=='$PRIVATE_DB_SUBNET_2'].NetworkAclAssociationId" \
    --output text)

# Remplacer les associations
aws ec2 replace-network-acl-association \
    --region "$AWS_REGION" \
    --association-id "$OLD_ASSOC_1" \
    --network-acl-id "$DB_NACL" > /dev/null

aws ec2 replace-network-acl-association \
    --region "$AWS_REGION" \
    --association-id "$OLD_ASSOC_2" \
    --network-acl-id "$DB_NACL" > /dev/null

print_success "NACL associe aux subnets Database"

# =============================================================================
# RESUME
# =============================================================================
print_header "Infrastructure VPC Creee avec Succes!"

echo ""
echo "Ressources creees:"
echo "  VPC:                  $VPC_ID"
echo ""
echo "  Subnets Publics:"
echo "    - Public-Subnet-AZ1:     $PUBLIC_SUBNET_1 (10.0.1.0/24)"
echo "    - Public-Subnet-AZ2:     $PUBLIC_SUBNET_2 (10.0.2.0/24)"
echo ""
echo "  Subnets Prives (App):"
echo "    - Private-App-Subnet-AZ1: $PRIVATE_APP_SUBNET_1 (10.0.3.0/24)"
echo "    - Private-App-Subnet-AZ2: $PRIVATE_APP_SUBNET_2 (10.0.4.0/24)"
echo ""
echo "  Subnets Prives (Database):"
echo "    - Private-DB-Subnet-AZ1:  $PRIVATE_DB_SUBNET_1 (10.0.5.0/24)"
echo "    - Private-DB-Subnet-AZ2:  $PRIVATE_DB_SUBNET_2 (10.0.6.0/24)"
echo ""
echo "  Gateways:"
echo "    - Internet Gateway:  $IGW_ID"
echo "    - NAT Gateway:       $NAT_GW_ID"
echo "    - Elastic IP:        $EIP_ALLOC"
echo ""
echo "  Route Tables:"
echo "    - Public:            $PUBLIC_RT"
echo "    - Private App:       $PRIVATE_APP_RT"
echo "    - Private DB:        $PRIVATE_DB_RT"
echo ""
echo "  Security Groups:"
echo "    - Web-Tier-SG:       $WEB_SG"
echo "    - App-Tier-SG:       $APP_SG"
echo "    - Database-Tier-SG:  $DB_SG"
echo ""
echo "  Network ACL:"
echo "    - Database-NACL:     $DB_NACL"
echo ""
echo -e "${GREEN}Les IDs des ressources ont ete sauvegardes dans: $OUTPUT_FILE${NC}"
echo ""
echo "Pour nettoyer l'infrastructure:"
echo "  ./scripts/cleanup-vpc-infrastructure.sh"
