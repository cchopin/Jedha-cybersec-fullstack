#!/bin/bash
# =============================================================================
# StartupExcuses - Script de Creation d'Infrastructure 3-Tier
# Cree VPC, Subnets, Security Groups, RDS PostgreSQL et EC2
# =============================================================================

set -e

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
VPC_NAME="StartupExcusesVPC"
VPC_CIDR="10.0.0.0/16"
DB_IDENTIFIER="startupexcuses-db"
DB_NAME="startupexcuses"
DB_USER="postgres"
DB_PASSWORD="${DB_PASSWORD:-StartupExcuses2024!}"
KEY_PAIR_NAME="StartupExcusesKeyPair"

# Fichier pour stocker les IDs
SCRIPT_DIR="$(dirname "$0")"
OUTPUT_FILE="$SCRIPT_DIR/../resources-ids.txt"

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
print_header "StartupExcuses - Infrastructure 3-Tier"
echo "Region: $AWS_REGION"
echo "VPC: $VPC_NAME"
echo "Database: $DB_IDENTIFIER"
echo ""

# Initialiser le fichier de sortie
echo "# Ressources AWS creees le $(date)" > "$OUTPUT_FILE"
echo "AWS_REGION=$AWS_REGION" >> "$OUTPUT_FILE"
echo "DB_PASSWORD=$DB_PASSWORD" >> "$OUTPUT_FILE"

# =============================================================================
# PHASE 1: CREATION DU VPC
# =============================================================================
print_step "1/11" "Creation du VPC..."

VPC_ID=$(aws ec2 create-vpc \
    --region "$AWS_REGION" \
    --cidr-block "$VPC_CIDR" \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$VPC_NAME},{Key=Project,Value=StartupExcuses}]" \
    --query "Vpc.VpcId" \
    --output text)

aws ec2 modify-vpc-attribute \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --enable-dns-hostnames

aws ec2 modify-vpc-attribute \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --enable-dns-support

print_success "VPC cree: $VPC_ID"
save_resource_id "VPC_ID" "$VPC_ID"

# =============================================================================
# PHASE 2: CREATION DES SUBNETS
# =============================================================================
print_step "2/11" "Creation des subnets..."

# Public Subnet 1 (us-east-1a)
PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.1.0/24" \
    --availability-zone "${AWS_REGION}a" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Public-Subnet-1},{Key=Project,Value=StartupExcuses}]" \
    --query "Subnet.SubnetId" \
    --output text)

aws ec2 modify-subnet-attribute \
    --region "$AWS_REGION" \
    --subnet-id "$PUBLIC_SUBNET_1" \
    --map-public-ip-on-launch

print_success "Public-Subnet-1: $PUBLIC_SUBNET_1 (10.0.1.0/24 - ${AWS_REGION}a)"
save_resource_id "PUBLIC_SUBNET_1" "$PUBLIC_SUBNET_1"

# Public Subnet 2 (us-east-1b)
PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.2.0/24" \
    --availability-zone "${AWS_REGION}b" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Public-Subnet-2},{Key=Project,Value=StartupExcuses}]" \
    --query "Subnet.SubnetId" \
    --output text)

aws ec2 modify-subnet-attribute \
    --region "$AWS_REGION" \
    --subnet-id "$PUBLIC_SUBNET_2" \
    --map-public-ip-on-launch

print_success "Public-Subnet-2: $PUBLIC_SUBNET_2 (10.0.2.0/24 - ${AWS_REGION}b)"
save_resource_id "PUBLIC_SUBNET_2" "$PUBLIC_SUBNET_2"

# Private Subnet 1 (us-east-1a)
PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.3.0/24" \
    --availability-zone "${AWS_REGION}a" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Private-Subnet-1},{Key=Project,Value=StartupExcuses}]" \
    --query "Subnet.SubnetId" \
    --output text)

print_success "Private-Subnet-1: $PRIVATE_SUBNET_1 (10.0.3.0/24 - ${AWS_REGION}a)"
save_resource_id "PRIVATE_SUBNET_1" "$PRIVATE_SUBNET_1"

# Private Subnet 2 (us-east-1b)
PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --cidr-block "10.0.4.0/24" \
    --availability-zone "${AWS_REGION}b" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Private-Subnet-2},{Key=Project,Value=StartupExcuses}]" \
    --query "Subnet.SubnetId" \
    --output text)

print_success "Private-Subnet-2: $PRIVATE_SUBNET_2 (10.0.4.0/24 - ${AWS_REGION}b)"
save_resource_id "PRIVATE_SUBNET_2" "$PRIVATE_SUBNET_2"

# =============================================================================
# PHASE 3: CREATION DE L'INTERNET GATEWAY
# =============================================================================
print_step "3/11" "Creation de l'Internet Gateway..."

IGW_ID=$(aws ec2 create-internet-gateway \
    --region "$AWS_REGION" \
    --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=StartupExcuses-IGW},{Key=Project,Value=StartupExcuses}]" \
    --query "InternetGateway.InternetGatewayId" \
    --output text)

aws ec2 attach-internet-gateway \
    --region "$AWS_REGION" \
    --internet-gateway-id "$IGW_ID" \
    --vpc-id "$VPC_ID"

print_success "Internet Gateway: $IGW_ID"
save_resource_id "IGW_ID" "$IGW_ID"

# =============================================================================
# PHASE 4: CREATION DE LA ROUTE TABLE PUBLIQUE
# =============================================================================
print_step "4/11" "Creation de la Route Table publique..."

PUBLIC_RT=$(aws ec2 create-route-table \
    --region "$AWS_REGION" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=Public-Route-Table},{Key=Project,Value=StartupExcuses}]" \
    --query "RouteTable.RouteTableId" \
    --output text)

aws ec2 create-route \
    --region "$AWS_REGION" \
    --route-table-id "$PUBLIC_RT" \
    --destination-cidr-block "0.0.0.0/0" \
    --gateway-id "$IGW_ID" > /dev/null

aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PUBLIC_RT" \
    --subnet-id "$PUBLIC_SUBNET_1" > /dev/null

aws ec2 associate-route-table \
    --region "$AWS_REGION" \
    --route-table-id "$PUBLIC_RT" \
    --subnet-id "$PUBLIC_SUBNET_2" > /dev/null

print_success "Public Route Table: $PUBLIC_RT"
save_resource_id "PUBLIC_RT" "$PUBLIC_RT"

# =============================================================================
# PHASE 5: CREATION DES SECURITY GROUPS
# =============================================================================
print_step "5/11" "Creation des Security Groups..."

# Obtenir l'IP publique
MY_IP=$(curl -s https://checkip.amazonaws.com 2>/dev/null || echo "0.0.0.0")
print_info "Votre IP publique: $MY_IP"

# Web Server Security Group
WEB_SG=$(aws ec2 create-security-group \
    --region "$AWS_REGION" \
    --group-name "WebServerSecurityGroup" \
    --description "Security group for web servers" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=WebServerSecurityGroup},{Key=Project,Value=StartupExcuses}]" \
    --query "GroupId" \
    --output text)

# Regles entrantes Web SG
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

print_success "WebServerSecurityGroup: $WEB_SG"
save_resource_id "WEB_SG" "$WEB_SG"

# Database Security Group
DB_SG=$(aws ec2 create-security-group \
    --region "$AWS_REGION" \
    --group-name "DatabaseSecurityGroup" \
    --description "Security group for RDS database" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=DatabaseSecurityGroup},{Key=Project,Value=StartupExcuses}]" \
    --query "GroupId" \
    --output text)

# PostgreSQL depuis Web SG uniquement
aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$DB_SG" \
    --protocol tcp \
    --port 5432 \
    --source-group "$WEB_SG" > /dev/null

print_success "DatabaseSecurityGroup: $DB_SG"
save_resource_id "DB_SG" "$DB_SG"

# =============================================================================
# PHASE 6: CREATION DU DB SUBNET GROUP
# =============================================================================
print_step "6/11" "Creation du DB Subnet Group..."

aws rds create-db-subnet-group \
    --region "$AWS_REGION" \
    --db-subnet-group-name "startupexcuses-subnet-group" \
    --db-subnet-group-description "Subnet group for StartupExcuses RDS" \
    --subnet-ids "$PRIVATE_SUBNET_1" "$PRIVATE_SUBNET_2" \
    --tags Key=Name,Value=startupexcuses-subnet-group Key=Project,Value=StartupExcuses > /dev/null

print_success "DB Subnet Group: startupexcuses-subnet-group"
save_resource_id "DB_SUBNET_GROUP" "startupexcuses-subnet-group"

# =============================================================================
# PHASE 7: CREATION DE L'INSTANCE RDS
# =============================================================================
print_step "7/11" "Creation de l'instance RDS PostgreSQL (Free Tier)..."
print_info "Cette operation peut prendre 5-10 minutes..."

aws rds create-db-instance \
    --region "$AWS_REGION" \
    --db-instance-identifier "$DB_IDENTIFIER" \
    --db-instance-class "db.t3.micro" \
    --engine "postgres" \
    --engine-version "15" \
    --master-username "$DB_USER" \
    --master-user-password "$DB_PASSWORD" \
    --allocated-storage 20 \
    --db-subnet-group-name "startupexcuses-subnet-group" \
    --vpc-security-group-ids "$DB_SG" \
    --no-publicly-accessible \
    --backup-retention-period 0 \
    --no-multi-az \
    --storage-type "gp2" \
    --tags Key=Name,Value=$DB_IDENTIFIER Key=Project,Value=StartupExcuses > /dev/null

print_info "RDS en cours de creation..."
print_info "Attente de la disponibilite de RDS..."

aws rds wait db-instance-available \
    --region "$AWS_REGION" \
    --db-instance-identifier "$DB_IDENTIFIER"

# Recuperer l'endpoint RDS
RDS_ENDPOINT=$(aws rds describe-db-instances \
    --region "$AWS_REGION" \
    --db-instance-identifier "$DB_IDENTIFIER" \
    --query "DBInstances[0].Endpoint.Address" \
    --output text)

print_success "RDS disponible: $RDS_ENDPOINT"
save_resource_id "DB_IDENTIFIER" "$DB_IDENTIFIER"
save_resource_id "RDS_ENDPOINT" "$RDS_ENDPOINT"

# =============================================================================
# PHASE 8: CREATION DE LA KEY PAIR
# =============================================================================
print_step "8/11" "Creation de la Key Pair..."

KEY_FILE="$SCRIPT_DIR/../$KEY_PAIR_NAME.pem"

# Supprimer si existe deja
aws ec2 delete-key-pair \
    --region "$AWS_REGION" \
    --key-name "$KEY_PAIR_NAME" 2>/dev/null || true

aws ec2 create-key-pair \
    --region "$AWS_REGION" \
    --key-name "$KEY_PAIR_NAME" \
    --query "KeyMaterial" \
    --output text > "$KEY_FILE"

chmod 400 "$KEY_FILE"

print_success "Key Pair: $KEY_PAIR_NAME (sauvegardee dans $KEY_FILE)"
save_resource_id "KEY_PAIR_NAME" "$KEY_PAIR_NAME"

# =============================================================================
# PHASE 9: CREATION DU USER DATA SCRIPT
# =============================================================================
print_step "9/11" "Preparation du script User Data..."

USER_DATA=$(cat << 'USERDATA'
#!/bin/bash
set -e

# Logging
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting user-data script..."

# Update system
yum update -y

# Install dependencies
yum install -y python3 python3-pip git nginx

# Create app directory
mkdir -p /opt/startupexcuses
cd /opt/startupexcuses

# Create the Flask app
cat > app.py << 'EOF'
import os
import psycopg2
from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        database=os.getenv("DB_NAME", "postgres"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "password"),
        port=os.getenv("DB_PORT", "5432"),
    )

def init_db():
    try:
        print("Initializing database...")
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS excuses (
                        id SERIAL PRIMARY KEY,
                        excuse TEXT NOT NULL,
                        votes INTEGER DEFAULT 0,
                        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                # Insert sample data if table is empty
                cur.execute("SELECT COUNT(*) FROM excuses")
                if cur.fetchone()[0] == 0:
                    sample_excuses = [
                        "The code worked on my machine",
                        "I was mass editing with regex",
                        "The tests passed locally",
                        "Git ate my homework",
                        "It was a DNS issue"
                    ]
                    for excuse in sample_excuses:
                        cur.execute("INSERT INTO excuses (excuse) VALUES (%s)", (excuse,))
                print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise e

@app.route("/")
def home():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, excuse, votes FROM excuses ORDER BY votes DESC LIMIT 10")
            top_excuses = cur.fetchall()
    return render_template("index.html", excuses=top_excuses)

@app.route("/submit", methods=["POST"])
def submit_excuse():
    excuse = request.form["excuse"]
    if excuse.strip():
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO excuses (excuse) VALUES (%s)", (excuse,))
    return redirect(url_for("home"))

@app.route("/vote/<int:excuse_id>")
def vote(excuse_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE excuses SET votes = votes + 1 WHERE id = %s", (excuse_id,))
    return redirect(url_for("home"))

@app.route("/health")
def health():
    return {"status": "healthy", "app": "StartupExcuses"}, 200

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
EOF

# Create templates directory
mkdir -p templates

# Create index.html template
cat > templates/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>StartupExcuses - Best Developer Excuses</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        h1 { color: #333; text-align: center; }
        .excuse-card { background: white; border-radius: 8px; padding: 15px; margin: 10px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        .excuse-text { flex: 1; font-size: 16px; }
        .vote-btn { background: #4CAF50; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin-left: 10px; }
        .vote-btn:hover { background: #45a049; }
        .vote-count { background: #2196F3; color: white; padding: 5px 10px; border-radius: 15px; margin-left: 10px; }
        .submit-form { background: white; padding: 20px; border-radius: 8px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .submit-form input[type="text"] { width: 70%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .submit-form button { background: #ff9800; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        .submit-form button:hover { background: #f57c00; }
    </style>
</head>
<body>
    <h1>StartupExcuses</h1>
    <p style="text-align: center; color: #666;">The best excuses for missing deadlines!</p>

    <h2>Top Excuses</h2>
    {% for excuse in excuses %}
    <div class="excuse-card">
        <span class="excuse-text">{{ excuse[1] }}</span>
        <span class="vote-count">{{ excuse[2] }} votes</span>
        <a href="/vote/{{ excuse[0] }}"><button class="vote-btn">Vote</button></a>
    </div>
    {% endfor %}

    <div class="submit-form">
        <h3>Submit Your Excuse</h3>
        <form action="/submit" method="post">
            <input type="text" name="excuse" placeholder="Enter your best excuse..." required>
            <button type="submit">Submit</button>
        </form>
    </div>
</body>
</html>
EOF

# Install Python dependencies
pip3 install flask psycopg2-binary

# Create environment file (will be updated with actual values)
cat > /opt/startupexcuses/.env << 'ENVFILE'
DB_HOST=__RDS_ENDPOINT__
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=__DB_PASSWORD__
DB_PORT=5432
ENVFILE

# Create systemd service
cat > /etc/systemd/system/startupexcuses.service << 'EOF'
[Unit]
Description=StartupExcuses Flask App
After=network.target

[Service]
User=root
WorkingDirectory=/opt/startupexcuses
EnvironmentFile=/opt/startupexcuses/.env
ExecStart=/usr/bin/python3 /opt/startupexcuses/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
cat > /etc/nginx/conf.d/startupexcuses.conf << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Remove default nginx config
rm -f /etc/nginx/conf.d/default.conf 2>/dev/null || true

# Enable and start services
systemctl daemon-reload
systemctl enable nginx
systemctl start nginx
systemctl enable startupexcuses

echo "User-data script completed. App will start after .env is configured."
USERDATA
)

# Remplacer les placeholders
USER_DATA_FINAL=$(echo "$USER_DATA" | sed "s|__RDS_ENDPOINT__|$RDS_ENDPOINT|g" | sed "s|__DB_PASSWORD__|$DB_PASSWORD|g")

print_success "User Data prepare"

# =============================================================================
# PHASE 10: CREATION DE L'INSTANCE EC2
# =============================================================================
print_step "10/11" "Creation de l'instance EC2..."

# Obtenir l'AMI Amazon Linux 2023 la plus recente
AMI_ID=$(aws ec2 describe-images \
    --region "$AWS_REGION" \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-*-x86_64" "Name=state,Values=available" \
    --query "Images | sort_by(@, &CreationDate) | [-1].ImageId" \
    --output text)

print_info "AMI Amazon Linux 2023: $AMI_ID"

# Lancer l'instance EC2
INSTANCE_ID=$(aws ec2 run-instances \
    --region "$AWS_REGION" \
    --image-id "$AMI_ID" \
    --instance-type "t2.micro" \
    --key-name "$KEY_PAIR_NAME" \
    --subnet-id "$PUBLIC_SUBNET_1" \
    --security-group-ids "$WEB_SG" \
    --user-data "$USER_DATA_FINAL" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=StartupExcuses-WebServer},{Key=Project,Value=StartupExcuses}]" \
    --query "Instances[0].InstanceId" \
    --output text)

print_info "Instance EC2 en cours de demarrage: $INSTANCE_ID"
print_info "Attente du demarrage..."

aws ec2 wait instance-running \
    --region "$AWS_REGION" \
    --instance-ids "$INSTANCE_ID"

# Obtenir l'IP publique
EC2_PUBLIC_IP=$(aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$INSTANCE_ID" \
    --query "Reservations[0].Instances[0].PublicIpAddress" \
    --output text)

print_success "EC2 en cours d'execution: $INSTANCE_ID"
print_success "IP publique: $EC2_PUBLIC_IP"
save_resource_id "INSTANCE_ID" "$INSTANCE_ID"
save_resource_id "EC2_PUBLIC_IP" "$EC2_PUBLIC_IP"
save_resource_id "AMI_ID" "$AMI_ID"

# =============================================================================
# PHASE 11: DEMARRAGE DE L'APPLICATION
# =============================================================================
print_step "11/11" "Finalisation..."

print_info "L'application est en cours d'installation sur l'EC2..."
print_info "Cela peut prendre 2-3 minutes supplementaires."

# =============================================================================
# RESUME
# =============================================================================
print_header "Infrastructure 3-Tier Deployee!"

echo ""
echo "Ressources creees:"
echo ""
echo "  VPC:           $VPC_ID"
echo "  Subnets:"
echo "    - Public 1:  $PUBLIC_SUBNET_1 (10.0.1.0/24)"
echo "    - Public 2:  $PUBLIC_SUBNET_2 (10.0.2.0/24)"
echo "    - Private 1: $PRIVATE_SUBNET_1 (10.0.3.0/24)"
echo "    - Private 2: $PRIVATE_SUBNET_2 (10.0.4.0/24)"
echo ""
echo "  Internet Gateway: $IGW_ID"
echo ""
echo "  Security Groups:"
echo "    - Web Server:  $WEB_SG"
echo "    - Database:    $DB_SG"
echo ""
echo "  RDS PostgreSQL:"
echo "    - Identifier:  $DB_IDENTIFIER"
echo "    - Endpoint:    $RDS_ENDPOINT"
echo "    - User:        $DB_USER"
echo "    - Password:    $DB_PASSWORD"
echo ""
echo "  EC2 Instance:"
echo "    - Instance ID: $INSTANCE_ID"
echo "    - Public IP:   $EC2_PUBLIC_IP"
echo "    - Key Pair:    $KEY_PAIR_NAME"
echo ""
echo -e "${GREEN}Application URL: http://$EC2_PUBLIC_IP${NC}"
echo ""
echo "Connexion SSH:"
echo "  ssh -i $KEY_FILE ec2-user@$EC2_PUBLIC_IP"
echo ""
echo "Logs de deploiement sur l'EC2:"
echo "  sudo cat /var/log/user-data.log"
echo ""
echo "Demarrer l'application manuellement si necessaire:"
echo "  sudo systemctl start startupexcuses"
echo ""
echo -e "${YELLOW}Note: Attendez 2-3 minutes que l'application soit prete.${NC}"
echo ""
echo "Pour nettoyer:"
echo "  ./scripts/cleanup-3tier-infrastructure.sh"
