# Commandes AWS CLI Pas à Pas

Ce guide montre les commandes AWS CLI les plus courantes, étape par étape.

---

## Structure des commandes

```bash
aws <service> <action> [--options]
```

Exemples :
```bash
aws ec2 describe-instances
aws s3 ls
aws iam list-users
```

---

## 1. VPC - Créer un réseau

### Étape 1.1 : Créer le VPC

```bash
# Créer un VPC avec le bloc CIDR 10.0.0.0/16
aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=MonVPC}]'
```

**Résultat** :
```json
{
    "Vpc": {
        "VpcId": "vpc-0123456789abcdef0",
        "CidrBlock": "10.0.0.0/16",
        "State": "available"
    }
}
```

**Sauvegarder l'ID** :
```bash
VPC_ID="vpc-0123456789abcdef0"
```

### Étape 1.2 : Activer les DNS

```bash
# Activer les hostnames DNS
aws ec2 modify-vpc-attribute \
    --vpc-id $VPC_ID \
    --enable-dns-hostnames '{"Value": true}'

# Activer la résolution DNS
aws ec2 modify-vpc-attribute \
    --vpc-id $VPC_ID \
    --enable-dns-support '{"Value": true}'
```

### Étape 1.3 : Créer un subnet public

```bash
aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.1.0/24 \
    --availability-zone eu-west-3a \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=PublicSubnet}]'
```

**Sauvegarder** :
```bash
PUBLIC_SUBNET_ID="subnet-0123456789abcdef0"
```

### Étape 1.4 : Créer un subnet privé

```bash
aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.2.0/24 \
    --availability-zone eu-west-3a \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=PrivateSubnet}]'
```

### Étape 1.5 : Créer l'Internet Gateway

```bash
# Créer l'IGW
aws ec2 create-internet-gateway \
    --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=MonIGW}]'

# Attacher au VPC
IGW_ID="igw-0123456789abcdef0"
aws ec2 attach-internet-gateway \
    --internet-gateway-id $IGW_ID \
    --vpc-id $VPC_ID
```

### Étape 1.6 : Configurer la route table

```bash
# Récupérer la route table par défaut
ROUTE_TABLE_ID=$(aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query 'RouteTables[0].RouteTableId' \
    --output text)

# Ajouter une route vers Internet
aws ec2 create-route \
    --route-table-id $ROUTE_TABLE_ID \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id $IGW_ID

# Associer au subnet public
aws ec2 associate-route-table \
    --route-table-id $ROUTE_TABLE_ID \
    --subnet-id $PUBLIC_SUBNET_ID
```

---

## 2. Security Groups - Configurer le pare-feu

### Étape 2.1 : Créer un Security Group

```bash
aws ec2 create-security-group \
    --group-name WebServerSG \
    --description "Security group pour serveur web" \
    --vpc-id $VPC_ID
```

**Sauvegarder** :
```bash
SG_ID="sg-0123456789abcdef0"
```

### Étape 2.2 : Autoriser SSH (port 22)

```bash
# Depuis votre IP uniquement (recommandé)
MY_IP=$(curl -s https://checkip.amazonaws.com)

aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 22 \
    --cidr "$MY_IP/32"
```

### Étape 2.3 : Autoriser HTTP (port 80)

```bash
aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0
```

### Étape 2.4 : Autoriser HTTPS (port 443)

```bash
aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 443 \
    --cidr 0.0.0.0/0
```

### Voir les règles

```bash
aws ec2 describe-security-groups \
    --group-ids $SG_ID
```

---

## 3. EC2 - Lancer une instance

### Étape 3.1 : Créer une Key Pair

```bash
aws ec2 create-key-pair \
    --key-name ma-cle \
    --query 'KeyMaterial' \
    --output text > ma-cle.pem

# Protéger la clé
chmod 400 ma-cle.pem
```

### Étape 3.2 : Trouver l'AMI Amazon Linux

```bash
# Dernière AMI Amazon Linux 2023
AMI_ID=$(aws ec2 describe-images \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-*-x86_64" \
              "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)

echo "AMI: $AMI_ID"
```

### Étape 3.3 : Lancer l'instance

```bash
aws ec2 run-instances \
    --image-id $AMI_ID \
    --instance-type t2.micro \
    --key-name ma-cle \
    --security-group-ids $SG_ID \
    --subnet-id $PUBLIC_SUBNET_ID \
    --associate-public-ip-address \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=MonServeur}]'
```

**Sauvegarder** :
```bash
INSTANCE_ID="i-0123456789abcdef0"
```

### Étape 3.4 : Attendre que l'instance démarre

```bash
aws ec2 wait instance-running --instance-ids $INSTANCE_ID
echo "Instance démarrée !"
```

### Étape 3.5 : Récupérer l'IP publique

```bash
PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids $INSTANCE_ID \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)

echo "IP publique : $PUBLIC_IP"
```

### Étape 3.6 : Se connecter en SSH

```bash
ssh -i ma-cle.pem ec2-user@$PUBLIC_IP
```

---

## 4. S3 - Stockage de fichiers

### Étape 4.1 : Créer un bucket

```bash
# Le nom doit être unique mondialement
BUCKET_NAME="mon-bucket-unique-12345"

aws s3 mb s3://$BUCKET_NAME
```

### Étape 4.2 : Activer le versioning

```bash
aws s3api put-bucket-versioning \
    --bucket $BUCKET_NAME \
    --versioning-configuration Status=Enabled
```

### Étape 4.3 : Bloquer l'accès public

```bash
aws s3api put-public-access-block \
    --bucket $BUCKET_NAME \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### Étape 4.4 : Uploader un fichier

```bash
# Créer un fichier test
echo "Hello AWS" > test.txt

# Uploader
aws s3 cp test.txt s3://$BUCKET_NAME/

# Uploader dans un dossier
aws s3 cp test.txt s3://$BUCKET_NAME/dossier/test.txt
```

### Étape 4.5 : Lister les fichiers

```bash
# Lister tous les buckets
aws s3 ls

# Lister le contenu d'un bucket
aws s3 ls s3://$BUCKET_NAME/

# Lister récursivement
aws s3 ls s3://$BUCKET_NAME/ --recursive
```

### Étape 4.6 : Télécharger un fichier

```bash
aws s3 cp s3://$BUCKET_NAME/test.txt ./downloaded.txt
```

### Étape 4.7 : Synchroniser un dossier

```bash
# Upload un dossier entier
aws s3 sync ./mon-dossier s3://$BUCKET_NAME/mon-dossier/

# Download un dossier
aws s3 sync s3://$BUCKET_NAME/mon-dossier/ ./local-dossier/
```

---

## 5. IAM - Gestion des identités

### Étape 5.1 : Créer un utilisateur

```bash
aws iam create-user --user-name alice
```

### Étape 5.2 : Créer une policy

```bash
# Créer le fichier policy
cat > ma-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::mon-bucket-unique-12345",
                "arn:aws:s3:::mon-bucket-unique-12345/*"
            ]
        }
    ]
}
EOF

# Créer la policy dans IAM
aws iam create-policy \
    --policy-name MaS3Policy \
    --policy-document file://ma-policy.json
```

### Étape 5.3 : Attacher la policy à l'utilisateur

```bash
POLICY_ARN="arn:aws:iam::123456789012:policy/MaS3Policy"

aws iam attach-user-policy \
    --user-name alice \
    --policy-arn $POLICY_ARN
```

### Étape 5.4 : Créer un role pour EC2

```bash
# Trust policy (qui peut assumer le role)
cat > trust-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

# Créer le role
aws iam create-role \
    --role-name MonEC2Role \
    --assume-role-policy-document file://trust-policy.json

# Attacher une policy au role
aws iam attach-role-policy \
    --role-name MonEC2Role \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

---

## 6. RDS - Base de données

### Étape 6.1 : Créer un subnet group

```bash
aws rds create-db-subnet-group \
    --db-subnet-group-name mon-db-subnet-group \
    --db-subnet-group-description "Subnets pour RDS" \
    --subnet-ids $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2
```

### Étape 6.2 : Créer un Security Group pour RDS

```bash
aws ec2 create-security-group \
    --group-name DatabaseSG \
    --description "Security group pour base de données" \
    --vpc-id $VPC_ID

DB_SG_ID="sg-database123"

# Autoriser PostgreSQL depuis le SG web
aws ec2 authorize-security-group-ingress \
    --group-id $DB_SG_ID \
    --protocol tcp \
    --port 5432 \
    --source-group $SG_ID
```

### Étape 6.3 : Créer l'instance RDS

```bash
aws rds create-db-instance \
    --db-instance-identifier ma-base \
    --db-instance-class db.t3.micro \
    --engine postgres \
    --engine-version 15 \
    --master-username admin \
    --master-user-password MonMotDePasse123! \
    --allocated-storage 20 \
    --db-subnet-group-name mon-db-subnet-group \
    --vpc-security-group-ids $DB_SG_ID \
    --no-publicly-accessible \
    --backup-retention-period 7
```

### Étape 6.4 : Attendre la création

```bash
aws rds wait db-instance-available --db-instance-identifier ma-base
echo "Base de données prête !"
```

### Étape 6.5 : Récupérer l'endpoint

```bash
DB_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier ma-base \
    --query 'DBInstances[0].Endpoint.Address' \
    --output text)

echo "Endpoint: $DB_ENDPOINT"
```

---

## 7. CloudWatch - Monitoring

### Étape 7.1 : Créer une alarme CPU

```bash
aws cloudwatch put-metric-alarm \
    --alarm-name HighCPU \
    --alarm-description "Alarme si CPU > 80%" \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --statistic Average \
    --period 300 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --dimensions Name=InstanceId,Value=$INSTANCE_ID \
    --evaluation-periods 2 \
    --alarm-actions arn:aws:sns:eu-west-3:123456789:mes-alertes
```

### Étape 7.2 : Voir les métriques

```bash
# Métriques EC2
aws cloudwatch get-metric-statistics \
    --namespace AWS/EC2 \
    --metric-name CPUUtilization \
    --dimensions Name=InstanceId,Value=$INSTANCE_ID \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --period 300 \
    --statistics Average
```

### Étape 7.3 : Envoyer une métrique custom

```bash
aws cloudwatch put-metric-data \
    --namespace "MonApplication" \
    --metric-name "NombreRequetes" \
    --value 42 \
    --unit Count
```

---

## 8. Nettoyage - Supprimer les ressources

**IMPORTANT** : Supprimer dans le bon ordre !

```bash
# 1. Terminer les instances EC2
aws ec2 terminate-instances --instance-ids $INSTANCE_ID
aws ec2 wait instance-terminated --instance-ids $INSTANCE_ID

# 2. Supprimer RDS
aws rds delete-db-instance \
    --db-instance-identifier ma-base \
    --skip-final-snapshot
aws rds wait db-instance-deleted --db-instance-identifier ma-base

# 3. Supprimer les Security Groups (sauf default)
aws ec2 delete-security-group --group-id $SG_ID
aws ec2 delete-security-group --group-id $DB_SG_ID

# 4. Supprimer les subnets
aws ec2 delete-subnet --subnet-id $PUBLIC_SUBNET_ID
aws ec2 delete-subnet --subnet-id $PRIVATE_SUBNET_ID

# 5. Détacher et supprimer l'IGW
aws ec2 detach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID
aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID

# 6. Supprimer le VPC
aws ec2 delete-vpc --vpc-id $VPC_ID

# 7. Supprimer le bucket S3 (doit être vide)
aws s3 rm s3://$BUCKET_NAME --recursive
aws s3 rb s3://$BUCKET_NAME

# 8. Supprimer la key pair
aws ec2 delete-key-pair --key-name ma-cle
rm ma-cle.pem
```

---

## Astuces

### Filtrer avec --query

```bash
# Seulement les IDs des instances running
aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text
```

### Format de sortie

```bash
# JSON (défaut)
aws ec2 describe-instances --output json

# Table (lisible)
aws ec2 describe-instances --output table

# Texte (pour scripts)
aws ec2 describe-instances --output text
```

### Aide

```bash
# Aide générale
aws help

# Aide d'un service
aws ec2 help

# Aide d'une commande
aws ec2 describe-instances help
```

---

## Prochaine étape

Pour des scripts plus complexes, utilisez Python avec Boto3.

Voir : **05_boto3_python.md**
