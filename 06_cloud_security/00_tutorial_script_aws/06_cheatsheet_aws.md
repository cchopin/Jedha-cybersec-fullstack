# Cheatsheet AWS CLI & Boto3

Référence rapide des commandes AWS les plus utilisées.

---

## Configuration

### AWS CLI

```bash
# Configurer les credentials
aws configure

# Configurer un profil spécifique
aws configure --profile nom_profil

# Vérifier l'identité
aws sts get-caller-identity

# Lister les profils
cat ~/.aws/credentials

# Utiliser un profil
aws s3 ls --profile nom_profil
export AWS_PROFILE=nom_profil
```

### Boto3

```python
import boto3

# Session par défaut
client = boto3.client('s3')

# Profil spécifique
session = boto3.Session(profile_name='formation')
client = session.client('s3')

# Région spécifique
client = boto3.client('ec2', region_name='eu-west-3')
```

---

## EC2 - Instances

### AWS CLI

```bash
# Lister les instances
aws ec2 describe-instances

# Lister seulement les instances running
aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name]' \
    --output table

# Lancer une instance
aws ec2 run-instances \
    --image-id ami-xxx \
    --instance-type t2.micro \
    --key-name ma-cle \
    --security-group-ids sg-xxx \
    --subnet-id subnet-xxx

# Démarrer/Arrêter/Terminer
aws ec2 start-instances --instance-ids i-xxx
aws ec2 stop-instances --instance-ids i-xxx
aws ec2 terminate-instances --instance-ids i-xxx

# Attendre un état
aws ec2 wait instance-running --instance-ids i-xxx
aws ec2 wait instance-terminated --instance-ids i-xxx

# Récupérer l'IP publique
aws ec2 describe-instances --instance-ids i-xxx \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text

# Key pairs
aws ec2 create-key-pair --key-name ma-cle --query 'KeyMaterial' --output text > ma-cle.pem
aws ec2 delete-key-pair --key-name ma-cle
aws ec2 describe-key-pairs
```

### Boto3

```python
ec2 = boto3.client('ec2')

# Lister
response = ec2.describe_instances()

# Lancer
ec2.run_instances(
    ImageId='ami-xxx',
    InstanceType='t2.micro',
    MinCount=1, MaxCount=1
)

# Arrêter/Démarrer/Terminer
ec2.stop_instances(InstanceIds=['i-xxx'])
ec2.start_instances(InstanceIds=['i-xxx'])
ec2.terminate_instances(InstanceIds=['i-xxx'])

# Waiter
waiter = ec2.get_waiter('instance_running')
waiter.wait(InstanceIds=['i-xxx'])
```

---

## VPC - Réseau

### AWS CLI

```bash
# VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16
aws ec2 describe-vpcs
aws ec2 delete-vpc --vpc-id vpc-xxx
aws ec2 modify-vpc-attribute --vpc-id vpc-xxx --enable-dns-hostnames

# Subnets
aws ec2 create-subnet --vpc-id vpc-xxx --cidr-block 10.0.1.0/24 --availability-zone eu-west-3a
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-xxx"
aws ec2 delete-subnet --subnet-id subnet-xxx

# Internet Gateway
aws ec2 create-internet-gateway
aws ec2 attach-internet-gateway --internet-gateway-id igw-xxx --vpc-id vpc-xxx
aws ec2 detach-internet-gateway --internet-gateway-id igw-xxx --vpc-id vpc-xxx
aws ec2 delete-internet-gateway --internet-gateway-id igw-xxx

# Route Tables
aws ec2 describe-route-tables --filters "Name=vpc-id,Values=vpc-xxx"
aws ec2 create-route --route-table-id rtb-xxx --destination-cidr-block 0.0.0.0/0 --gateway-id igw-xxx
aws ec2 associate-route-table --route-table-id rtb-xxx --subnet-id subnet-xxx

# NAT Gateway
aws ec2 allocate-address --domain vpc  # Elastic IP
aws ec2 create-nat-gateway --subnet-id subnet-xxx --allocation-id eipalloc-xxx
aws ec2 delete-nat-gateway --nat-gateway-id nat-xxx
```

---

## Security Groups

### AWS CLI

```bash
# Créer
aws ec2 create-security-group \
    --group-name MonSG \
    --description "Description" \
    --vpc-id vpc-xxx

# Lister
aws ec2 describe-security-groups --group-ids sg-xxx

# Ajouter règles
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 5432 \
    --source-group sg-autre

# Supprimer règles
aws ec2 revoke-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0

# Supprimer SG
aws ec2 delete-security-group --group-id sg-xxx
```

### Boto3

```python
ec2 = boto3.client('ec2')

# Créer
sg = ec2.create_security_group(
    GroupName='MonSG',
    Description='Description',
    VpcId='vpc-xxx'
)

# Ajouter règles
ec2.authorize_security_group_ingress(
    GroupId='sg-xxx',
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
```

---

## S3 - Stockage

### AWS CLI

```bash
# Buckets
aws s3 mb s3://mon-bucket                    # Créer
aws s3 ls                                     # Lister buckets
aws s3 ls s3://mon-bucket/                   # Lister contenu
aws s3 rb s3://mon-bucket                    # Supprimer (vide)
aws s3 rb s3://mon-bucket --force            # Supprimer (avec contenu)

# Fichiers
aws s3 cp fichier.txt s3://mon-bucket/       # Upload
aws s3 cp s3://mon-bucket/fichier.txt ./     # Download
aws s3 mv s3://mon-bucket/old.txt s3://mon-bucket/new.txt  # Renommer
aws s3 rm s3://mon-bucket/fichier.txt        # Supprimer
aws s3 rm s3://mon-bucket/ --recursive       # Vider bucket

# Sync
aws s3 sync ./dossier s3://mon-bucket/dossier/
aws s3 sync s3://mon-bucket/dossier/ ./dossier

# Configuration bucket
aws s3api put-bucket-versioning --bucket mon-bucket --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket mon-bucket \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### Boto3

```python
s3 = boto3.client('s3')

# Upload/Download
s3.upload_file('local.txt', 'mon-bucket', 'remote.txt')
s3.download_file('mon-bucket', 'remote.txt', 'local.txt')

# Contenu en mémoire
s3.put_object(Bucket='mon-bucket', Key='hello.txt', Body='Hello!')
response = s3.get_object(Bucket='mon-bucket', Key='hello.txt')
content = response['Body'].read().decode()

# Lister
response = s3.list_objects_v2(Bucket='mon-bucket')
for obj in response.get('Contents', []):
    print(obj['Key'])

# URL présignée
url = s3.generate_presigned_url('get_object',
    Params={'Bucket': 'mon-bucket', 'Key': 'fichier.pdf'},
    ExpiresIn=3600)
```

---

## IAM - Identités

### AWS CLI

```bash
# Users
aws iam create-user --user-name alice
aws iam delete-user --user-name alice
aws iam list-users

# Access Keys
aws iam create-access-key --user-name alice
aws iam delete-access-key --user-name alice --access-key-id AKIA...
aws iam list-access-keys --user-name alice

# Policies
aws iam create-policy --policy-name MaPolicy --policy-document file://policy.json
aws iam attach-user-policy --user-name alice --policy-arn arn:aws:iam::123:policy/MaPolicy
aws iam detach-user-policy --user-name alice --policy-arn arn:aws:iam::123:policy/MaPolicy
aws iam list-attached-user-policies --user-name alice

# Roles
aws iam create-role --role-name MonRole --assume-role-policy-document file://trust.json
aws iam attach-role-policy --role-name MonRole --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam delete-role --role-name MonRole

# Instance Profile (pour EC2)
aws iam create-instance-profile --instance-profile-name MonProfile
aws iam add-role-to-instance-profile --instance-profile-name MonProfile --role-name MonRole
```

### Boto3

```python
iam = boto3.client('iam')

# Users
iam.create_user(UserName='alice')
iam.delete_user(UserName='alice')

# Policies
iam.attach_user_policy(
    UserName='alice',
    PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
)
```

---

## RDS - Bases de données

### AWS CLI

```bash
# Créer
aws rds create-db-instance \
    --db-instance-identifier ma-base \
    --db-instance-class db.t3.micro \
    --engine postgres \
    --master-username admin \
    --master-user-password MonPassword123! \
    --allocated-storage 20

# Lister
aws rds describe-db-instances

# Récupérer endpoint
aws rds describe-db-instances --db-instance-identifier ma-base \
    --query 'DBInstances[0].Endpoint.Address' --output text

# Attendre disponibilité
aws rds wait db-instance-available --db-instance-identifier ma-base

# Supprimer
aws rds delete-db-instance --db-instance-identifier ma-base --skip-final-snapshot

# Subnet group
aws rds create-db-subnet-group \
    --db-subnet-group-name mon-group \
    --db-subnet-group-description "Description" \
    --subnet-ids subnet-xxx subnet-yyy
```

---

## CloudWatch - Monitoring

### AWS CLI

```bash
# Métriques
aws cloudwatch put-metric-data \
    --namespace "MonApp" \
    --metric-name "Requetes" \
    --value 42 \
    --unit Count

aws cloudwatch get-metric-statistics \
    --namespace AWS/EC2 \
    --metric-name CPUUtilization \
    --dimensions Name=InstanceId,Value=i-xxx \
    --start-time 2024-01-01T00:00:00Z \
    --end-time 2024-01-02T00:00:00Z \
    --period 3600 \
    --statistics Average

# Alarmes
aws cloudwatch put-metric-alarm \
    --alarm-name HighCPU \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --period 300 \
    --evaluation-periods 2 \
    --statistic Average \
    --dimensions Name=InstanceId,Value=i-xxx

aws cloudwatch describe-alarms
aws cloudwatch delete-alarms --alarm-names HighCPU

# Logs
aws logs create-log-group --log-group-name /app/logs
aws logs put-retention-policy --log-group-name /app/logs --retention-in-days 30
aws logs describe-log-groups
```

### Boto3

```python
cloudwatch = boto3.client('cloudwatch')

# Métrique
cloudwatch.put_metric_data(
    Namespace='MonApp',
    MetricData=[{
        'MetricName': 'Requetes',
        'Value': 42,
        'Unit': 'Count'
    }]
)

# Alarme
cloudwatch.put_metric_alarm(
    AlarmName='HighCPU',
    MetricName='CPUUtilization',
    Namespace='AWS/EC2',
    Threshold=80,
    ComparisonOperator='GreaterThanThreshold',
    EvaluationPeriods=2,
    Period=300,
    Statistic='Average',
    Dimensions=[{'Name': 'InstanceId', 'Value': 'i-xxx'}]
)
```

---

## Tags

### AWS CLI

```bash
# Ajouter des tags
aws ec2 create-tags \
    --resources i-xxx vpc-xxx \
    --tags Key=Name,Value=MonNom Key=Environment,Value=Dev

# Lister les tags
aws ec2 describe-tags --filters "Name=resource-id,Values=i-xxx"

# Filtrer par tag
aws ec2 describe-instances --filters "Name=tag:Environment,Values=Dev"
```

---

## Formats de sortie

```bash
# JSON (défaut)
aws ec2 describe-instances --output json

# Table (lisible)
aws ec2 describe-instances --output table

# Texte (pour scripts)
aws ec2 describe-instances --output text

# YAML
aws ec2 describe-instances --output yaml
```

---

## Filtres et Queries

### Filtres (côté serveur)

```bash
# Filtrer les instances running
aws ec2 describe-instances --filters "Name=instance-state-name,Values=running"

# Filtrer par tag
aws ec2 describe-instances --filters "Name=tag:Name,Values=WebServer"

# Plusieurs filtres
aws ec2 describe-instances --filters \
    "Name=instance-type,Values=t2.micro" \
    "Name=availability-zone,Values=eu-west-3a"
```

### Query (côté client - JMESPath)

```bash
# Extraire des champs spécifiques
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].[InstanceId,State.Name]'

# Premier élément
aws ec2 describe-instances --query 'Reservations[0].Instances[0].InstanceId'

# Avec filtre dans query
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[?State.Name==`running`].InstanceId'

# Output texte
aws ec2 describe-instances \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text
```

---

## Régions courantes

| Région | Code | Description |
|--------|------|-------------|
| Paris | `eu-west-3` | France |
| Irlande | `eu-west-1` | Europe principale |
| Francfort | `eu-central-1` | Allemagne |
| N. Virginia | `us-east-1` | USA (région principale AWS) |
| Oregon | `us-west-2` | USA Ouest |

```bash
# Changer de région
aws ec2 describe-instances --region us-east-1

# Lister toutes les régions
aws ec2 describe-regions --query 'Regions[*].RegionName' --output table
```

---

## Ordre de suppression

Toujours supprimer dans cet ordre pour éviter les erreurs de dépendances :

1. **Instances EC2** (terminate)
2. **RDS** (delete, skip-final-snapshot)
3. **NAT Gateway** (delete)
4. **Elastic IPs** (release)
5. **Security Groups** (sauf default)
6. **Subnets**
7. **Route Tables** (sauf main)
8. **Internet Gateway** (detach puis delete)
9. **VPC**
10. **S3 Buckets** (vider puis delete)
11. **IAM** (detach policies, delete users/roles)

---

## Debugging

```bash
# Mode verbose
aws ec2 describe-instances --debug

# Dry run (vérifie sans exécuter)
aws ec2 run-instances ... --dry-run

# Voir la requête HTTP
aws ec2 describe-instances --debug 2>&1 | grep "REQUEST"
```

---

## Variables utiles pour scripts

```bash
# Récupérer l'ID du compte
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Récupérer la région configurée
REGION=$(aws configure get region)

# Récupérer son IP publique
MY_IP=$(curl -s https://checkip.amazonaws.com)

# Dernière AMI Amazon Linux
AMI_ID=$(aws ec2 describe-images \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-*-x86_64" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text)
```
