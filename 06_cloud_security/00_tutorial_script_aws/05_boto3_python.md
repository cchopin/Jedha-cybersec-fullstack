# Boto3 - SDK Python pour AWS

Ce guide explique comment utiliser Boto3, le SDK Python officiel pour AWS.

---

## Pourquoi Boto3 ?

| AWS CLI | Boto3 |
|---------|-------|
| Scripts bash simples | Logique complexe |
| Commandes one-shot | Applications Python |
| Prototypage rapide | Intégration dans du code |

Boto3 permet d'intégrer AWS dans vos applications Python.

---

## Installation

```bash
pip install boto3
```

Vérification :
```python
import boto3
print(boto3.__version__)
```

---

## Configuration

Boto3 utilise **automatiquement** les credentials de AWS CLI.

```python
import boto3

# Utilise le profil [default] de ~/.aws/credentials
s3 = boto3.client('s3')

# Spécifier un profil
session = boto3.Session(profile_name='formation')
s3 = session.client('s3')

# Spécifier une région
ec2 = boto3.client('ec2', region_name='eu-west-3')
```

---

## Client vs Resource

Boto3 offre deux interfaces :

### Client (bas niveau)

```python
# Client = appels API directs
s3_client = boto3.client('s3')
response = s3_client.list_buckets()
print(response['Buckets'])
```

### Resource (haut niveau)

```python
# Resource = interface orientée objet
s3_resource = boto3.resource('s3')
for bucket in s3_resource.buckets.all():
    print(bucket.name)
```

**Recommandation** : Utiliser `client` pour plus de contrôle, `resource` pour plus de simplicité.

---

## 1. S3 - Stockage

### Lister les buckets

```python
import boto3

s3 = boto3.client('s3')

response = s3.list_buckets()
for bucket in response['Buckets']:
    print(f"- {bucket['Name']} (créé le {bucket['CreationDate']})")
```

### Créer un bucket

```python
import boto3

s3 = boto3.client('s3', region_name='eu-west-3')

bucket_name = 'mon-bucket-unique-12345'

s3.create_bucket(
    Bucket=bucket_name,
    CreateBucketConfiguration={
        'LocationConstraint': 'eu-west-3'
    }
)
print(f"Bucket {bucket_name} créé !")
```

### Uploader un fichier

```python
import boto3

s3 = boto3.client('s3')

# Méthode 1 : upload_file
s3.upload_file('local_file.txt', 'mon-bucket', 'remote_file.txt')

# Méthode 2 : put_object (pour du contenu en mémoire)
s3.put_object(
    Bucket='mon-bucket',
    Key='hello.txt',
    Body='Hello World!'
)
```

### Télécharger un fichier

```python
import boto3

s3 = boto3.client('s3')

# Télécharger vers un fichier
s3.download_file('mon-bucket', 'remote_file.txt', 'local_file.txt')

# Ou lire directement en mémoire
response = s3.get_object(Bucket='mon-bucket', Key='hello.txt')
content = response['Body'].read().decode('utf-8')
print(content)
```

### Lister les fichiers d'un bucket

```python
import boto3

s3 = boto3.client('s3')

response = s3.list_objects_v2(Bucket='mon-bucket')

if 'Contents' in response:
    for obj in response['Contents']:
        print(f"- {obj['Key']} ({obj['Size']} bytes)")
else:
    print("Bucket vide")
```

### Générer une URL présignée

```python
import boto3

s3 = boto3.client('s3')

# URL valide 1 heure
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'mon-bucket', 'Key': 'fichier.pdf'},
    ExpiresIn=3600
)
print(f"URL de téléchargement : {url}")
```

---

## 2. EC2 - Instances

### Lister les instances

```python
import boto3

ec2 = boto3.client('ec2', region_name='eu-west-3')

response = ec2.describe_instances()

for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        # Récupérer le tag Name
        name = 'Sans nom'
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                name = tag['Value']

        print(f"{name}: {instance['InstanceId']} - {instance['State']['Name']}")
```

### Lancer une instance

```python
import boto3

ec2 = boto3.client('ec2', region_name='eu-west-3')

response = ec2.run_instances(
    ImageId='ami-0123456789abcdef0',  # AMI Amazon Linux
    InstanceType='t2.micro',
    MinCount=1,
    MaxCount=1,
    KeyName='ma-cle',
    SecurityGroupIds=['sg-0123456789abcdef0'],
    SubnetId='subnet-0123456789abcdef0',
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [
                {'Key': 'Name', 'Value': 'MonServeur'},
                {'Key': 'Environment', 'Value': 'Dev'}
            ]
        }
    ]
)

instance_id = response['Instances'][0]['InstanceId']
print(f"Instance lancée : {instance_id}")
```

### Attendre qu'une instance soit running

```python
import boto3

ec2 = boto3.client('ec2', region_name='eu-west-3')

instance_id = 'i-0123456789abcdef0'

# Waiter = attend un état spécifique
waiter = ec2.get_waiter('instance_running')
print("Attente du démarrage...")
waiter.wait(InstanceIds=[instance_id])
print("Instance démarrée !")

# Récupérer l'IP publique
response = ec2.describe_instances(InstanceIds=[instance_id])
public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
print(f"IP publique : {public_ip}")
```

### Arrêter / Démarrer / Terminer

```python
import boto3

ec2 = boto3.client('ec2', region_name='eu-west-3')

instance_id = 'i-0123456789abcdef0'

# Arrêter
ec2.stop_instances(InstanceIds=[instance_id])

# Démarrer
ec2.start_instances(InstanceIds=[instance_id])

# Terminer (supprimer)
ec2.terminate_instances(InstanceIds=[instance_id])
```

---

## 3. IAM - Identités

### Lister les utilisateurs

```python
import boto3

iam = boto3.client('iam')

response = iam.list_users()

for user in response['Users']:
    print(f"- {user['UserName']} (créé le {user['CreateDate']})")
```

### Créer un utilisateur

```python
import boto3

iam = boto3.client('iam')

iam.create_user(UserName='nouveau-user')
print("Utilisateur créé !")
```

### Attacher une policy

```python
import boto3

iam = boto3.client('iam')

# Policy AWS gérée
iam.attach_user_policy(
    UserName='nouveau-user',
    PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
)
```

---

## 4. CloudWatch - Monitoring

### Envoyer une métrique custom

```python
import boto3
from datetime import datetime

cloudwatch = boto3.client('cloudwatch', region_name='eu-west-3')

cloudwatch.put_metric_data(
    Namespace='MonApplication',
    MetricData=[
        {
            'MetricName': 'NombreVisites',
            'Value': 42,
            'Unit': 'Count',
            'Timestamp': datetime.utcnow()
        }
    ]
)
print("Métrique envoyée !")
```

### Récupérer des métriques

```python
import boto3
from datetime import datetime, timedelta

cloudwatch = boto3.client('cloudwatch', region_name='eu-west-3')

response = cloudwatch.get_metric_statistics(
    Namespace='AWS/EC2',
    MetricName='CPUUtilization',
    Dimensions=[
        {'Name': 'InstanceId', 'Value': 'i-0123456789abcdef0'}
    ],
    StartTime=datetime.utcnow() - timedelta(hours=1),
    EndTime=datetime.utcnow(),
    Period=300,  # 5 minutes
    Statistics=['Average']
)

for datapoint in response['Datapoints']:
    print(f"{datapoint['Timestamp']}: {datapoint['Average']:.2f}%")
```

### Créer une alarme

```python
import boto3

cloudwatch = boto3.client('cloudwatch', region_name='eu-west-3')

cloudwatch.put_metric_alarm(
    AlarmName='HighCPU',
    AlarmDescription='Alarme si CPU > 80%',
    MetricName='CPUUtilization',
    Namespace='AWS/EC2',
    Statistic='Average',
    Period=300,
    EvaluationPeriods=2,
    Threshold=80,
    ComparisonOperator='GreaterThanThreshold',
    Dimensions=[
        {'Name': 'InstanceId', 'Value': 'i-0123456789abcdef0'}
    ],
    AlarmActions=[
        'arn:aws:sns:eu-west-3:123456789:mes-alertes'
    ]
)
print("Alarme créée !")
```

---

## 5. VPC - Réseau

### Créer un VPC complet

```python
import boto3

ec2 = boto3.client('ec2', region_name='eu-west-3')

# 1. Créer le VPC
vpc_response = ec2.create_vpc(CidrBlock='10.0.0.0/16')
vpc_id = vpc_response['Vpc']['VpcId']
print(f"VPC créé : {vpc_id}")

# Ajouter un tag
ec2.create_tags(
    Resources=[vpc_id],
    Tags=[{'Key': 'Name', 'Value': 'MonVPC'}]
)

# 2. Activer les DNS hostnames
ec2.modify_vpc_attribute(
    VpcId=vpc_id,
    EnableDnsHostnames={'Value': True}
)

# 3. Créer un subnet
subnet_response = ec2.create_subnet(
    VpcId=vpc_id,
    CidrBlock='10.0.1.0/24',
    AvailabilityZone='eu-west-3a'
)
subnet_id = subnet_response['Subnet']['SubnetId']
print(f"Subnet créé : {subnet_id}")

# 4. Créer Internet Gateway
igw_response = ec2.create_internet_gateway()
igw_id = igw_response['InternetGateway']['InternetGatewayId']
print(f"IGW créé : {igw_id}")

# 5. Attacher l'IGW au VPC
ec2.attach_internet_gateway(
    InternetGatewayId=igw_id,
    VpcId=vpc_id
)

# 6. Configurer la route table
route_tables = ec2.describe_route_tables(
    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
)
route_table_id = route_tables['RouteTables'][0]['RouteTableId']

ec2.create_route(
    RouteTableId=route_table_id,
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=igw_id
)

print("VPC configuré avec succès !")
```

### Créer un Security Group

```python
import boto3

ec2 = boto3.client('ec2', region_name='eu-west-3')

# Créer le SG
sg_response = ec2.create_security_group(
    GroupName='WebServerSG',
    Description='Security group pour serveur web',
    VpcId='vpc-0123456789abcdef0'
)
sg_id = sg_response['GroupId']
print(f"Security Group créé : {sg_id}")

# Ajouter des règles
ec2.authorize_security_group_ingress(
    GroupId=sg_id,
    IpPermissions=[
        {
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH'}]
        },
        {
            'IpProtocol': 'tcp',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP'}]
        },
        {
            'IpProtocol': 'tcp',
            'FromPort': 443,
            'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS'}]
        }
    ]
)
print("Règles ajoutées !")
```

---

## 6. Gestion des erreurs

### Try/Except avec botocore

```python
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

s3 = boto3.client('s3')

try:
    s3.head_bucket(Bucket='mon-bucket')
    print("Le bucket existe")
except NoCredentialsError:
    print("ERREUR: Credentials AWS non configurées")
except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code == '404':
        print("Le bucket n'existe pas")
    elif error_code == '403':
        print("Accès refusé")
    else:
        print(f"Erreur: {e}")
```

### Erreurs courantes

| Code | Signification |
|------|---------------|
| `AccessDenied` | Permissions insuffisantes |
| `InvalidParameterValue` | Paramètre invalide |
| `ResourceNotFoundException` | Ressource introuvable |
| `LimitExceededException` | Quota dépassé |

---

## 7. Pagination

Pour les grosses listes, AWS pagine les résultats.

### Méthode manuelle

```python
import boto3

s3 = boto3.client('s3')

paginator = s3.get_paginator('list_objects_v2')

for page in paginator.paginate(Bucket='mon-bucket'):
    if 'Contents' in page:
        for obj in page['Contents']:
            print(obj['Key'])
```

### Avec Resource

```python
import boto3

s3 = boto3.resource('s3')
bucket = s3.Bucket('mon-bucket')

# Itération automatique avec pagination
for obj in bucket.objects.all():
    print(obj.key)
```

---

## 8. Bonnes pratiques

### Utiliser des sessions

```python
import boto3

# Créer une session explicite
session = boto3.Session(
    profile_name='formation',
    region_name='eu-west-3'
)

# Utiliser la session pour tous les clients
s3 = session.client('s3')
ec2 = session.client('ec2')
```

### Variables d'environnement

```python
import os
import boto3

# Configuration via variables d'environnement
os.environ['AWS_DEFAULT_REGION'] = 'eu-west-3'

# Ou dans le code
boto3.setup_default_session(region_name='eu-west-3')
```

### Ne jamais hardcoder les credentials

```python
# MAUVAIS - Ne jamais faire ça !
s3 = boto3.client(
    's3',
    aws_access_key_id='AKIAXXXX',  # DANGER !
    aws_secret_access_key='xxxx'   # DANGER !
)

# BON - Utiliser les credentials configurées
s3 = boto3.client('s3')
```

---

## Script complet exemple

Voici un script qui crée une infrastructure complète :

```python
#!/usr/bin/env python3
"""
Script de démonstration Boto3
Crée un VPC, un subnet, un security group et une instance EC2
"""

import boto3
import time

def main():
    # Configuration
    region = 'eu-west-3'
    ec2 = boto3.client('ec2', region_name=region)

    print("=== Création de l'infrastructure ===\n")

    # 1. VPC
    print("1. Création du VPC...")
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
    vpc_id = vpc['Vpc']['VpcId']
    ec2.create_tags(Resources=[vpc_id], Tags=[{'Key': 'Name', 'Value': 'DemoVPC'}])
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})
    print(f"   VPC: {vpc_id}")

    # 2. Subnet
    print("2. Création du subnet...")
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.0.1.0/24')
    subnet_id = subnet['Subnet']['SubnetId']
    print(f"   Subnet: {subnet_id}")

    # 3. Internet Gateway
    print("3. Création de l'Internet Gateway...")
    igw = ec2.create_internet_gateway()
    igw_id = igw['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    print(f"   IGW: {igw_id}")

    # 4. Route table
    print("4. Configuration des routes...")
    rt = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    rt_id = rt['RouteTables'][0]['RouteTableId']
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)

    # 5. Security Group
    print("5. Création du Security Group...")
    sg = ec2.create_security_group(GroupName='DemoSG', Description='Demo', VpcId=vpc_id)
    sg_id = sg['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ]
    )
    print(f"   SG: {sg_id}")

    print("\n=== Infrastructure créée avec succès ! ===")
    print(f"\nRessources créées:")
    print(f"  - VPC: {vpc_id}")
    print(f"  - Subnet: {subnet_id}")
    print(f"  - IGW: {igw_id}")
    print(f"  - SG: {sg_id}")

    # Sauvegarder les IDs
    with open('infrastructure_ids.txt', 'w') as f:
        f.write(f"VPC_ID={vpc_id}\n")
        f.write(f"SUBNET_ID={subnet_id}\n")
        f.write(f"IGW_ID={igw_id}\n")
        f.write(f"SG_ID={sg_id}\n")

    print("\nIDs sauvegardés dans infrastructure_ids.txt")


if __name__ == '__main__':
    main()
```

---

## Prochaine étape

Pour une référence rapide des commandes, consultez le cheatsheet.

Voir : **06_cheatsheet_aws.md**
