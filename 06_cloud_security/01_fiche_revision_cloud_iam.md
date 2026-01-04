# Fiche de révision - Fondations du cloud et IAM

## Cloud computing - concepts fondamentaux

### Définition
Le cloud computing est l'accès à la demande à des ressources informatiques partagées, provisionnées et libérées rapidement avec un effort de gestion minimal.

### Les 5 caractéristiques essentielles
1. **Self-service à la demande** : provisionnement sans intervention humaine
2. **Accès réseau large** : disponible depuis n'importe où via internet
3. **Mutualisation des ressources** : plusieurs clients partagent la même infrastructure
4. **Élasticité rapide** : les ressources s'adaptent automatiquement à la demande
5. **Service mesuré** : facturation à l'usage uniquement

### Modèles de service

| Modèle | Description | Exemple |
|--------|-------------|---------|
| **IaaS** | Infrastructure (VMs, stockage, réseau) | EC2, S3 |
| **PaaS** | Plateforme de développement complète | Elastic Beanstalk, RDS |
| **SaaS** | Applications prêtes à l'emploi | Gmail, Office 365 |

### Modèle de responsabilité partagée

**AWS gère** (sécurité DU cloud) :
- Sécurité physique des datacenters
- Infrastructure matérielle et réseau
- Hyperviseur et systèmes hôtes
- Disponibilité des services

**Vous gérez** (sécurité DANS le cloud) :
- Vos données et leur chiffrement
- Gestion des identités et accès (IAM)
- Configuration des applications
- Paramètres réseau et firewall
- Mises à jour OS (sur EC2)

---

## Infrastructure AWS

### Régions et zones de disponibilité

```
Région (ex: eu-west-3 Paris)
├── Zone de disponibilité A (datacenter isolé)
├── Zone de disponibilité B (datacenter isolé)
└── Zone de disponibilité C (datacenter isolé)
```

**Points clés** :
- Une région = zone géographique indépendante
- Les AZ sont isolées mais connectées à faible latence
- Toujours vérifier la région sélectionnée dans la console (piège classique !)

### Services AWS essentiels

| Service | Type | Description |
|---------|------|-------------|
| **EC2** | Compute | Serveurs virtuels élastiques |
| **S3** | Stockage | Stockage objet (durabilité 11 nines) |
| **RDS** | Base de données | BDD managées (PostgreSQL, MySQL, etc.) |
| **Lambda** | Serverless | Exécution de code sans serveur |

---

## AWS IAM - Identity and Access Management

### Composants IAM

#### 1. Utilisateurs (Users)
- Identité avec credentials permanents
- Types : humains ou applications
- Credentials : mot de passe console et/ou access keys

```bash
# Créer un utilisateur
aws iam create-user --user-name alice

# Lister les utilisateurs
aws iam list-users
```

#### 2. Groupes (Groups)
- Collection d'utilisateurs
- Permissions héritées par tous les membres
- Un utilisateur peut appartenir à plusieurs groupes
- Pas d'imbrication de groupes

```bash
# Créer un groupe
aws iam create-group --group-name Developers

# Ajouter un utilisateur à un groupe
aws iam add-user-to-group --user-name alice --group-name Developers
```

#### 3. Rôles (Roles)
- Identité temporaire assumable
- Credentials automatiquement rotés
- Idéal pour services AWS et accès cross-account

```bash
# Lister les rôles
aws iam list-roles

# Assumer un rôle (retourne des credentials temporaires)
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/MyRole \
    --role-session-name MySession
```

#### 4. Policies (Politiques)
- Documents JSON définissant les permissions
- Types : AWS managed, customer managed, inline

### Structure d'une policy IAM

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::mon-bucket",
        "arn:aws:s3:::mon-bucket/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "192.168.1.0/24"
        }
      }
    }
  ]
}
```

**Éléments clés** :
- `Effect` : Allow ou Deny
- `Action` : actions autorisées (ex: `s3:GetObject`)
- `Resource` : ressources ciblées (ARN)
- `Condition` : conditions optionnelles

### Évaluation des policies

1. **Deny par défaut** : tout est refusé initialement
2. **Deny explicite gagne** : un Deny l'emporte toujours sur un Allow
3. **Allow explicite** : autorise si pas de Deny
4. **Deny implicite** : refusé si pas d'Allow explicite

---

## Bonnes pratiques IAM

### Sécurité du compte root
- Ne jamais utiliser le compte root pour les tâches quotidiennes
- Activer MFA sur le compte root
- Ne pas créer d'access keys pour root
- Utiliser uniquement pour les tâches nécessitant root

### Gestion des utilisateurs
- Créer des utilisateurs IAM individuels (jamais de partage)
- Activer MFA pour tous les utilisateurs privilégiés
- Utiliser des groupes pour gérer les permissions
- Appliquer le principe du moindre privilège

### Gestion des credentials
- Préférer les rôles aux utilisateurs quand possible
- Rotation régulière des access keys
- Ne jamais coder les credentials en dur dans le code
- Utiliser AWS Secrets Manager pour les secrets

```bash
# Vérifier l'identité actuelle
aws sts get-caller-identity

# Lister les access keys d'un utilisateur
aws iam list-access-keys --user-name alice

# Créer une nouvelle access key
aws iam create-access-key --user-name alice
```

---

## Configuration AWS CLI

### Installation et configuration

```bash
# Configurer AWS CLI
aws configure

# Informations demandées :
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (ex: eu-west-3)
# - Default output format (json)
```

### Fichiers de configuration

```bash
# Credentials (~/.aws/credentials)
[default]
aws_access_key_id = AKIA...
aws_secret_access_key = ...

# Config (~/.aws/config)
[default]
region = eu-west-3
output = json
```

### Vérification

```bash
# Tester la configuration
aws sts get-caller-identity

# Résultat attendu :
{
    "UserId": "AIDAXXXXXXXXXX",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/admin"
}
```

---

## AWS Free Tier

### Types de Free Tier

| Type | Durée | Exemples |
|------|-------|----------|
| **12 mois** | Première année | EC2 t2.micro (750h/mois), S3 (5GB), RDS (750h) |
| **Always Free** | Permanent | Lambda (1M requêtes), DynamoDB (25GB) |
| **Essais** | Variable | Certains services spécifiques |

### Surveillance des coûts

```bash
# Accéder au dashboard de facturation (via console)
# Billing > Free Tier > Vérifier l'usage
```

**Conseils** :
- Créer un budget à $0.01 pour être alerté
- Vérifier régulièrement la page Free Tier
- Toujours nettoyer les ressources après les exercices
- Attention aux régions : les ressources sont régionales !

---

## Commandes CLI essentielles

```bash
# IAM
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-policies --scope Local
aws iam get-user --user-name alice
aws iam attach-user-policy --user-name alice --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# STS (Security Token Service)
aws sts get-caller-identity
aws sts assume-role --role-arn <ARN> --role-session-name <SESSION>

# EC2
aws ec2 describe-instances
aws ec2 describe-regions

# S3
aws s3 ls
aws s3 mb s3://mon-bucket
aws s3 cp fichier.txt s3://mon-bucket/
```

---

## Ressources

- [Documentation AWS IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/)
- [AWS CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/)
- [Modèle de responsabilité partagée](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [AWS Free Tier](https://aws.amazon.com/free/)
- [IAM Policy Simulator](https://policysim.aws.amazon.com/)
