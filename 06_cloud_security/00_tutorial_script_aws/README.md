# Tutoriel Scripts AWS

Bienvenue dans ce tutoriel pour automatiser AWS avec AWS CLI et Boto3 (Python).

## Objectif

Apprendre à utiliser les outils AWS pour :
- Créer des ressources cloud (VPC, EC2, S3, RDS...)
- Automatiser des tâches via des scripts
- Comprendre les bonnes pratiques de sécurité

## Structure du tutoriel

```
00_tutorial_script_aws/
├── README.md                          # Ce fichier
├── 01_installation_aws_cli.md         # Installation AWS CLI
├── 02_configuration_credentials.md    # Configuration des credentials
├── 03_concepts_aws.md                 # Concepts AWS fondamentaux
├── 04_commandes_aws_cli.md            # Commandes AWS CLI pas à pas
├── 05_boto3_python.md                 # SDK Python Boto3
├── 06_cheatsheet_aws.md               # Référence rapide
│
└── scripts/
    ├── demo_vpc.sh                    # Démo création VPC (bash)
    └── demo_s3.py                     # Démo opérations S3 (Python)
```

## Ordre de lecture recommandé

1. **01_installation_aws_cli.md** - Installer AWS CLI et Boto3
2. **02_configuration_credentials.md** - Configurer vos identifiants AWS
3. **03_concepts_aws.md** - Comprendre VPC, EC2, S3, IAM...
4. **04_commandes_aws_cli.md** - Apprendre les commandes CLI
5. **05_boto3_python.md** - Utiliser Python avec AWS
6. **06_cheatsheet_aws.md** - Référence rapide (à garder sous la main)

## Prérequis

- Un compte AWS (Free Tier suffit)
- AWS CLI installé
- Python 3.x avec Boto3
- Credentials AWS configurés

## Quick Start

### 1. Installer AWS CLI

```bash
# Mac
brew install awscli

# Vérifier
aws --version
```

### 2. Configurer les credentials

```bash
aws configure
# Entrer: Access Key ID, Secret Access Key, Region (eu-west-3), Format (json)
```

### 3. Vérifier la configuration

```bash
aws sts get-caller-identity
```

### 4. Tester un script

```bash
cd scripts

# Démo VPC (bash)
chmod +x demo_vpc.sh
./demo_vpc.sh

# Démo S3 (Python)
python3 demo_s3.py create
python3 demo_s3.py upload
python3 demo_s3.py list
python3 demo_s3.py cleanup
```

## Les scripts de démonstration

### demo_vpc.sh

Crée un VPC complet avec :
- Un VPC (10.0.0.0/16)
- Un subnet public
- Un Internet Gateway
- Un Security Group (SSH + HTTP)

```bash
# Créer
./demo_vpc.sh

# Nettoyer
./demo_vpc.sh cleanup
```

### demo_s3.py

Opérations S3 avec Boto3 :
- Créer un bucket sécurisé
- Uploader des fichiers
- Lister le contenu
- Générer des URLs présignées
- Nettoyer

```bash
python3 demo_s3.py create    # Créer le bucket
python3 demo_s3.py upload    # Uploader des fichiers
python3 demo_s3.py list      # Lister les fichiers
python3 demo_s3.py url       # URL présignée
python3 demo_s3.py cleanup   # Supprimer tout
```

## Concepts clés

### Services AWS couverts

| Service | Description | Cas d'usage |
|---------|-------------|-------------|
| **VPC** | Réseau privé virtuel | Isolation réseau |
| **EC2** | Serveurs virtuels | Applications, web servers |
| **S3** | Stockage objets | Fichiers, backups |
| **RDS** | Base de données | PostgreSQL, MySQL |
| **IAM** | Identités et accès | Users, roles, policies |
| **CloudWatch** | Monitoring | Métriques, alarmes |

### Architecture typique

```
                Internet
                    │
               ┌────┴────┐
               │   IGW   │
               └────┬────┘
                    │
    ┌───────────────┼───────────────┐
    │          VPC (10.0.0.0/16)    │
    │                               │
    │  ┌─────────────────────────┐  │
    │  │   Public Subnet         │  │
    │  │   10.0.1.0/24           │  │
    │  │   ┌─────────────────┐   │  │
    │  │   │  EC2 (Web)      │   │  │
    │  │   │  Security Group │   │  │
    │  │   └────────┬────────┘   │  │
    │  └────────────┼────────────┘  │
    │               │               │
    │  ┌────────────┼────────────┐  │
    │  │   Private Subnet        │  │
    │  │   10.0.2.0/24           │  │
    │  │   ┌─────────────────┐   │  │
    │  │   │  RDS (Database) │   │  │
    │  │   └─────────────────┘   │  │
    │  └─────────────────────────┘  │
    └───────────────────────────────┘
```

## Bonnes pratiques de sécurité

1. **Ne jamais utiliser le compte root** pour les tâches quotidiennes
2. **Activer MFA** sur les comptes privilégiés
3. **Principe du moindre privilège** : permissions minimales
4. **Ne jamais commiter les credentials** dans Git
5. **Utiliser des roles IAM** pour les services AWS (pas des access keys)
6. **Chiffrer les données** au repos et en transit
7. **Activer les logs** (CloudTrail, VPC Flow Logs)

## Commandes utiles

| Action | Commande |
|--------|----------|
| Qui suis-je ? | `aws sts get-caller-identity` |
| Lister les instances | `aws ec2 describe-instances` |
| Lister les buckets | `aws s3 ls` |
| Lister les utilisateurs | `aws iam list-users` |
| Changer de région | `--region eu-west-1` |
| Mode verbose | `--debug` |

## Troubleshooting

### "Unable to locate credentials"

```bash
aws configure
# Ou vérifier ~/.aws/credentials
```

### "Access Denied"

L'utilisateur n'a pas les permissions nécessaires.
Vérifier les policies IAM attachées.

### "InvalidClientTokenId"

Les credentials sont invalides ou expirées.
Recréer les access keys dans la console IAM.

## Pour aller plus loin

Une fois ce tutoriel maîtrisé, regardez les projets plus avancés :
- `Deploy_basic_3-tier_app/` - Application 3-tiers complète
- `AWS_network_security_services/` - Sécurité réseau avancée
- `StartupExcuses_monitoring/` - Monitoring CloudWatch
- `CreativeFlow_management_system/` - IAM et S3 avancé

## Ressources

- [Documentation AWS CLI](https://docs.aws.amazon.com/cli/)
- [Documentation Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS Free Tier](https://aws.amazon.com/free/)

Bon apprentissage !
