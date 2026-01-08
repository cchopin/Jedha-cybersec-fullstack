# Concepts AWS pour Débutants

Ce guide explique les concepts fondamentaux d'AWS nécessaires pour comprendre les scripts.

---

## Vue d'ensemble : L'infrastructure AWS

```
┌─────────────────────────────────────────────────────────────────┐
│                         REGION (eu-west-3)                      │
│  ┌────────────────────────┐    ┌────────────────────────────┐   │
│  │   Availability Zone A  │    │   Availability Zone B      │   │
│  │  ┌──────────────────┐  │    │  ┌──────────────────────┐  │   │
│  │  │  VPC 10.0.0.0/16 │  │    │  │                      │  │   │
│  │  │  ┌────────────┐  │  │    │  │  ┌────────────────┐  │  │   │
│  │  │  │ Subnet     │  │  │    │  │  │ Subnet         │  │  │   │
│  │  │  │ 10.0.1.0   │  │  │    │  │  │ 10.0.2.0       │  │  │   │
│  │  │  │  ┌─────┐   │  │  │    │  │  │  ┌─────────┐   │  │  │   │
│  │  │  │  │ EC2 │   │  │  │    │  │  │  │   RDS   │   │  │  │   │
│  │  │  │  └─────┘   │  │  │    │  │  │  └─────────┘   │  │  │   │
│  │  │  └────────────┘  │  │    │  │  └────────────────┘  │  │   │
│  │  └──────────────────┘  │    │  └──────────────────────┘  │   │
│  └────────────────────────┘    └────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                           Internet Gateway
                                │
                            Internet
```

---

## 1. Régions et Availability Zones

### Région

Une **région** est une zone géographique avec plusieurs data centers.

| Région | Code | Localisation |
|--------|------|--------------|
| Paris | `eu-west-3` | France |
| Irlande | `eu-west-1` | Europe |
| Francfort | `eu-central-1` | Allemagne |
| N. Virginia | `us-east-1` | USA (principal) |

**Choisir une région proche** = moins de latence.

### Availability Zone (AZ)

Chaque région a **2 à 6 AZs** (data centers indépendants).

- `eu-west-3a`, `eu-west-3b`, `eu-west-3c`

**Déployer sur plusieurs AZs** = haute disponibilité.

---

## 2. VPC (Virtual Private Cloud)

Un **VPC** est votre réseau privé dans AWS. C'est comme avoir votre propre data center virtuel.

### Composants d'un VPC

```
Internet
    │
    ▼
┌─────────────────┐
│Internet Gateway │  ← Porte vers Internet
└────────┬────────┘
         │
    ┌────┴────┐
    │   VPC   │  ← Votre réseau privé (10.0.0.0/16)
    │         │
    │  ┌──────┴──────┐
    │  │             │
    │  ▼             ▼
    │ Public      Private
    │ Subnet      Subnet
    │ 10.0.1.0/24 10.0.2.0/24
    │  │             │
    │  ▼             ▼
    │ EC2          RDS
    │ (Web)        (DB)
    └─────────────────┘
```

### Subnet public vs privé

| Type | Accès Internet | Utilisation |
|------|----------------|-------------|
| **Public** | Oui (via IGW) | Serveurs web, bastion |
| **Private** | Non (ou via NAT) | Bases de données, backend |

### CIDR (notation réseau)

```
10.0.0.0/16  = 65,536 IPs (VPC entier)
10.0.1.0/24  = 256 IPs (un subnet)
10.0.2.0/24  = 256 IPs (un autre subnet)
```

---

## 3. EC2 (Elastic Compute Cloud)

EC2 = **serveurs virtuels** (instances).

### Types d'instances courants

| Type | Specs | Utilisation | Prix/h (eu-west-3) |
|------|-------|-------------|-------------------|
| `t2.micro` | 1 vCPU, 1GB RAM | Tests, dev | ~$0.012 |
| `t2.small` | 1 vCPU, 2GB RAM | Petites apps | ~$0.025 |
| `t3.medium` | 2 vCPU, 4GB RAM | Apps moyennes | ~$0.046 |

**Free Tier** : 750h/mois de t2.micro pendant 12 mois.

### AMI (Amazon Machine Image)

Une AMI est une **image système** (comme une ISO).

AMIs courantes :
- `Amazon Linux 2023` (léger, optimisé AWS)
- `Ubuntu 22.04 LTS`
- `Windows Server 2022`

### Key Pair (clé SSH)

Pour se connecter à une instance Linux :

```bash
# Créer une key pair
aws ec2 create-key-pair --key-name ma-cle --query 'KeyMaterial' --output text > ma-cle.pem
chmod 400 ma-cle.pem

# Se connecter
ssh -i ma-cle.pem ec2-user@IP_PUBLIQUE
```

---

## 4. Security Groups (Pare-feu)

Un **Security Group** est un pare-feu virtuel pour vos instances.

### Règles par défaut

- **Sortant** : Tout autorisé
- **Entrant** : Tout bloqué (sauf règles ajoutées)

### Exemple de règles

```
┌─────────────────────────────────────────────────┐
│           Security Group : WebServerSG          │
├─────────────────────────────────────────────────┤
│ ENTRANT (Inbound)                               │
│   SSH (22)      ← Mon IP uniquement             │
│   HTTP (80)     ← Tout le monde (0.0.0.0/0)     │
│   HTTPS (443)   ← Tout le monde                 │
├─────────────────────────────────────────────────┤
│ SORTANT (Outbound)                              │
│   Tout          → Tout                          │
└─────────────────────────────────────────────────┘
```

### Security Groups vs NACLs

| Aspect | Security Group | NACL |
|--------|----------------|------|
| Niveau | Instance | Subnet |
| État | Stateful | Stateless |
| Règles | Allow only | Allow + Deny |
| Default | Deny all in | Allow all |

**Stateful** = si une requête entre, la réponse sort automatiquement.

---

## 5. IAM (Identity and Access Management)

IAM gère **QUI peut faire QUOI** sur AWS.

### Les composants IAM

```
┌─────────────────────────────────────────┐
│                  IAM                    │
│  ┌──────────┐  ┌──────────┐  ┌───────┐  │
│  │  Users   │  │  Groups  │  │ Roles │  │
│  │  Alice   │  │  Admins  │  │EC2Role│  │
│  │  Bob     │  │  Devs    │  │LambdaR│  │
│  └────┬─────┘  └────┬─────┘  └───┬───┘  │
│       │             │            │      │
│       └─────────────┴────────────┘      │
│                     │                   │
│              ┌──────┴──────┐            │
│              │   Policies  │            │
│              │  (JSON)     │            │
│              └─────────────┘            │
└─────────────────────────────────────────┘
```

### User vs Role

| Type | Utilisation | Credentials |
|------|-------------|-------------|
| **User** | Humains, applications externes | Access Key permanente |
| **Role** | Services AWS (EC2, Lambda) | Temporaires, auto-rotées |

**Best practice** : Utiliser des **roles** pour les services AWS, pas des users.

### Exemple de Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::mon-bucket/*"
        }
    ]
}
```

**Principe du moindre privilège** : Donner seulement les permissions nécessaires.

---

## 6. S3 (Simple Storage Service)

S3 = **stockage d'objets** (fichiers) illimité.

### Concepts

- **Bucket** : Conteneur de fichiers (nom unique mondial)
- **Object** : Fichier + metadata
- **Key** : Chemin du fichier (`uploads/image.jpg`)

### Classes de stockage

| Classe | Utilisation | Prix |
|--------|-------------|------|
| Standard | Accès fréquent | $$$ |
| Intelligent-Tiering | Variable | $$ |
| Glacier | Archives | $ |

### Sécurité S3

```
┌─────────────────────────────────────────┐
│              Bucket S3                  │
│  ┌─────────────────────────────────┐    │
│  │ Block Public Access : ACTIVE    │    │ ← Par défaut
│  ├─────────────────────────────────┤    │
│  │ Bucket Policy : HTTPS only      │    │
│  ├─────────────────────────────────┤    │
│  │ Versioning : Enabled            │    │ ← Protection suppression
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

---

## 7. RDS (Relational Database Service)

RDS = **bases de données gérées** (pas de maintenance serveur).

### Moteurs supportés

- PostgreSQL
- MySQL
- MariaDB
- Oracle
- SQL Server
- Aurora (AWS natif)

### Architecture typique

```
┌────────────────┐        ┌────────────────┐
│  EC2 (App)     │        │  RDS (DB)      │
│  Public Subnet │ ─────> │  Private Subnet│
│  10.0.1.0/24   │  :5432 │  10.0.2.0/24   │
└────────────────┘        └────────────────┘
       │                         │
       │    Security Group       │
       │    Autorise port 5432   │
       │    depuis App SG        │
       └─────────────────────────┘
```

**Jamais de RDS dans un subnet public** (sécurité).

---

## 8. CloudWatch (Monitoring)

CloudWatch = **surveillance et alertes**.

### Composants

| Composant | Description |
|-----------|-------------|
| **Metrics** | Données numériques (CPU, mémoire) |
| **Logs** | Journaux d'applications |
| **Alarms** | Alertes sur seuils |
| **Dashboards** | Visualisation |

### Métriques EC2 par défaut

- CPUUtilization
- NetworkIn / NetworkOut
- DiskReadOps / DiskWriteOps
- StatusCheckFailed

### Exemple d'alarme

```
SI CPUUtilization > 80%
PENDANT 5 minutes
ALORS envoyer email via SNS
```

---

## 9. ARN (Amazon Resource Name)

Chaque ressource AWS a un **ARN unique** :

```
arn:aws:service:region:account:resource
```

Exemples :
```
arn:aws:s3:::mon-bucket
arn:aws:ec2:eu-west-3:123456789:instance/i-1234567890abcdef
arn:aws:iam::123456789:user/alice
```

Les ARNs sont utilisés dans les policies IAM pour spécifier les ressources.

---

## 10. Tags

Les **tags** sont des étiquettes clé-valeur pour organiser les ressources.

```json
{
    "Name": "WebServer-Prod",
    "Environment": "Production",
    "Project": "MonApp",
    "Owner": "alice@example.com"
}
```

**Utilités** :
- Organisation
- Facturation par projet
- Automatisation (scripts qui filtrent par tag)

---

## Résumé : Architecture 3-tiers typique

```
                    Internet
                        │
                   ┌────┴────┐
                   │   IGW   │
                   └────┬────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │   ALB   │    │   ALB   │    │   ALB   │
   │ (Load   │    │         │    │         │
   │Balancer)│    │         │    │         │
   └────┬────┘    └─────────┘    └─────────┘
        │
   Public Subnet (10.0.1.0/24)
   ┌────┴────┐
   │   EC2   │  ← Web Tier (port 80/443)
   │  (Web)  │
   └────┬────┘
        │
   Private Subnet (10.0.2.0/24)
   ┌────┴────┐
   │   EC2   │  ← App Tier (port 8080)
   │  (App)  │
   └────┬────┘
        │
   Private Subnet (10.0.3.0/24)
   ┌────┴────┐
   │   RDS   │  ← Data Tier (port 5432)
   │  (DB)   │
   └─────────┘
```

---

## Prochaine étape

Maintenant que vous connaissez les concepts, passons aux commandes AWS CLI.

Voir : **04_commandes_aws_cli.md**
