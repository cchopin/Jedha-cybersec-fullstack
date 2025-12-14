# CreativeFlow - Guide de Déploiement

## Table des Matières

1. [Prérequis](#1-prérequis)
2. [Installation AWS CLI](#2-installation-aws-cli)
3. [Configuration des Credentials AWS](#3-configuration-des-credentials-aws)
4. [Création d'une Paire de Clés SSH](#4-création-dune-paire-de-clés-ssh)
5. [Déploiement Étape par Étape](#5-déploiement-étape-par-étape)
6. [Vérification et Tests](#6-vérification-et-tests)
7. [Nettoyage des Ressources](#7-nettoyage-des-ressources)
8. [Dépannage](#8-dépannage)
9. [Liens Documentation AWS](#9-liens-documentation-aws)

---

## 1. Prérequis

- Un **compte AWS** actif
- Un terminal **Bash** (Linux, macOS, ou WSL sur Windows)
- **Droits administrateur** sur la machine locale (pour installer AWS CLI)

---

## 2. Installation AWS CLI

### macOS

```bash
# Avec Homebrew
brew install awscli

# OU téléchargement direct
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
```

### Linux (Ubuntu/Debian)

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### Windows (WSL)

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### Vérification de l'installation

```bash
aws --version
# Résultat : aws-cli/2.x.x Python/3.x.x ...
```

**Documentation** : https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

---

## 3. Configuration des Credentials AWS

### 3.1 Création d'un Utilisateur IAM avec Access Keys

1. Connexion à la **Console AWS** : https://console.aws.amazon.com/

2. Navigation vers **IAM** :
   - Services → IAM → Users → "Create user"

3. Configuration de l'utilisateur :
   - Nom : `creativeflow-admin`
   - Option : "Provide user access to the AWS Management Console" (optionnel)

4. Attribution des permissions :
   - Sélection de "Attach policies directly"
   - Activation de **AdministratorAccess**

5. Création et récupération des identifiants :
   - Access Key ID
   - Secret Access Key (visible une seule fois)

### 3.2 Création d'une Access Key (utilisateur existant)

1. IAM → Users → Sélection de l'utilisateur
2. Onglet "Security credentials"
3. Section "Access keys" → "Create access key"
4. Sélection de "Command Line Interface (CLI)"
5. Téléchargement du fichier CSV

### 3.3 Configuration AWS CLI

```bash
aws configure
```

Paramètres à renseigner :

```
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: eu-west-3
Default output format [None]: json
```

| Paramètre | Exemple | Description |
|-----------|---------|-------------|
| Access Key ID | `AKIA...` | Identifiant de la clé (20 caractères) |
| Secret Access Key | `wJal...` | Clé secrète (40 caractères) |
| Region | `eu-west-3` | Région AWS (Paris) |
| Output format | `json` | Format de sortie |

### 3.4 Vérification de la configuration

```bash
aws sts get-caller-identity
```

Résultat :
```json
{
    "UserId": "AIDAIOSFODNN7EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/creativeflow-admin"
}
```

### Emplacement des fichiers de configuration

```bash
~/.aws/credentials    # Credentials
~/.aws/config         # Configuration
```

**Documentation** : https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html

---

## 4. Création d'une Paire de Clés SSH

### Option A : Via AWS CLI

```bash
aws ec2 create-key-pair \
    --key-name creativeflow-key \
    --query 'KeyMaterial' \
    --output text > ~/.ssh/creativeflow-key.pem

chmod 400 ~/.ssh/creativeflow-key.pem
```

### Option B : Via la Console AWS

1. Console AWS → EC2 → "Key Pairs"
2. "Create key pair"
3. Nom : `creativeflow-key`
4. Type : RSA
5. Format : `.pem` (Linux/macOS) ou `.ppk` (Windows PuTTY)
6. Déplacement du fichier : `mv ~/Downloads/creativeflow-key.pem ~/.ssh/`
7. Sécurisation : `chmod 400 ~/.ssh/creativeflow-key.pem`

**Documentation** : https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html

---

## 5. Déploiement Étape par Étape

### 5.1 Préparation de l'environnement

```bash
cd /chemin/vers/CreativeFlow_management_system

chmod +x scripts/*.sh

export AWS_REGION=eu-west-3
export S3_BUCKET_NAME=creativeflow-docs-$(date +%s)

echo "Nom du bucket: $S3_BUCKET_NAME"
```

### 5.2 Création du Bucket S3

```bash
./scripts/setup-s3.sh
```

Actions effectuées :
- Création du bucket S3
- Activation du versioning
- Blocage de l'accès public
- Application de la politique SSL/TLS
- Création de la structure de dossiers

### 5.3 Création des Rôles IAM

```bash
./scripts/setup-iam.sh
```

Actions effectuées :
- Création du rôle `CreativeFlow-Developer`
- Création du rôle `CreativeFlow-Contributor`
- Création des profils d'instance EC2

### 5.4 Création du Security Group

```bash
./scripts/setup-security-group.sh
```

**Noter le `SECURITY_GROUP_ID` affiché.**

```bash
export SECURITY_GROUP_ID=sg-xxxxxxxxxxxxxxxxx
```

Actions effectuées :
- Création du security group
- Configuration des règles SSH (port 22, IP admin)
- Configuration des règles HTTP/HTTPS (ports 80, 443, 5000)

### 5.5 Déploiement de l'Instance EC2

```bash
export KEY_NAME=creativeflow-key

# Rôle Developer (accès complet)
./scripts/deploy-ec2.sh

# OU Rôle Contributor (accès restreint)
IAM_ROLE=CreativeFlow-Contributor ./scripts/deploy-ec2.sh
```

Actions effectuées :
- Lancement d'une instance EC2 Amazon Linux 2023
- Attachement du rôle IAM
- Installation de Python, Flask et dépendances
- Démarrage de l'application comme service systemd

### 5.6 Accès à l'Application

Délai de démarrage : 2-3 minutes après le lancement de l'instance.

```bash
echo "http://$(aws ec2 describe-instances \
    --filters "Name=tag:Project,Values=CreativeFlow" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].PublicIpAddress" \
    --output text):5000"
```

### 5.7 Identifiants de Connexion

L'application utilise une authentification HTTP Basic. Une fenêtre de connexion apparaît au premier accès.

| Utilisateur | Mot de passe | Rôle | Accès |
|-------------|--------------|------|-------|
| `developer` | `dev123` | Developer | Fichiers + Logs |
| `contributor` | `contrib123` | Contributor | Fichiers uniquement |

---

## 6. Vérification et Tests

### Test 1 : Vérification des informations utilisateur

L'interface web affiche :
- L'utilisateur connecté et son rôle applicatif :
```
Utilisateur connecte : developer [developer]
```
- Le rôle IAM EC2 utilisé pour accéder à S3 :
```
Role IAM EC2 : arn:aws:sts::123456789012:assumed-role/CreativeFlow-Developer/i-0abc123...
```

### Test 2 : Upload de fichier

1. Sélection d'un fichier
2. Choix de la catégorie
3. Clic sur "Uploader"
4. Le fichier apparaît dans la liste

### Test 3 : Accès aux logs

Connexion avec les identifiants `developer` / `dev123` :

| Action | Résultat |
|--------|----------|
| Clic sur "Tester Acces aux Logs" | Accès accordé (message vert) |

Connexion avec les identifiants `contributor` / `contrib123` :

| Action | Résultat |
|--------|----------|
| Clic sur "Tester Acces aux Logs" | Accès refusé - 403 (message rouge) |

### Test 4 : Connexion SSH

```bash
ssh -i ~/.ssh/creativeflow-key.pem ec2-user@<IP-PUBLIQUE>

# Vérification du service
sudo systemctl status creativeflow

# Consultation des logs
sudo journalctl -u creativeflow -f
```

---

## 7. Nettoyage des Ressources

**Exécution obligatoire après les tests pour éviter la facturation.**

```bash
export S3_BUCKET_NAME=creativeflow-docs-xxxxxxxxxx

./scripts/cleanup.sh
```

Ressources supprimées :
- Instances EC2 (tag Project=CreativeFlow)
- Bucket S3 et contenu
- Security Group
- Rôles IAM et profils d'instance

---

## 8. Dépannage

### Erreur "This account is currently blocked"

Cette erreur survient lors du lancement d'une instance EC2 :
```
Instance launch failed. This account is currently blocked and not recognized
as a valid account. Please contact aws-verification@amazon.com if you have questions.
```

**Cause** : Le compte AWS est en attente de vérification (nouveau compte, problème de paiement, ou vérification d'identité).

**Solution** :
1. Connexion à la Console AWS : https://console.aws.amazon.com/
2. Navigation vers **Support Center** (icône `?` en haut à droite)
3. Création d'un ticket :
   - Catégorie : Account and billing support
   - Type : Account
   - Objet : Account verification / Account blocked
4. Délai de réponse annoncé: 24h

En attendant la résolution, les services S3 et IAM restent fonctionnels.

### Erreur "Unable to locate credentials"

```bash
aws configure list
aws configure
```

### Erreur "Access Denied"

Vérification des permissions de l'utilisateur IAM :
- Permissions minimales requises : EC2, S3, IAM

### Application non accessible

```bash
ssh -i ~/.ssh/creativeflow-key.pem ec2-user@<IP>

sudo systemctl status creativeflow
sudo journalctl -u creativeflow -n 50
sudo systemctl restart creativeflow
```

### Connexion SSH impossible

1. Vérification du changement d'IP (relancer setup-security-group.sh)
2. Vérification des permissions : `chmod 400 ~/.ssh/creativeflow-key.pem`
3. Vérification de l'état de l'instance dans la console EC2

---

## 9. Liens Documentation AWS

### Documentation Générale

| Service | Lien |
|---------|------|
| AWS CLI | https://docs.aws.amazon.com/cli/latest/userguide/ |
| IAM | https://docs.aws.amazon.com/IAM/latest/UserGuide/ |
| S3 | https://docs.aws.amazon.com/AmazonS3/latest/userguide/ |
| EC2 | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ |

### Documentation Spécifique

| Sujet | Lien |
|-------|------|
| Installation AWS CLI | https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html |
| Configuration Credentials | https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html |
| Access Keys | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html |
| Paires de clés EC2 | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html |
| Rôles IAM pour EC2 | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html |
| Politiques IAM | https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html |
| Security Groups | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html |
| Politiques S3 | https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html |

### Bonnes Pratiques

| Sujet | Lien |
|-------|------|
| IAM | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
| S3 | https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html |
| EC2 | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-best-practices.html |

### Tarification

| Sujet | Lien |
|-------|------|
| Calculateur | https://calculator.aws/ |
| Free Tier | https://aws.amazon.com/free/ |
| EC2 | https://aws.amazon.com/ec2/pricing/ |
| S3 | https://aws.amazon.com/s3/pricing/ |

---

## Annexe : Régions AWS

| Code | Localisation |
|------|--------------|
| `eu-west-3` | Paris (France) |
| `eu-west-1` | Dublin (Irlande) |
| `eu-central-1` | Francfort (Allemagne) |
| `us-east-1` | Virginie du Nord (États-Unis) |
| `us-west-2` | Oregon (États-Unis) |
