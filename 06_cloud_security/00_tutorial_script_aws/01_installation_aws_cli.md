# Installation de AWS CLI

Ce guide explique comment installer AWS CLI (Command Line Interface) sur Mac, Windows et Linux.

## Qu'est-ce que AWS CLI ?

AWS CLI est l'outil en ligne de commande officiel d'Amazon Web Services. Il permet de :

- Créer et gérer des ressources AWS (EC2, S3, VPC, RDS...)
- Automatiser des tâches via des scripts
- Interagir avec tous les services AWS depuis le terminal

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Votre     │   CLI   │    AWS      │   API   │  Services   │
│  Terminal   │ ──────> │    CLI      │ ──────> │    AWS      │
│             │         │             │         │ EC2/S3/RDS  │
└─────────────┘         └─────────────┘         └─────────────┘
```

---

## Installation sur Mac

### Méthode 1 : Via Homebrew (Recommandé)

```bash
# 1. Installer Homebrew si pas déjà fait
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Installer AWS CLI
brew install awscli

# 3. Vérifier l'installation
aws --version
```

### Méthode 2 : Via le package officiel

```bash
# 1. Télécharger le package
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"

# 2. Installer
sudo installer -pkg AWSCLIV2.pkg -target /

# 3. Vérifier
aws --version

# 4. Nettoyer
rm AWSCLIV2.pkg
```

**Résultat attendu** :
```
aws-cli/2.x.x Python/3.x.x Darwin/xx.x.x source/x86_64
```

---

## Installation sur Windows

### Méthode 1 : Via l'installateur MSI (Recommandé)

1. Télécharger l'installateur :
   - https://awscli.amazonaws.com/AWSCLIV2.msi

2. Double-cliquer sur le fichier `.msi`

3. Suivre l'assistant d'installation

4. Ouvrir PowerShell et vérifier :
   ```powershell
   aws --version
   ```

### Méthode 2 : Via Chocolatey

```powershell
# Si Chocolatey est installé
choco install awscli
```

### Méthode 3 : Via winget

```powershell
winget install Amazon.AWSCLI
```

---

## Installation sur Linux

### Ubuntu / Debian

```bash
# Méthode 1 : Via le package officiel (recommandé)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm -rf aws awscliv2.zip

# Vérifier
aws --version
```

### Amazon Linux / CentOS / RHEL

```bash
# AWS CLI est souvent pré-installé sur Amazon Linux
# Sinon :
sudo yum install awscli

# Ou via le package officiel (même méthode que Ubuntu)
```

---

## Vérification de l'installation

### Test basique

```bash
# Afficher la version
aws --version

# Afficher l'aide
aws help

# Afficher l'aide d'un service spécifique
aws ec2 help
```

### Structure des commandes AWS CLI

```
aws <service> <action> [options]
```

Exemples :
```bash
aws ec2 describe-instances          # Lister les instances EC2
aws s3 ls                           # Lister les buckets S3
aws iam list-users                  # Lister les utilisateurs IAM
```

---

## Installer Boto3 (SDK Python)

Boto3 est le SDK Python officiel pour AWS. Il permet de faire la même chose que AWS CLI, mais en Python.

### Installation

```bash
# Via pip
pip install boto3

# Ou pip3
pip3 install boto3

# Vérifier
python3 -c "import boto3; print(boto3.__version__)"
```

### Quand utiliser quoi ?

| Outil | Utilisation |
|-------|-------------|
| **AWS CLI** | Scripts bash, commandes rapides, automatisation simple |
| **Boto3** | Applications Python, logique complexe, intégration avec du code |

---

## Mise à jour

### Mac (Homebrew)

```bash
brew upgrade awscli
```

### Windows

Retélécharger et réinstaller le MSI, ou :
```powershell
choco upgrade awscli
```

### Linux

```bash
# Retélécharger et réinstaller
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install --update
```

---

## Désinstallation

### Mac

```bash
# Via Homebrew
brew uninstall awscli

# Via package
sudo rm -rf /usr/local/aws-cli
sudo rm /usr/local/bin/aws
sudo rm /usr/local/bin/aws_completer
```

### Windows

Panneau de configuration > Programmes > Désinstaller AWS CLI

### Linux

```bash
sudo rm -rf /usr/local/aws-cli
sudo rm /usr/local/bin/aws
sudo rm /usr/local/bin/aws_completer
```

---

## Auto-complétion (optionnel mais pratique)

### Bash

```bash
# Ajouter à ~/.bashrc
complete -C '/usr/local/bin/aws_completer' aws

# Recharger
source ~/.bashrc
```

### Zsh (Mac par défaut)

```bash
# Ajouter à ~/.zshrc
autoload bashcompinit && bashcompinit
complete -C '/usr/local/bin/aws_completer' aws

# Recharger
source ~/.zshrc
```

Maintenant, tapez `aws s3 ` puis Tab pour voir les suggestions !

---

## Prochaine étape

L'installation est faite, mais AWS CLI ne sait pas encore QUI vous êtes.
Il faut configurer vos credentials (identifiants).

Voir : **02_configuration_credentials.md**
