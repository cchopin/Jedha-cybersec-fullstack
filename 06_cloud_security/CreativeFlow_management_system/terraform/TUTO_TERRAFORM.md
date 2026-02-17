# CreativeFlow - Tutoriel Terraform de A a Z

Ce guide vous accompagne pas a pas pour deployer le lab CreativeFlow sur AWS avec Terraform, depuis l'installation jusqu'au nettoyage.

---

## Contexte : lien avec l'exercice du cours

Ce tutoriel Terraform deploie **exactement la meme infrastructure** que l'exercice CreativeFlow du cours, qui utilise des scripts shell (`scripts/*.sh`). L'objectif pedagogique est identique : comprendre la securite AWS a travers IAM, S3, EC2 et les Security Groups.

### Rappel de l'exercice du cours

Le lab CreativeFlow est un systeme de gestion documentaire pour une agence marketing. Il met en pratique :

- **IAM** : deux roles (Developer / Contributor) avec des permissions differentes
- **S3** : un bucket securise (versioning, SSL, blocage public) avec controle d'acces par dossier
- **EC2** : une instance qui heberge une application Flask
- **Security Groups** : regles de firewall (SSH restreint, port 5000 ouvert)
- **Defense en profondeur** : double couche de securite (application + IAM)

Pour plus de details sur les concepts, consultez :
- [GUIDE_DEPLOIEMENT.md](../GUIDE_DEPLOIEMENT.md) : le guide de deploiement original avec scripts shell
- [SECURITY_DOCUMENTATION.md](../SECURITY_DOCUMENTATION.md) : l'architecture de securite detaillee
- [EXPLICATION_POLICIES.md](../aws-config/iam-policies/EXPLICATION_POLICIES.md) : explication des politiques IAM (ARN, Deny explicite, Trust Policy, etc.)

### Pourquoi Terraform ?

Dans le cours, le deploiement se fait avec **6 scripts shell** lances un par un :

```bash
# Version scripts shell (cours)
./scripts/setup-s3.sh              # Etape 1 : creer le bucket S3
./scripts/setup-iam.sh             # Etape 2 : creer les roles IAM
./scripts/setup-security-group.sh  # Etape 3 : creer le security group
./scripts/deploy-ec2.sh            # Etape 4 : lancer l'instance EC2
# ... tester ...
./scripts/cleanup.sh               # Etape 5 : tout supprimer
```

Avec **Terraform**, on remplace tout ca par 3 commandes :

```bash
# Version Terraform
terraform init     # Telecharger les plugins
terraform apply    # Tout creer d'un coup (S3 + IAM + SG + EC2)
terraform destroy  # Tout supprimer d'un coup
```

### Correspondance scripts shell / fichiers Terraform

| Script du cours | Fichier Terraform | Ressources AWS creees |
|----------------|-------------------|----------------------|
| `setup-s3.sh` | `s3.tf` | Bucket S3 + versioning + blocage public + politique SSL + structure de dossiers |
| `setup-iam.sh` | `iam.tf` | 2 roles IAM (Developer + Contributor) + 2 policies + 2 instance profiles |
| `setup-security-group.sh` | `security_group.tf` | 1 security group avec 4 regles (SSH, Flask, HTTP, HTTPS) |
| `deploy-ec2.sh` + `user-data.sh` | `ec2.tf` + `user-data.sh` | 1 instance EC2 avec l'application Flask |
| `cleanup.sh` | `terraform destroy` | Suppression de toutes les ressources |
| *(pas d'equivalent)* | `data.tf` | Detection automatique de l'AMI, du VPC, et de votre IP |
| *(pas d'equivalent)* | `outputs.tf` | Affichage de l'URL, IP, commande SSH, etc. |
| *(pas d'equivalent)* | `variables.tf` | Configuration centralisee (region, instance type, role) |

### Ce qui est identique entre les deux versions

Les ressources AWS creees sont **strictement les memes** :

- Les **politiques IAM** sont identiques a `developer-policy.json` et `contributor-policy.json`
- La **Trust Policy** EC2 est identique a `trust-policy-ec2.json`
- Le **bucket S3** a la meme configuration (versioning, public block, SSL enforcement)
- Le **Security Group** a les memes 4 regles d'entree
- L'**application Flask** (`app.py`) et le **template HTML** sont identiques
- Les **identifiants de connexion** sont les memes (`developer`/`dev123`, `contributor`/`contrib123`)

La seule difference est l'outil utilise pour creer ces ressources (scripts shell vs Terraform).

---

## Table des matieres

1. [Pre-requis](#1-pre-requis)
2. [Installer Terraform](#2-installer-terraform)
3. [Installer AWS CLI](#3-installer-aws-cli)
4. [Configurer les credentials AWS](#4-configurer-les-credentials-aws)
5. [Creer une Key Pair SSH](#5-creer-une-key-pair-ssh)
6. [Configurer le projet Terraform](#6-configurer-le-projet-terraform)
7. [Deployer l'infrastructure](#7-deployer-linfrastructure)
8. [Tester l'application](#8-tester-lapplication)
9. [Se connecter en SSH](#9-se-connecter-en-ssh)
10. [Detruire l'infrastructure](#10-detruire-linfrastructure)
11. [Comprendre les fichiers Terraform](#11-comprendre-les-fichiers-terraform)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Pre-requis

- Un **compte AWS** (le Free Tier suffit)
- Un **utilisateur IAM** avec les droits `AdministratorAccess`
- Les **Access Keys** de cet utilisateur (voir `02_configuration_credentials.md`)
- Avoir lu le **GUIDE_DEPLOIEMENT.md** du cours pour comprendre l'architecture

---

## 2. Installer Terraform

### Mac

**Option A : Homebrew (recommande)**

```bash
# Installer Homebrew si pas deja fait
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Installer Terraform
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
```

**Option B : Telechargement manuel**

```bash
# Telecharger depuis le site officiel
curl -O https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_darwin_amd64.zip

# Pour les Mac Apple Silicon (M1/M2/M3/M4) :
curl -O https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_darwin_arm64.zip

# Dezipper
unzip terraform_*.zip

# Deplacer dans le PATH
sudo mv terraform /usr/local/bin/

# Nettoyer
rm terraform_*.zip
```

### Windows

**Option A : Chocolatey (recommande)**

Ouvrir **PowerShell en Administrateur** :

```powershell
# Installer Chocolatey si pas deja fait
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Installer Terraform
choco install terraform -y
```

**Option B : Telechargement manuel**

1. Aller sur https://developer.hashicorp.com/terraform/install
2. Telecharger le fichier `.zip` pour Windows AMD64
3. Extraire le fichier `terraform.exe`
4. Deplacer `terraform.exe` dans un dossier du PATH, par exemple `C:\Windows\System32\`

   Ou creer un dossier dedie :
   ```powershell
   # Creer un dossier pour Terraform
   mkdir C:\terraform

   # Deplacer le .exe dedans
   Move-Item terraform.exe C:\terraform\

   # Ajouter au PATH (PowerShell Admin)
   [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\terraform", "Machine")
   ```

5. **Fermer et rouvrir** le terminal

### Verifier l'installation

```bash
terraform --version
```

Vous devez voir quelque chose comme :

```
Terraform v1.7.5
on darwin_arm64
```

---

## 3. Installer AWS CLI

### Mac

```bash
# Avec Homebrew
brew install awscli

# OU telechargement direct
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
rm AWSCLIV2.pkg
```

### Windows

1. Telecharger l'installeur : https://awscli.amazonaws.com/AWSCLIV2.msi
2. Double-cliquer sur le fichier `.msi`
3. Suivre l'assistant d'installation (Next, Next, Install)
4. **Fermer et rouvrir** le terminal

### Verifier

```bash
aws --version
```

---

## 4. Configurer les credentials AWS

```bash
aws configure
```

Repondre aux 4 questions :

```
AWS Access Key ID [None]: VOTRE_ACCESS_KEY_ID
AWS Secret Access Key [None]: VOTRE_SECRET_ACCESS_KEY
Default region name [None]: eu-west-3
Default output format [None]: json
```

Verifier que ca marche :

```bash
aws sts get-caller-identity
```

Vous devez voir votre Account ID et votre ARN.

---

## 5. Creer une Key Pair SSH

La Key Pair permet de se connecter en SSH a l'instance EC2.

### Mac

```bash
# Creer la key pair dans AWS et sauvegarder la cle privee
aws ec2 create-key-pair \
  --key-name creativeflow-key \
  --query 'KeyMaterial' \
  --output text \
  --region eu-west-3 > ~/.ssh/creativeflow-key.pem

# Proteger le fichier (obligatoire pour SSH)
chmod 400 ~/.ssh/creativeflow-key.pem
```

### Windows (PowerShell)

```powershell
# Creer le dossier .ssh si necessaire
mkdir $env:USERPROFILE\.ssh -Force

# Creer la key pair dans AWS
aws ec2 create-key-pair `
  --key-name creativeflow-key `
  --query 'KeyMaterial' `
  --output text `
  --region eu-west-3 | Out-File -Encoding ascii $env:USERPROFILE\.ssh\creativeflow-key.pem
```

> **Note** : Si la key pair `creativeflow-key` existe deja, supprimez-la d'abord :
> ```bash
> aws ec2 delete-key-pair --key-name creativeflow-key --region eu-west-3
> ```

---

## 6. Configurer le projet Terraform

### Naviguer dans le dossier

**Mac :**

```bash
cd chemin/vers/CreativeFlow_management_system/terraform
```

**Windows :**

```powershell
cd chemin\vers\CreativeFlow_management_system\terraform
```

### Creer le fichier de variables

**Mac / Linux :**

```bash
cp terraform.tfvars.example terraform.tfvars
```

**Windows :**

```powershell
copy terraform.tfvars.example terraform.tfvars
```

### Editer terraform.tfvars

Ouvrez `terraform.tfvars` dans votre editeur et modifiez si besoin :

```hcl
# Region AWS (Paris par defaut)
aws_region = "eu-west-3"

# Nom de votre key pair SSH (celui cree a l'etape 5)
key_name = "creativeflow-key"

# Type d'instance (t2.micro = gratuit avec Free Tier)
instance_type = "t2.micro"

# Role IAM : "Developer" (acces complet) ou "Contributor" (acces restreint)
iam_role = "Developer"
```

> **Astuce** : Pour tester les differences de permissions, deployez d'abord avec `Developer`, testez, puis `terraform destroy`, changez en `Contributor` et re-deployez.

---

## 7. Deployer l'infrastructure

### Etape 1 : Initialiser Terraform

```bash
terraform init
```

Terraform telecharge le provider AWS. Vous devez voir :

```
Terraform has been successfully initialized!
```

### Etape 2 : Previsualiser les changements

```bash
terraform plan
```

Terraform affiche tout ce qu'il va creer :

```
Plan: 17 to add, 0 to change, 0 to destroy.
```

Vous devez voir **17 ressources** a creer. Lisez le plan pour verifier que tout est correct.

### Etape 3 : Deployer

```bash
terraform apply
```

Terraform re-affiche le plan puis demande confirmation :

```
Do you want to perform these actions?
  Enter a value: yes
```

Tapez `yes` et appuyez sur Entree.

Le deploiement prend environ **2-3 minutes**. A la fin vous verrez les outputs :

```
Apply complete! Resources: 17 added, 0 changed, 0 destroyed.

Outputs:

admin_ip_detected  = "82.67.xxx.xxx"
app_url            = "http://13.36.xxx.xxx:5000"
iam_role_used      = "CreativeFlow-Developer"
instance_id        = "i-0abc123def456"
instance_public_ip = "13.36.xxx.xxx"
s3_bucket_name     = "creativeflow-docs-a1b2c3d4"
security_group_id  = "sg-0abc123def456"
ssh_command        = "ssh -i ~/.ssh/creativeflow-key.pem ec2-user@13.36.xxx.xxx"
```

### Etape 4 : Attendre le demarrage de l'application

L'instance EC2 a besoin de **2-3 minutes supplementaires** pour :
- Installer les paquets
- Configurer l'application Flask
- Demarrer le service

Vous pouvez verifier avec :

```bash
# Revoir les outputs a tout moment
terraform output

# Tester si l'app repond
curl http://$(terraform output -raw instance_public_ip):5000/health
```

Quand l'app est prete, vous recevez :

```json
{"status":"healthy"}
```

---

## 8. Tester l'application

### 8.1 Recuperer l'IP

```bash
terraform output app_url
```

Stockez l'IP dans une variable pour simplifier les tests :

**Mac / Linux :**
```bash
export IP=$(terraform output -raw instance_public_ip)
```

**Windows (PowerShell) :**
```powershell
$IP = terraform output -raw instance_public_ip
```

### 8.2 Tests en ligne de commande (curl)

Attendez 2-3 minutes apres le `terraform apply`, puis lancez les tests un par un.

**Test 1 : Health check (sans authentification)**

```bash
curl -s http://$IP:5000/health
```

Resultat attendu :
```json
{"status":"healthy"}
```

**Test 2 : Authentification developer**

```bash
curl -s -o /dev/null -w "HTTP %{http_code}" -u developer:dev123 http://$IP:5000/
```

Resultat attendu : `HTTP 200`

**Test 3 : Authentification contributor**

```bash
curl -s -o /dev/null -w "HTTP %{http_code}" -u contributor:contrib123 http://$IP:5000/
```

Resultat attendu : `HTTP 200`

**Test 4 : Mauvais mot de passe**

```bash
curl -s -o /dev/null -w "HTTP %{http_code}" -u developer:wrongpassword http://$IP:5000/
```

Resultat attendu : `HTTP 401`

**Test 5 : Upload un fichier (developer)**

```bash
echo "Ceci est un fichier de test" > /tmp/test.txt
curl -s -u developer:dev123 \
  -F "file=@/tmp/test.txt" \
  -F "category=drafts" \
  http://$IP:5000/upload
```

Resultat attendu :
```json
{"category":"drafts","file":"test.txt","message":"Fichier uploade avec succes"}
```

**Test 6 : Lister les fichiers**

```bash
curl -s -u developer:dev123 http://$IP:5000/files
```

Resultat attendu :
```json
{"files":[{"key":"uploads/drafts/test.txt","last_modified":"...","name":"test.txt","size":28}]}
```

**Test 7 : Acces aux logs (developer) - DOIT REUSSIR**

```bash
curl -s -u developer:dev123 http://$IP:5000/logs
```

Resultat attendu :
```json
{"access":"granted","logs":["app-logs/"],"user":"developer"}
```

**Test 8 : Acces aux logs (contributor) - DOIT ECHOUER**

```bash
curl -s -u contributor:contrib123 http://$IP:5000/logs
```

Resultat attendu :
```json
{"access":"denied","error":"Acces refuse - Role developer requis"}
```

**Test 9 : Upload en tant que contributor**

```bash
echo "Fichier contributor" > /tmp/contrib.txt
curl -s -u contributor:contrib123 \
  -F "file=@/tmp/contrib.txt" \
  -F "category=final" \
  http://$IP:5000/upload
```

Resultat attendu :
```json
{"category":"final","file":"contrib.txt","message":"Fichier uploade avec succes"}
```

**Test 10 : Verifier la configuration S3**

```bash
# Verifier que le bucket existe et que le versioning est actif
aws s3api get-bucket-versioning \
  --bucket $(terraform output -raw s3_bucket_name) \
  --region eu-west-3
```

Resultat attendu :
```json
{"Status": "Enabled"}
```

**Test 11 : Verifier les roles IAM**

```bash
aws iam get-role --role-name CreativeFlow-Developer --query 'Role.RoleName' --output text
aws iam get-role --role-name CreativeFlow-Contributor --query 'Role.RoleName' --output text
```

Resultat attendu :
```
CreativeFlow-Developer
CreativeFlow-Contributor
```

### 8.3 Tableau recapitulatif des tests

| # | Test | Commande | Resultat attendu |
|---|------|----------|-----------------|
| 1 | Health check | `curl /health` | `{"status":"healthy"}` |
| 2 | Auth developer | `curl -u developer:dev123 /` | HTTP 200 |
| 3 | Auth contributor | `curl -u contributor:contrib123 /` | HTTP 200 |
| 4 | Mauvais mdp | `curl -u developer:wrong /` | HTTP 401 |
| 5 | Upload (developer) | `curl -F file=@test.txt /upload` | `"Fichier uploade avec succes"` |
| 6 | Liste fichiers | `curl /files` | Liste JSON des fichiers |
| 7 | Logs (developer) | `curl /logs` | `"access":"granted"` |
| 8 | Logs (contributor) | `curl /logs` | `"access":"denied"` (HTTP 403) |
| 9 | Upload (contributor) | `curl -F file=@test.txt /upload` | `"Fichier uploade avec succes"` |
| 10 | S3 versioning | `aws s3api get-bucket-versioning` | `"Status": "Enabled"` |
| 11 | Roles IAM | `aws iam get-role` | Les 2 roles existent |

### 8.4 Tests dans le navigateur

> **Lien avec le cours** : ces tests sont les memes que dans la section 6 "Verification et Tests" du [GUIDE_DEPLOIEMENT.md](../GUIDE_DEPLOIEMENT.md). Ils demontrent la **defense en profondeur** : l'application Flask controle l'acces (couche 1), et le role IAM limite les operations S3 (couche 2).

Ouvrez `http://IP:5000` dans votre navigateur. Une fenetre de connexion (HTTP Basic Auth) apparait :

| Utilisateur | Mot de passe | Role |
|-------------|-------------|------|
| `developer` | `dev123` | Developer (acces complet) |
| `contributor` | `contrib123` | Contributor (acces restreint) |

1. **Connectez-vous en `developer`** :
   - Uploadez un fichier dans la categorie "Brouillons"
   - Cliquez "Tester Acces aux Logs" -> le message doit etre VERT

2. **Deconnectez-vous** (fermez le navigateur ou ouvrez un onglet prive)

3. **Connectez-vous en `contributor`** :
   - Uploadez un fichier -> ca doit fonctionner
   - Cliquez "Tester Acces aux Logs" -> le message doit etre ROUGE (403 Forbidden)

### 8.5 Tester avec un role Contributor au niveau IAM (exercice avance)

> **Lien avec le cours** : dans le guide de deploiement original, on peut lancer `IAM_ROLE=CreativeFlow-Contributor ./scripts/deploy-ec2.sh` pour deployer avec le role restreint. Avec Terraform, on change simplement une variable.

Pour voir la **double couche de securite** (app + IAM), re-deployez avec le role Contributor :

```bash
# Modifier terraform.tfvars : changer iam_role = "Contributor"

# Re-deployer
terraform apply
```

Maintenant, l'instance EC2 a le role `CreativeFlow-Contributor`. Testez :

1. Connectez-vous en tant que `developer` (couche app = acces complet)
2. Uploadez un fichier -> ca marche (le role Contributor autorise l'upload dans `uploads/`)
3. Cliquez "Tester Acces aux Logs" -> la couche app dit OK, mais le **role IAM bloque** l'acces a `app-logs/`

C'est la demonstration de la **defense en profondeur** : meme si la couche applicative est compromise, le role IAM empeche l'acces aux donnees sensibles.

> **Rappel du cours** : le role Contributor a un **Deny explicite** sur `app-logs/*`.
> Un Deny est TOUJOURS prioritaire sur un Allow. Voir [EXPLICATION_POLICIES.md](../aws-config/iam-policies/EXPLICATION_POLICIES.md) pour les details.

---

## 9. Se connecter en SSH

### Mac

```bash
# Utiliser la commande donnee par terraform output
ssh -i ~/.ssh/creativeflow-key.pem ec2-user@$(terraform output -raw instance_public_ip)
```

### Windows (PowerShell)

```powershell
ssh -i $env:USERPROFILE\.ssh\creativeflow-key.pem ec2-user@$(terraform output -raw instance_public_ip)
```

### Commandes utiles une fois connecte

```bash
# Verifier le statut de l'application
sudo systemctl status creativeflow

# Voir les logs de l'application
sudo journalctl -u creativeflow -f

# Verifier le role IAM de l'instance
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Tester l'acces S3
aws s3 ls
```

---

## 10. Detruire l'infrastructure

**IMPORTANT** : Pour eviter les couts AWS, detruisez tout quand vous avez fini !

### Etape 1 : Vider le bucket S3

Si vous avez uploade des fichiers pendant vos tests, le bucket n'est pas vide.
Terraform ne peut pas supprimer un bucket non vide, il faut le vider d'abord :

```bash
# Recuperer le nom du bucket
export BUCKET=$(terraform output -raw s3_bucket_name)

# Supprimer tous les objets
aws s3 rm s3://$BUCKET --recursive --region eu-west-3

# Supprimer aussi les versions (car le versioning est active)
aws s3api list-object-versions --bucket $BUCKET --region eu-west-3 \
  --query 'Versions[].{Key:Key,VersionId:VersionId}' --output json | \
  python3 -c "
import json, sys, subprocess
versions = json.load(sys.stdin)
if versions:
    for v in versions:
        subprocess.run([
            'aws', 's3api', 'delete-object',
            '--bucket', '$BUCKET',
            '--key', v['Key'],
            '--version-id', v['VersionId'],
            '--region', 'eu-west-3'
        ], capture_output=True)
    print(f'{len(versions)} versions supprimees')
else:
    print('Aucune version restante')
"

# Supprimer les delete markers
aws s3api list-object-versions --bucket $BUCKET --region eu-west-3 \
  --query 'DeleteMarkers[].{Key:Key,VersionId:VersionId}' --output json | \
  python3 -c "
import json, sys, subprocess
markers = json.load(sys.stdin)
if markers:
    for m in markers:
        subprocess.run([
            'aws', 's3api', 'delete-object',
            '--bucket', '$BUCKET',
            '--key', m['Key'],
            '--version-id', m['VersionId'],
            '--region', 'eu-west-3'
        ], capture_output=True)
    print(f'{len(markers)} delete markers supprimes')
else:
    print('Aucun delete marker')
"
```

> **Pourquoi c'est necessaire ?** Le versioning est active sur le bucket (pour la securite).
> Quand on supprime un fichier, AWS garde une "version" et un "delete marker".
> Il faut tout supprimer explicitement pour que le bucket soit vraiment vide.

### Etape 2 : Terraform destroy

```bash
terraform destroy
```

Terraform affiche tout ce qu'il va supprimer, puis demande confirmation :

```
Plan: 0 to add, 0 to change, 17 to destroy.

Do you really want to destroy all resources?
  Enter a value: yes
```

Tapez `yes`. Tout est supprime en **1-2 minutes**.

```
Destroy complete! Resources: 17 destroyed.
```

### Etape 3 : Supprimer la Key Pair

```bash
aws ec2 delete-key-pair --key-name creativeflow-key --region eu-west-3
```

Et le fichier local :

**Mac :**
```bash
chmod 600 ~/.ssh/creativeflow-key.pem
rm ~/.ssh/creativeflow-key.pem
```

**Windows :**
```powershell
del $env:USERPROFILE\.ssh\creativeflow-key.pem
```

### Verification finale

```bash
# Verifier qu'il ne reste rien
aws ec2 describe-instances --region eu-west-3 \
  --filters "Name=tag:Project,Values=CreativeFlow" \
  --query 'Reservations[].Instances[].State.Name' --output text

# Doit retourner "terminated" ou rien
```

---

## 11. Comprendre les fichiers Terraform

```
terraform/
  provider.tf              # Configuration du provider AWS
  variables.tf             # Declaration des variables
  terraform.tfvars         # Vos valeurs (a creer depuis .example)
  data.tf                  # Sources de donnees (AMI, VPC, IP)
  iam.tf                   # Roles IAM Developer et Contributor
  s3.tf                    # Bucket S3 avec securite
  security_group.tf        # Regles de firewall
  ec2.tf                   # Instance EC2
  user-data.sh             # Script d'installation de l'app
  outputs.tf               # Informations affichees apres deploiement
```

### Que fait chaque fichier ?

#### `iam.tf` - Les roles IAM (equivalent de `setup-iam.sh`)

C'est le coeur de la securite du lab. Ce fichier cree :

- **Trust Policy** : autorise le service EC2 a assumer les roles (= `trust-policy-ec2.json` du cours)
- **Role Developer** : acces complet aux buckets `creativeflow-docs-*`, describe EC2, CloudWatch Logs (= `developer-policy.json` du cours)
- **Role Contributor** : acces restreint a `uploads/` uniquement, avec 2 **Deny explicites** sur `app-logs/` et `DeleteObject` (= `contributor-policy.json` du cours)
- **Instance Profiles** : attachent les roles aux instances EC2

> **Concept cle du cours** : le Deny explicite est toujours prioritaire sur le Allow.
> Voir [EXPLICATION_POLICIES.md](../aws-config/iam-policies/EXPLICATION_POLICIES.md) pour les details.

#### `s3.tf` - Le bucket S3 (equivalent de `setup-s3.sh`)

Configure le stockage securise :

- **Versioning** : protege contre la suppression accidentelle (on peut recuperer les anciennes versions)
- **Block Public Access** : empeche toute exposition publique du bucket
- **Bucket Policy SSL** : refuse les requetes non-HTTPS (chiffrement en transit)
- **Structure de dossiers** : `uploads/drafts/`, `uploads/final/`, `uploads/client-assets/`, `app-logs/`

> **Concept cle du cours** : la defense en profondeur. Meme si un role IAM autorise l'acces, la bucket policy bloque les connexions non-SSL.

#### `security_group.tf` - Le firewall (equivalent de `setup-security-group.sh`)

Definit les regles reseau :

| Port | Ouvert a | Pourquoi |
|------|----------|----------|
| 22 (SSH) | Votre IP uniquement | Administration - restreint pour la securite |
| 5000 (Flask) | Tout le monde | L'application web |
| 80 (HTTP) | Tout le monde | Redirection future vers HTTPS |
| 443 (HTTPS) | Tout le monde | Support futur reverse proxy |

> **Concept cle du cours** : le principe du moindre privilege applique au reseau. SSH n'est ouvert qu'a votre IP, pas a tout internet.

#### `ec2.tf` - L'instance EC2 (equivalent de `deploy-ec2.sh`)

Lance une instance avec :

- **AMI Amazon Linux 2023** : detectee automatiquement (la plus recente)
- **t2.micro** : eligible au Free Tier
- **IAM Instance Profile** : le role Developer OU Contributor selon votre choix dans `terraform.tfvars`
- **User Data** : script qui installe et lance l'application au demarrage

> **Concept cle du cours** : l'instance n'a PAS de credentials AWS codees en dur. Elle utilise le role IAM qui lui fournit des credentials temporaires automatiquement. C'est la bonne pratique AWS.

#### `user-data.sh` - Le bootstrap (equivalent de `user-data.sh` du cours)

Script execute au premier demarrage de l'instance. Il :

1. Met a jour le systeme
2. Installe Python 3, pip, git
3. Cree l'application Flask (`app.py`) avec l'authentification HTTP Basic
4. Cree le template HTML (`index.html`) avec l'interface d'upload et le test d'acces aux logs
5. Installe les dependances (flask, boto3, gunicorn)
6. Cree et demarre un service systemd

> **Concept cle du cours** : l'app a 2 couches de securite.
> **Couche 1 (app)** : l'utilisateur `contributor` recoit un 403 sur la route `/logs`.
> **Couche 2 (IAM)** : meme si la couche app etait contournee, le role IAM Contributor a un Deny explicite sur `app-logs/`.

#### `data.tf` - Les sources de donnees (pas d'equivalent script)

Detecte automatiquement :
- Le **VPC par defaut** de votre compte
- L'**AMI Amazon Linux 2023** la plus recente
- Votre **IP publique** (pour restreindre SSH)

#### `outputs.tf` - Les sorties (pas d'equivalent script)

Affiche apres le deploiement : l'URL de l'app, l'IP, la commande SSH, le nom du bucket, etc.

### Avantage de Terraform vs scripts shell du cours

| | Scripts Shell (cours) | Terraform |
|---|---|---|
| **Deploiement** | 4 scripts a lancer dans l'ordre | 1 seule commande `terraform apply` |
| **Etat** | Aucun suivi (on ne sait pas ce qui est deploye) | Fichier `terraform.tfstate` |
| **Idempotence** | A gerer soi-meme (erreur si la ressource existe deja) | Automatique (Terraform sait ce qui existe) |
| **Suppression** | Script `cleanup.sh` (peut echouer si l'ordre est mauvais) | `terraform destroy` (gere les dependances) |
| **Previsualisation** | Impossible | `terraform plan` (voir avant de faire) |
| **Reproductibilite** | Fragile (depend de l'environnement) | Garantie (meme config = meme resultat) |
| **Dependances** | Gerees manuellement (lancer S3 avant EC2) | Automatiques (Terraform calcule l'ordre) |
| **Multiplateforme** | Bash uniquement (Mac/Linux/WSL) | Mac, Windows, Linux natif |

### Les 17 ressources creees par Terraform

Pour reference, voici le detail des 17 ressources :

| # | Ressource | Type AWS |
|---|-----------|----------|
| 1 | Suffixe unique pour le nom du bucket | `random_id` |
| 2 | Role IAM Developer | `aws_iam_role` |
| 3 | Role IAM Contributor | `aws_iam_role` |
| 4 | Policy Developer | `aws_iam_role_policy` |
| 5 | Policy Contributor | `aws_iam_role_policy` |
| 6 | Instance Profile Developer | `aws_iam_instance_profile` |
| 7 | Instance Profile Contributor | `aws_iam_instance_profile` |
| 8 | Bucket S3 | `aws_s3_bucket` |
| 9 | Versioning S3 | `aws_s3_bucket_versioning` |
| 10 | Block Public Access | `aws_s3_bucket_public_access_block` |
| 11 | Bucket Policy (SSL) | `aws_s3_bucket_policy` |
| 12 | Dossier uploads/drafts/ | `aws_s3_object` |
| 13 | Dossier uploads/final/ | `aws_s3_object` |
| 14 | Dossier uploads/client-assets/ | `aws_s3_object` |
| 15 | Dossier app-logs/ | `aws_s3_object` |
| 16 | Security Group | `aws_security_group` |
| 17 | Instance EC2 | `aws_instance` |

---

## 12. Troubleshooting

### "Error: No valid credential sources found"

AWS CLI n'est pas configure.

```bash
aws configure
# Entrez vos Access Key ID et Secret Access Key
```

### "Error: creating EC2 Instance: UnauthorizedOperation"

Votre utilisateur IAM n'a pas les permissions. Verifiez qu'il a `AdministratorAccess`.

### "Error: InvalidKeyPair.NotFound"

La key pair n'existe pas dans la bonne region.

```bash
# Verifier les key pairs dans eu-west-3
aws ec2 describe-key-pairs --region eu-west-3

# Si manquante, la recreer (voir etape 5)
```

### "Error: creating IAM Role: EntityAlreadyExists"

Le role existe deja d'un deploiement precedent.

```bash
# Option 1 : importer dans Terraform
terraform import aws_iam_role.developer CreativeFlow-Developer
terraform import aws_iam_role.contributor CreativeFlow-Contributor

# Option 2 : supprimer manuellement puis re-deployer
aws iam delete-role-policy --role-name CreativeFlow-Developer --policy-name CreativeFlow-Developer-Policy
aws iam remove-role-from-instance-profile --instance-profile-name CreativeFlow-Developer --role-name CreativeFlow-Developer
aws iam delete-instance-profile --instance-profile-name CreativeFlow-Developer
aws iam delete-role --role-name CreativeFlow-Developer
# Meme chose pour Contributor...
```

### L'application ne repond pas sur le port 5000

Attendez 3-5 minutes apres le `terraform apply`. Puis :

```bash
# Connectez-vous en SSH
ssh -i ~/.ssh/creativeflow-key.pem ec2-user@IP_PUBLIQUE

# Verifiez le service
sudo systemctl status creativeflow

# Voir les logs de demarrage (user-data)
sudo cat /var/log/cloud-init-output.log
```

### "Connection refused" sur SSH

Votre IP publique a peut-etre change. Re-deployez pour mettre a jour le security group :

```bash
terraform apply
```

### Terraform est bloque / plante

```bash
# Forcer le deverrouillage de l'etat (si bloque)
terraform force-unlock LOCK_ID

# Rafraichir l'etat
terraform refresh
```

---

## Resume des commandes

```bash
# --- INSTALLATION ---
brew install hashicorp/tap/terraform     # Mac
choco install terraform -y               # Windows

# --- DEPLOIEMENT ---
cd terraform/
cp terraform.tfvars.example terraform.tfvars   # Configurer
terraform init                                  # Initialiser
terraform plan                                  # Previsualiser
terraform apply                                 # Deployer (17 ressources)
terraform output                                # Voir les infos

# --- TESTS RAPIDES ---
export IP=$(terraform output -raw instance_public_ip)
curl -s http://$IP:5000/health                                   # Health check
curl -s -u developer:dev123 http://$IP:5000/files                # Lister fichiers
curl -s -u developer:dev123 http://$IP:5000/logs                 # Logs (OK)
curl -s -u contributor:contrib123 http://$IP:5000/logs           # Logs (403)
echo "test" > /tmp/t.txt && curl -s -u developer:dev123 \
  -F "file=@/tmp/t.txt" -F "category=drafts" http://$IP:5000/upload  # Upload

# --- NETTOYAGE ---
export BUCKET=$(terraform output -raw s3_bucket_name)
aws s3 rm s3://$BUCKET --recursive --region eu-west-3  # Vider le bucket
terraform destroy                                       # Tout supprimer (17 ressources)
aws ec2 delete-key-pair --key-name creativeflow-key --region eu-west-3  # Supprimer la key
```
