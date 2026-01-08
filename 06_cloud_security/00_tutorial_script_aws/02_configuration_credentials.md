# Configuration des Credentials AWS

Ce guide explique comment configurer vos identifiants AWS pour utiliser AWS CLI et Boto3.

## Pourquoi des credentials ?

AWS doit savoir QUI fait les appels API pour :
- Vérifier que vous avez les permissions nécessaires
- Facturer le bon compte
- Tracer les actions (audit)

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   aws s3 ls │ ──────> │  Qui es-tu? │ ──────> │   Accès     │
│             │         │  Credentials│         │   Autorisé  │
└─────────────┘         └─────────────┘         └─────────────┘
```

---

## Les types de credentials

| Type | Utilisation | Durée |
|------|-------------|-------|
| **Access Keys** | Utilisateur IAM permanent | Illimitée (jusqu'à rotation) |
| **Session Token** | Credentials temporaires | 1h à 12h |
| **Role** | Instance EC2, Lambda | Automatique |

Pour ce tutoriel, on utilise les **Access Keys** (le plus simple pour débuter).

---

## Étape 1 : Créer un utilisateur IAM

**IMPORTANT** : Ne JAMAIS utiliser le compte root pour les tâches quotidiennes !

### Via la Console AWS

1. Connectez-vous à la console AWS : https://console.aws.amazon.com

2. Allez dans **IAM** (Identity and Access Management)

3. Cliquez sur **Users** > **Create user**

4. Donnez un nom : `mon-utilisateur-cli`

5. Cochez **Provide user access to the AWS Management Console** (optionnel)

6. Cliquez **Next**

7. Permissions :
   - Pour apprendre : **Attach policies directly** > **AdministratorAccess**
   - En production : utiliser des permissions minimales !

8. Cliquez **Create user**

### Créer les Access Keys

1. Cliquez sur l'utilisateur créé

2. Onglet **Security credentials**

3. Section **Access keys** > **Create access key**

4. Choisir **Command Line Interface (CLI)**

5. Cocher la confirmation et cliquer **Next**

6. **IMPORTANT** : Notez les deux valeurs :
   - **Access key ID** : `AKIAIOSFODNN7EXAMPLE`
   - **Secret access key** : `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

**Ces informations ne seront plus jamais affichées !**

---

## Étape 2 : Configurer AWS CLI

### Méthode 1 : Configuration interactive (Recommandé)

```bash
aws configure
```

Répondez aux questions :

```
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: eu-west-3
Default output format [None]: json
```

**Régions courantes** :
| Région | Code | Localisation |
|--------|------|--------------|
| Paris | `eu-west-3` | France |
| Irlande | `eu-west-1` | Europe |
| Francfort | `eu-central-1` | Allemagne |
| Virginie | `us-east-1` | USA (défaut AWS) |

**Formats de sortie** :
- `json` : Pour scripts et parsing
- `table` : Pour lecture humaine
- `text` : Pour grep/awk

### Méthode 2 : Fichiers de configuration manuels

AWS CLI utilise deux fichiers dans `~/.aws/` :

**~/.aws/credentials** (les secrets)
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**~/.aws/config** (la configuration)
```ini
[default]
region = eu-west-3
output = json
```

### Méthode 3 : Variables d'environnement

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="eu-west-3"
```

**Priorité des credentials** :
1. Variables d'environnement (priorité haute)
2. Fichier credentials
3. Fichier config
4. Role IAM (sur EC2)

---

## Étape 3 : Vérifier la configuration

### Test basique

```bash
# Qui suis-je ?
aws sts get-caller-identity
```

**Résultat attendu** :
```json
{
    "UserId": "AIDAIOSFODNN7EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/mon-utilisateur-cli"
}
```

### Tests supplémentaires

```bash
# Lister les buckets S3 (peut être vide)
aws s3 ls

# Lister les instances EC2 (peut être vide)
aws ec2 describe-instances

# Lister les utilisateurs IAM
aws iam list-users
```

Si ça marche, vous êtes configuré !

---

## Profils multiples

Vous pouvez avoir plusieurs comptes AWS (perso, travail, formation...).

### Créer un profil nommé

```bash
aws configure --profile formation
```

### Fichiers avec profils

**~/.aws/credentials**
```ini
[default]
aws_access_key_id = AKIADEFAULT...
aws_secret_access_key = secret1...

[formation]
aws_access_key_id = AKIAFORMATION...
aws_secret_access_key = secret2...

[production]
aws_access_key_id = AKIAPROD...
aws_secret_access_key = secret3...
```

**~/.aws/config**
```ini
[default]
region = eu-west-3
output = json

[profile formation]
region = eu-west-3
output = table

[profile production]
region = eu-west-1
output = json
```

### Utiliser un profil

```bash
# Option --profile
aws s3 ls --profile formation

# Ou variable d'environnement
export AWS_PROFILE=formation
aws s3 ls
```

---

## Sécurité des credentials

### Ce qu'il ne faut JAMAIS faire

```bash
# NE JAMAIS commiter les credentials dans git !
git add ~/.aws/credentials  # DANGER !

# NE JAMAIS mettre dans le code
aws_secret = "wJalrXUtn..."  # DANGER !

# NE JAMAIS partager par email/chat
```

### Bonnes pratiques

1. **Ajouter au .gitignore**
   ```
   .aws/
   *.pem
   *credentials*
   ```

2. **Utiliser des roles IAM sur EC2** au lieu de credentials

3. **Rotation régulière** des access keys (tous les 90 jours)

4. **Permissions minimales** (principe du moindre privilège)

5. **Activer MFA** sur les comptes privilégiés

### Vérifier les fuites

```bash
# Voir les access keys actives
aws iam list-access-keys --user-name mon-utilisateur-cli

# Supprimer une ancienne key
aws iam delete-access-key --user-name mon-utilisateur-cli --access-key-id AKIAOLD...
```

---

## Configuration pour Boto3 (Python)

Boto3 utilise **automatiquement** les mêmes credentials que AWS CLI !

```python
import boto3

# Utilise le profil [default]
s3 = boto3.client('s3')

# Utiliser un profil spécifique
session = boto3.Session(profile_name='formation')
s3 = session.client('s3')

# Spécifier une région
ec2 = boto3.client('ec2', region_name='eu-west-3')
```

---

## Troubleshooting

### "Unable to locate credentials"

```bash
# Vérifier les fichiers
cat ~/.aws/credentials
cat ~/.aws/config

# Vérifier les variables d'environnement
echo $AWS_ACCESS_KEY_ID
echo $AWS_DEFAULT_REGION
```

### "InvalidClientTokenId"

L'access key est invalide ou supprimée.
- Vérifier dans la console IAM
- Recréer les credentials

### "AccessDenied"

L'utilisateur n'a pas les permissions.
- Vérifier les policies attachées
- Ajouter les permissions nécessaires

### "ExpiredToken"

Les credentials temporaires ont expiré.
- Se reconnecter ou rafraîchir le token

---

## Résumé

| Étape | Commande |
|-------|----------|
| Configurer | `aws configure` |
| Vérifier | `aws sts get-caller-identity` |
| Profil | `aws configure --profile nom` |
| Utiliser profil | `aws s3 ls --profile nom` |
| Voir config | `cat ~/.aws/config` |
| Voir credentials | `cat ~/.aws/credentials` |

---

## Prochaine étape

Maintenant que AWS CLI est configuré, voyons les concepts de base d'AWS.

Voir : **03_concepts_aws.md**
