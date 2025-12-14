# Explication des Politiques IAM

## Version "2012-10-17"

```json
{
    "Version": "2012-10-17",
    ...
}
```

### Définition

La valeur `"2012-10-17"` est l'**identifiant de version du langage de politique IAM** d'AWS. Il s'agit de la version du format utilisé pour écrire les politiques, et non d'une date d'expiration.

### Historique des versions

| Version | Description |
|---------|-------------|
| `2012-10-17` | Version actuelle et recommandée. Support des variables de politique et opérateurs de condition avancés. |
| `2008-10-17` | Version obsolète. Fonctionnalités limitées, non recommandée. |

### Fonctionnalités de la version 2012-10-17

- Variables de politique (`${aws:username}`, `${aws:sourceIp}`, etc.)
- Opérateurs de condition avancés
- Gestion des ressources multiples
- Support des actions avec wildcards

**Documentation** : https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html

---

## Structure d'une Politique IAM

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "IdentifiantUnique",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::mon-bucket/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "true"
                }
            }
        }
    ]
}
```

### Éléments

| Élément | Obligatoire | Description |
|---------|-------------|-------------|
| `Version` | Oui | Version du langage de politique |
| `Statement` | Oui | Liste des déclarations (règles) |
| `Sid` | Non | Identifiant unique pour la documentation |
| `Effect` | Oui | `Allow` ou `Deny` |
| `Action` | Oui | Actions autorisées ou refusées |
| `Resource` | Oui | Ressources concernées (format ARN) |
| `Condition` | Non | Conditions d'application de la règle |

---

## Analyse de developer-policy.json

```json
{
    "Sid": "S3FullAccessToCreativeFlowBucket",
    "Effect": "Allow",
    "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
    ],
    "Resource": [
        "arn:aws:s3:::creativeflow-docs-*",
        "arn:aws:s3:::creativeflow-docs-*/*"
    ]
}
```

### Actions S3

| Action | Description |
|--------|-------------|
| `s3:GetObject` | Lecture d'un fichier |
| `s3:PutObject` | Écriture d'un fichier |
| `s3:DeleteObject` | Suppression d'un fichier |
| `s3:ListBucket` | Liste du contenu du bucket |

### Format ARN (Amazon Resource Name)

```
arn:aws:s3:::mon-bucket/dossier/fichier.txt
│   │   │   │          │
│   │   │   │          └── Chemin de l'objet
│   │   │   └── Nom du bucket
│   │   └── Service
│   └── Partition
└── Préfixe ARN
```

| Exemple ARN | Cible |
|-------------|-------|
| `arn:aws:s3:::mon-bucket` | Le bucket uniquement |
| `arn:aws:s3:::mon-bucket/*` | Tous les objets du bucket |
| `arn:aws:s3:::mon-bucket/uploads/*` | Objets dans le dossier uploads/ |
| `arn:aws:s3:::creativeflow-docs-*` | Tout bucket commençant par creativeflow-docs- |

---

## Analyse de contributor-policy.json

### Restriction par condition

```json
{
    "Sid": "S3ListUploadsFolder",
    "Effect": "Allow",
    "Action": "s3:ListBucket",
    "Resource": "arn:aws:s3:::creativeflow-docs-*",
    "Condition": {
        "StringLike": {
            "s3:prefix": ["uploads/*"]
        }
    }
}
```

La condition `StringLike` limite l'action `ListBucket` aux objets dont le préfixe correspond à `uploads/*`. Sans cette condition, le listing serait possible sur tout le bucket, y compris `app-logs/`.

### Deny explicite

```json
{
    "Sid": "DenyAppLogsAccess",
    "Effect": "Deny",
    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::creativeflow-docs-*/app-logs/*"]
}
```

Un `Deny` explicite est prioritaire sur tout `Allow`. Cette règle garantit l'impossibilité d'accès au dossier `app-logs/` même si une autre politique autorise l'accès.

### Ordre d'évaluation des politiques IAM

```
1. Deny implicite par défaut (tout est refusé)
2. Si Allow trouvé → Autorisé
3. Si Deny explicite trouvé → Refusé (prioritaire sur Allow)
```

| Situation | Résultat |
|-----------|----------|
| Aucune règle | Refusé (deny implicite) |
| Allow sans Deny | Autorisé |
| Allow + Deny explicite | Refusé (Deny prioritaire) |

---

## Analyse de trust-policy-ec2.json

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

### Fonction

La Trust Policy définit les entités autorisées à assumer le rôle IAM.

### Élément Principal

| Type de Principal | Exemple | Description |
|-------------------|---------|-------------|
| Service AWS | `"Service": "ec2.amazonaws.com"` | Instances EC2 |
| Service Lambda | `"Service": "lambda.amazonaws.com"` | Fonctions Lambda |
| Utilisateur | `"AWS": "arn:aws:iam::123456789012:user/alice"` | Utilisateur spécifique |
| Compte | `"AWS": "arn:aws:iam::123456789012:root"` | Tout le compte AWS |

### Action sts:AssumeRole

L'action `sts:AssumeRole` autorise l'entité (ici le service EC2) à obtenir des credentials temporaires associées au rôle. Sans cette Trust Policy, l'attachement d'un rôle IAM à une instance EC2 est inopérant.

---

## Outils

| Outil | Lien |
|-------|------|
| IAM Policy Simulator | https://policysim.aws.amazon.com/ |
| AWS Policy Generator | https://awspolicygen.s3.amazonaws.com/policygen.html |

## Documentation

| Sujet | Lien |
|-------|------|
| Éléments de politique | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html |
| Actions par service | https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html |
| Bonnes pratiques IAM | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
