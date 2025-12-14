# CreativeFlow - Documentation de Sécurité

## Présentation

Ce document décrit les mesures de sécurité implémentées dans le système de gestion documentaire CreativeFlow, une plateforme sécurisée de partage de fichiers pour une agence marketing, construite sur AWS.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AWS Cloud                               │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                        VPC                              │    │
│  │  ┌───────────────────────────────────────────────────┐  │    │
│  │  │              Security Group                       │  │    │
│  │  │  ┌─────────────────────────────────────────────┐  │  │    │
│  │  │  │           Instance EC2                      │  │  │    │
│  │  │  │  ┌───────────────────────────────────────┐  │  │  │    │
│  │  │  │  │      Application Flask (Port 5000)    │  │  │  │    │
│  │  │  │  │              │                        │  │  │  │    │
│  │  │  │  │      Rôle IAM (Developer/Contributor) │  │  │  │    │
│  │  │  │  └───────────────────────────────────────┘  │  │  │    │
│  │  │  └─────────────────────────────────────────────┘  │  │    │
│  │  └───────────────────────────────────────────────────┘  │    │
│  │                         │                               │    │
│  │                         ▼                               │    │
│  │  ┌───────────────────────────────────────────────────┐  │    │
│  │  │                  Bucket S3                        │  │    │
│  │  │  ├── uploads/                                     │  │    │
│  │  │  │   ├── drafts/                                  │  │    │
│  │  │  │   ├── final/                                   │  │    │
│  │  │  │   └── client-assets/                           │  │    │
│  │  │  └── app-logs/                                    │  │    │
│  │  └───────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. Sécurité IAM (Identity and Access Management)

### 1.1 Principe du Moindre Privilège

Deux rôles IAM distincts sont implémentés, chacun avec les permissions minimales requises :

#### Rôle Developer (`CreativeFlow-Developer`)
| Permission | Ressource | Objectif |
|------------|-----------|----------|
| Accès complet S3 | `creativeflow-docs-*` | Gérer tous les fichiers y compris les logs |
| EC2 Describe | Toutes | Dépannage des problèmes d'instance |
| CloudWatch Logs | `/creativeflow/*` | Surveillance de l'application |
| STS GetCallerIdentity | * | Vérification du rôle |

#### Rôle Contributor (`CreativeFlow-Contributor`)
| Permission | Ressource | Objectif |
|------------|-----------|----------|
| S3 GetObject, PutObject | Dossiers `uploads/*` uniquement | Upload/téléchargement de fichiers |
| S3 ListBucket | Préfixe `uploads/*` uniquement | Afficher la liste des fichiers |
| **DENY** S3 tout | `app-logs/*` | Pas d'accès aux logs |
| **DENY** S3 DeleteObject | `*` | Impossible de supprimer des fichiers |

### 1.2 Politique de Confiance (Trust Policy)

Les deux rôles utilisent une politique de confiance EC2, permettant uniquement aux instances EC2 d'assumer ces rôles :

```json
{
    "Principal": {
        "Service": "ec2.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
}
```

### 1.3 Avantages de Sécurité
- Pas d'identifiants codés en dur dans le code de l'application
- Rotation automatique des identifiants via les rôles IAM
- Séparation claire des responsabilités entre les rôles
- Les instructions de refus explicites empêchent l'escalade de privilèges

---

## 2. Sécurité du Bucket S3

### 2.1 Configuration du Bucket

| Paramètre | Valeur | Objectif |
|-----------|--------|----------|
| Versioning | Activé | Protection contre la suppression accidentelle |
| Accès Public | Tout bloqué | Empêcher l'exposition des données |
| Application SSL | Requise | Chiffrer les données en transit |

### 2.2 Politique du Bucket

```json
{
    "Statement": [
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Condition": {
                "Bool": { "aws:SecureTransport": "false" }
            }
        }
    ]
}
```

### 2.3 Structure des Dossiers et Contrôle d'Accès

| Dossier | Developer | Contributor |
|---------|-----------|-------------|
| `uploads/drafts/` | Lecture/Écriture/Suppression | Lecture/Écriture |
| `uploads/final/` | Lecture/Écriture/Suppression | Lecture/Écriture |
| `uploads/client-assets/` | Lecture/Écriture/Suppression | Lecture/Écriture |
| `app-logs/` | Lecture/Écriture/Suppression | **AUCUN ACCÈS** |

---

## 3. Sécurité EC2

### 3.1 Règles du Security Group

#### Règles Entrantes
| Type | Port | Source | Objectif |
|------|------|--------|----------|
| SSH | 22 | IP Admin uniquement | Administration sécurisée |
| HTTP | 80 | 0.0.0.0/0 | Redirection vers HTTPS |
| HTTPS | 443 | 0.0.0.0/0 | Accès web sécurisé |
| TCP Personnalisé | 5000 | 0.0.0.0/0 | Application Flask |

#### Règles Sortantes
| Type | Port | Destination | Objectif |
|------|------|-------------|----------|
| Tout | Tout | 0.0.0.0/0 | Par défaut (tout autoriser) |

### 3.2 Configuration de l'Instance
- Utilise Amazon Linux 2023 (derniers correctifs)
- Rôle IAM attaché (pas de clés d'accès stockées)
- Paire de clés requise pour l'accès SSH
- Taggée pour le suivi des ressources

---

## 4. Sécurité de l'Application

### 4.1 Authentification HTTP Basic

L'application utilise une authentification HTTP Basic avec deux comptes utilisateurs :

| Utilisateur | Mot de passe | Rôle | Permissions |
|-------------|--------------|------|-------------|
| `developer` | `dev123` | developer | Accès complet (fichiers + logs) |
| `contributor` | `contrib123` | contributor | Fichiers uniquement (pas de logs) |

### 4.2 Décorateurs de Sécurité

```python
@requires_auth
def route_protegee():
    # Accessible par developer et contributor
    pass

@requires_developer
def route_developer_only():
    # Accessible uniquement par developer
    # Retourne 403 pour contributor
    pass
```

### 4.3 Double Couche de Sécurité

Le contrôle d'accès aux logs est appliqué à deux niveaux :

1. **Niveau Application** : Le décorateur `@requires_developer` bloque l'accès à `/logs` pour les contributors
2. **Niveau IAM** : La politique IAM `CreativeFlow-Contributor` contient un DENY explicite sur `app-logs/*`

Cette défense en profondeur garantit que même si une couche est contournée, l'autre reste active.

### 4.4 Sécurité des Uploads
- URLs présignées pour les téléchargements (durée limitée : 1 heure)
- Traitement des fichiers côté serveur
- Routage vers les dossiers basé sur la catégorie
- Journalisation des actions avec identité de l'utilisateur

---

## 5. Bonnes Pratiques de Sécurité Implémentées

### 5.1 Défense en Profondeur
```
Couche 1: Security Group (Réseau)
   └── Couche 2: Politiques IAM (Identité)
        └── Couche 3: Politique du Bucket S3 (Données)
             └── Couche 4: Logique Applicative (Contrôle d'Accès)
```

### 5.2 Checklist

- [x] **Pas de buckets S3 publics** - Tout accès public bloqué
- [x] **SSL/TLS imposé** - La politique du bucket refuse le non-HTTPS
- [x] **Moindre privilège** - Permissions minimales par rôle
- [x] **Pas d'identifiants codés en dur** - Rôles IAM utilisés
- [x] **Versioning activé** - Récupération des données possible
- [x] **SSH restreint** - IP admin uniquement
- [x] **Refus explicites** - Les Contributors ne peuvent pas accéder aux logs
- [x] **Tagging des ressources** - Toutes les ressources taggées pour le suivi

---

## 6. Tests des Contrôles d'Accès

### Test 1 : Accès aux Logs - Rôle Contributor
1. Déploiement EC2 avec le rôle `CreativeFlow-Contributor`
2. Accès à l'endpoint `/logs`
3. Résultat : `403 Forbidden - Accès refusé`

### Test 2 : Suppression de Fichiers - Rôle Contributor
1. Déploiement EC2 avec le rôle `CreativeFlow-Contributor`
2. Tentative de suppression d'un fichier via l'API S3
3. Résultat : Erreur `AccessDenied`

### Test 3 : Accès aux Logs - Rôle Developer
1. Déploiement EC2 avec le rôle `CreativeFlow-Developer`
2. Accès à l'endpoint `/logs`
3. Résultat : `200 OK` avec la liste des logs

---

## 7. Procédure de Nettoyage

**Exécution obligatoire après les tests pour éviter la facturation AWS.**

```bash
export S3_BUCKET_NAME=nom-du-bucket
export AWS_REGION=eu-west-3

./scripts/cleanup.sh
```

Ressources supprimées :
- Instances EC2 (taggées avec Project=CreativeFlow)
- Bucket S3 et tout son contenu
- Security Group
- Rôles IAM et Profils d'Instance

---

## 8. Recommandations pour la Production

1. **Ajouter HTTPS** - Utiliser ALB ou CloudFront avec certificat SSL
2. **Activer CloudTrail** - Auditer tous les appels API
3. **Activer la journalisation d'accès S3** - Suivre les accès au bucket
4. **Utiliser AWS WAF** - Protection contre les attaques web
5. **Activer GuardDuty** - Détection des menaces
6. **Implémenter MFA** - Pour l'accès à la console
7. **Utiliser Secrets Manager** - Pour les secrets de l'application
8. **Audits réguliers** - Réviser les politiques IAM périodiquement

---

## Annexe : Fichiers de Politique

Voir `aws-config/iam-policies/` pour les définitions complètes des politiques :
- `developer-policy.json`
- `contributor-policy.json`
- `trust-policy-ec2.json`
