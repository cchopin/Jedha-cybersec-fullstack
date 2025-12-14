# CreativeFlow - Système de Gestion Documentaire

Système de gestion documentaire sécurisé pour une agence marketing utilisant AWS S3, IAM et EC2.

## Documentation

| Document | Description |
|----------|-------------|
| [GUIDE_DEPLOIEMENT.md](GUIDE_DEPLOIEMENT.md) | Installation, configuration et déploiement |
| [SECURITY_DOCUMENTATION.md](SECURITY_DOCUMENTATION.md) | Architecture et mesures de sécurité |
| [aws-config/iam-policies/EXPLICATION_POLICIES.md](aws-config/iam-policies/EXPLICATION_POLICIES.md) | Explication des politiques IAM |

## Structure du Projet

```
CreativeFlow_management_system/
├── CreativeFlow/                 # Application Flask
│   ├── app.py
│   └── templates/index.html
├── aws-config/iam-policies/      # Politiques IAM
├── scripts/                      # Scripts de déploiement
│   ├── setup-s3.sh
│   ├── setup-iam.sh
│   ├── setup-security-group.sh
│   ├── deploy-ec2.sh
│   └── cleanup.sh
└── *.md                          # Documentation
```

## Déploiement

```bash
export AWS_REGION=eu-west-3
export S3_BUCKET_NAME=creativeflow-docs-$(date +%s)

chmod +x scripts/*.sh
./scripts/setup-s3.sh
./scripts/setup-iam.sh
./scripts/setup-security-group.sh
./scripts/deploy-ec2.sh
```

Instructions complètes : [GUIDE_DEPLOIEMENT.md](GUIDE_DEPLOIEMENT.md)

## Identifiants de Connexion

| Utilisateur | Mot de passe | Accès |
|-------------|--------------|-------|
| `developer` | `dev123` | Fichiers + Logs |
| `contributor` | `contrib123` | Fichiers uniquement |

## Nettoyage

```bash
./scripts/cleanup.sh
```
