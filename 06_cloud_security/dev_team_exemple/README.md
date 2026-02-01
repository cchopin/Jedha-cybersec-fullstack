# Terraform IAM lab : gestion d'une équipe de développement AWS

Ce projet Terraform déploie une infrastructure IAM complète pour une équipe de développement sur AWS. Il illustre les bonnes pratiques de gestion des accès : utilisateurs, groupes, policies et rôles.

## Contexte

L'objectif est de mettre en place une structure IAM pour une équipe de trois développeurs avec des responsabilités différentes :

| Utilisateur | Rôle | Groupes |
|-------------|------|---------|
| alice.developer | Senior Developer + DBA | Developers, DatabaseAdmins |
| bob.developer | Junior Developer | Developers |
| charlie.devops | DevOps Engineer | Developers, DeploymentTeam |

## Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │                      IAM Policies                      │
                    ├──────────────┬──────────────┬──────────────┬───────────┤
                    │ DeveloperPol │ DatabasePol  │ DeploymentPol│ EC2S3Pol  │
                    └──────┬───────┴──────┬───────┴──────┬───────┴─────┬─────┘
                           │              │              │             │
                    ┌──────▼───────┬──────▼────────┬─────▼─────────┐   │
                    │  Developers  │ DatabaseAdmins│DeploymentTeam │   │
                    │    Group     │    Group      │    Group      │   │
                    └──────┬───────┴──────┬────────┴─────┬─────────┘   │
                           │              │              │             │
              ┌────────────┼──────────────┼──────────────┤             │
              │            │              │              │             │
        ┌─────▼─────┐ ┌────▼────┐  ┌──────▼──────┐       │      ┌──────▼───────┐
        │   Alice   │ │   Bob   │  │   Charlie   │       │      │ EC2-S3-Access│
        │ Dev + DBA │ │   Dev   │  │   DevOps    │       │      │    Role      │
        └───────────┘ └─────────┘  └─────────────┘       │      └──────────────┘
                                                         │             │
                                                         │      ┌──────▼───────┐
                                                         │      │ EC2 Instance │
                                                         └──────► Profile      │
                                                                └──────────────┘
```

## Prérequis

- Terraform >= 1.0
- AWS CLI configuré avec des credentials ayant les droits administrateur
- Compte AWS

### Vérifier la configuration AWS

```bash
# Vérifier que les credentials sont en place
cat ~/.aws/credentials
cat ~/.aws/config

# Tester la connexion
aws sts get-caller-identity
```

## Structure du projet

```
terraform-iam-lab/
├── provider.tf      # Configuration du provider AWS
├── policies.tf      # Les 4 policies IAM (Developer, Database, Deployment, EC2S3)
├── groups.tf        # Les 3 groupes et leurs attachements de policies
├── users.tf         # Les 3 utilisateurs et leurs appartenances aux groupes
├── roles.tf         # Le rôle EC2-S3-Access et son instance profile
├── outputs.tf       # Sorties (mots de passe, URL console, etc.)
└── README.md
```

## Policies créées

### DeveloperPolicy

Permissions pour les ressources de développement :
- EC2 : lister et gérer des instances (limité aux types t2.micro, t2.small, t3.micro, t3.small)
- S3 : accès aux buckets commençant par `dev-`
- CloudWatch Logs : accès aux log groups commençant par `dev-`
- Lambda : gestion des fonctions commençant par `dev-`

### DatabasePolicy

Permissions pour l'administration des bases de données :
- RDS : gestion complète des instances taggées `Environment: dev*`
- DynamoDB : gestion des tables commençant par `dev-`
- AWS Backup : création et gestion des sauvegardes

### DeploymentPolicy

Permissions pour les déploiements :
- CodeDeploy : gestion des applications et déploiements
- ECR : push et pull d'images Docker
- ECS : gestion des services et tâches

### EC2S3AccessPolicy

Policy attachée au rôle EC2 pour permettre aux instances d'accéder aux buckets S3 de développement.

## Utilisation

### Initialisation

```bash
cd terraform-iam-lab
terraform init
```

### Prévisualisation des changements

```bash
terraform plan
```

### Déploiement

```bash
terraform apply
```

Terraform affichera les ressources à créer. Taper `yes` pour confirmer.

### Récupérer les mots de passe des utilisateurs

```bash
# Format JSON
terraform output -json user_passwords

# Mot de passe d'un utilisateur spécifique
terraform output -json user_passwords | jq -r '.alice'
```

### Récupérer l'URL de connexion

```bash
terraform output console_login_url
```

### Destruction de l'infrastructure

```bash
terraform destroy
```

## Tests post-déploiement

### Tester l'accès utilisateur

1. Se connecter à la console AWS avec l'URL fournie par `terraform output console_login_url`
2. Utiliser les credentials d'un utilisateur (alice.developer, bob.developer ou charlie.devops)
3. Changer le mot de passe temporaire
4. Vérifier les accès selon le rôle de l'utilisateur

### Tester le rôle EC2

1. Lancer une instance EC2 (t2.micro ou t3.micro)
2. Attacher le profil d'instance `EC2-S3-Access-Profile`
3. Se connecter à l'instance en SSH
4. Tester l'accès S3 :

```bash
# Créer un bucket de dev
aws s3 mb s3://dev-test-bucket-$(date +%s)

# Lister le contenu
aws s3 ls s3://dev-test-bucket-xxxxx/

# Upload un fichier
echo "test" > test.txt
aws s3 cp test.txt s3://dev-test-bucket-xxxxx/

# Vérifier que l'accès à un bucket non-dev est refusé
aws s3 ls s3://autre-bucket/  # Doit échouer
```

## Concepts IAM illustrés

### Principe du moindre privilège

Les policies sont restrictives et limitent l'accès aux seules ressources de développement (préfixe `dev-`). Les types d'instances EC2 sont également limités pour contrôler les coûts.

### Séparation des responsabilités

Chaque groupe a des permissions adaptées à son rôle :
- Les développeurs juniors n'ont pas accès aux bases de données
- Seuls les DevOps peuvent déployer
- Les DBA ont des permissions supplémentaires sur RDS et DynamoDB

### Héritage via les groupes

Les permissions sont attribuées aux groupes, pas directement aux utilisateurs. Cela facilite la gestion quand l'équipe évolue.

### Rôles pour les services

Les instances EC2 utilisent un rôle IAM plutôt que des credentials statiques. C'est plus sécurisé car les credentials sont temporaires et automatiquement renouvelés.

## Personnalisation

### Ajouter un utilisateur

Dans `users.tf`, ajouter :

```hcl
resource "aws_iam_user" "nouveau" {
  name = "nouveau.utilisateur"
  tags = {
    Role = "Description du rôle"
  }
}

resource "aws_iam_user_group_membership" "nouveau_groups" {
  user = aws_iam_user.nouveau.name
  groups = [
    aws_iam_group.developers.name
    # Ajouter d'autres groupes si nécessaire
  ]
}

resource "aws_iam_user_login_profile" "nouveau" {
  user                    = aws_iam_user.nouveau.name
  password_reset_required = true
}
```

### Modifier les permissions d'un groupe

Dans `groups.tf`, ajouter un `aws_iam_group_policy_attachment` supplémentaire ou modifier les policies dans `policies.tf`.

### Ajouter un nouveau groupe

```hcl
resource "aws_iam_group" "nouveau_groupe" {
  name = "NouveauGroupe"
}

resource "aws_iam_group_policy_attachment" "nouveau_groupe_policy" {
  group      = aws_iam_group.nouveau_groupe.name
  policy_arn = aws_iam_policy.une_policy.arn
}
```

## Sécurité

### Recommandations

- Activer MFA pour tous les utilisateurs (non inclus dans ce lab pour simplifier)
- Ne jamais commiter le fichier `terraform.tfstate` contenant les mots de passe
- Utiliser un backend distant (S3 + DynamoDB) pour le state en production
- Rotater régulièrement les credentials

### Fichiers sensibles à ne pas commiter

Ajouter au `.gitignore` :

```
*.tfstate
*.tfstate.*
.terraform/
*.tfvars
```

## Ressources

- [Documentation AWS IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Best practices IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

## Nettoyage

Ne pas oublier de détruire les ressources après les tests pour éviter des frais :

```bash
terraform destroy
```

Vérifier également dans la console AWS :
- Qu'aucune instance EC2 n'est encore en cours d'exécution
- Que les buckets S3 de test ont été supprimés
