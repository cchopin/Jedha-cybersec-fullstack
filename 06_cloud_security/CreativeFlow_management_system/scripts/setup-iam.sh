#!/bin/bash
# =============================================================================
# CreativeFlow - Script de Configuration IAM
# Crée les rôles IAM pour Developer et Contributor avec les politiques appropriées
# =============================================================================

set -e  # Arrêter en cas d'erreur

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
POLICIES_DIR="$PROJECT_DIR/aws-config/iam-policies"

echo "============================================="
echo "Configuration IAM CreativeFlow"
echo "============================================="

# Fonction pour créer un rôle avec sa politique
create_role() {
    local ROLE_NAME=$1
    local POLICY_FILE=$2
    local DESCRIPTION=$3

    echo ""
    echo "Création du rôle: $ROLE_NAME"
    echo "-------------------------------------------"

    # Vérifier si le rôle existe
    if aws iam get-role --role-name "$ROLE_NAME" 2>/dev/null; then
        echo "Le rôle $ROLE_NAME existe déjà, mise à jour de la politique..."

        # Mettre à jour la politique inline
        aws iam put-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-name "${ROLE_NAME}Policy" \
            --policy-document "file://${POLICY_FILE}"
    else
        # Créer le rôle
        aws iam create-role \
            --role-name "$ROLE_NAME" \
            --assume-role-policy-document "file://${POLICIES_DIR}/trust-policy-ec2.json" \
            --description "$DESCRIPTION" \
            --tags Key=Project,Value=CreativeFlow Key=Environment,Value=Production

        # Attacher la politique inline
        aws iam put-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-name "${ROLE_NAME}Policy" \
            --policy-document "file://${POLICY_FILE}"

        echo "Rôle $ROLE_NAME créé avec succès"
    fi

    # Créer le profil d'instance s'il n'existe pas
    if ! aws iam get-instance-profile --instance-profile-name "$ROLE_NAME" 2>/dev/null; then
        echo "Création du profil d'instance pour $ROLE_NAME..."
        aws iam create-instance-profile --instance-profile-name "$ROLE_NAME"
        aws iam add-role-to-instance-profile \
            --instance-profile-name "$ROLE_NAME" \
            --role-name "$ROLE_NAME"
        echo "Profil d'instance créé et rôle attaché"
    else
        echo "Le profil d'instance $ROLE_NAME existe déjà"
    fi
}

# Créer le rôle Developer
create_role \
    "CreativeFlow-Developer" \
    "${POLICIES_DIR}/developer-policy.json" \
    "Rôle avec accès complet pour les développeurs CreativeFlow - peut gérer toutes les ressources"

# Créer le rôle Contributor
create_role \
    "CreativeFlow-Contributor" \
    "${POLICIES_DIR}/contributor-policy.json" \
    "Rôle avec accès limité pour les contributeurs CreativeFlow - upload/download uniquement"

echo ""
echo "============================================="
echo "Configuration IAM Terminée !"
echo "============================================="
echo ""
echo "Rôles créés:"
echo "  1. CreativeFlow-Developer"
echo "     - Accès complet S3 aux buckets creativeflow-docs-*"
echo "     - Accès aux app-logs/"
echo "     - Permissions EC2 describe pour le dépannage"
echo "     - Accès CloudWatch Logs"
echo ""
echo "  2. CreativeFlow-Contributor"
echo "     - Upload/Download vers les dossiers uploads/* uniquement"
echo "     - PAS d'accès aux app-logs/"
echo "     - PAS de permissions de suppression"
echo ""
echo "Profils d'instance créés (pour EC2):"
echo "  - CreativeFlow-Developer"
echo "  - CreativeFlow-Contributor"
echo ""
echo "============================================="
