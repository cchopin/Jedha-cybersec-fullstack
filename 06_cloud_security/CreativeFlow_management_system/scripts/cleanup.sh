#!/bin/bash
# =============================================================================
# CreativeFlow - Script de Nettoyage
# Supprime toutes les ressources AWS creees pour ce projet
# =============================================================================

AWS_REGION="${AWS_REGION:-eu-west-3}"
S3_BUCKET_NAME="${S3_BUCKET_NAME:-}"

echo "============================================="
echo "Nettoyage des Ressources CreativeFlow"
echo "============================================="
echo ""
echo "ATTENTION : Ceci supprimera definitivement :"
echo "  - Toutes les instances EC2 taggees avec Project=CreativeFlow"
echo "  - Le bucket S3 : $S3_BUCKET_NAME (et tout son contenu)"
echo "  - Le Security Group : creativeflow-webapp-sg"
echo "  - Les roles IAM : CreativeFlow-Developer, CreativeFlow-Contributor"
echo ""
read -p "Etes-vous sur de vouloir continuer ? (oui/non) : " CONFIRM

if [ "$CONFIRM" != "oui" ]; then
    echo "Nettoyage annule."
    exit 0
fi

echo ""
echo "[1/5] Terminaison des instances EC2..."
INSTANCE_IDS=$(aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --filters "Name=tag:Project,Values=CreativeFlow" "Name=instance-state-name,Values=running,pending,stopped" \
    --query "Reservations[].Instances[].InstanceId" \
    --output text 2>/dev/null)

if [ -n "$INSTANCE_IDS" ] && [ "$INSTANCE_IDS" != "None" ]; then
    echo "Terminaison des instances : $INSTANCE_IDS"
    aws ec2 terminate-instances \
        --region "$AWS_REGION" \
        --instance-ids $INSTANCE_IDS

    echo "Attente de la terminaison des instances..."
    aws ec2 wait instance-terminated \
        --region "$AWS_REGION" \
        --instance-ids $INSTANCE_IDS
    echo "Instances terminees."
else
    echo "Aucune instance en cours d'execution trouvee."
fi

echo ""
echo "[2/5] Suppression du bucket S3..."
if [ -n "$S3_BUCKET_NAME" ]; then
    if aws s3api head-bucket --bucket "$S3_BUCKET_NAME" 2>/dev/null; then
        echo "Vidage du bucket : $S3_BUCKET_NAME"

        # Supprimer tous les objets
        aws s3 rm "s3://$S3_BUCKET_NAME" --recursive 2>/dev/null || true

        # Boucle pour supprimer toutes les versions
        echo "Suppression des versions..."
        while true; do
            VERSIONS=$(aws s3api list-object-versions \
                --bucket "$S3_BUCKET_NAME" \
                --max-items 1000 \
                --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' \
                --output json 2>/dev/null)

            if [ -z "$VERSIONS" ] || [ "$VERSIONS" = '{"Objects":null}' ] || [ "$VERSIONS" = '{"Objects":[]}' ]; then
                break
            fi

            aws s3api delete-objects \
                --bucket "$S3_BUCKET_NAME" \
                --delete "$VERSIONS" > /dev/null 2>&1 || break
        done

        # Boucle pour supprimer tous les delete markers
        echo "Suppression des delete markers..."
        while true; do
            DELETE_MARKERS=$(aws s3api list-object-versions \
                --bucket "$S3_BUCKET_NAME" \
                --max-items 1000 \
                --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' \
                --output json 2>/dev/null)

            if [ -z "$DELETE_MARKERS" ] || [ "$DELETE_MARKERS" = '{"Objects":null}' ] || [ "$DELETE_MARKERS" = '{"Objects":[]}' ]; then
                break
            fi

            aws s3api delete-objects \
                --bucket "$S3_BUCKET_NAME" \
                --delete "$DELETE_MARKERS" > /dev/null 2>&1 || break
        done

        echo "Suppression du bucket : $S3_BUCKET_NAME"
        aws s3api delete-bucket --bucket "$S3_BUCKET_NAME" --region "$AWS_REGION" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo "Bucket supprime."
        else
            echo "Erreur lors de la suppression du bucket."
        fi
    else
        echo "Le bucket $S3_BUCKET_NAME n'existe pas ou a deja ete supprime."
    fi
else
    echo "S3_BUCKET_NAME non specifie, suppression du bucket ignoree."
fi

echo ""
echo "[3/5] Suppression du Security Group..."
SG_ID=$(aws ec2 describe-security-groups \
    --region "$AWS_REGION" \
    --filters "Name=group-name,Values=creativeflow-webapp-sg" \
    --query "SecurityGroups[0].GroupId" \
    --output text 2>/dev/null || echo "None")

if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
    echo "Suppression du security group : $SG_ID"
    sleep 5
    aws ec2 delete-security-group --region "$AWS_REGION" --group-id "$SG_ID" 2>/dev/null || \
        echo "Impossible de supprimer le security group. Reessayez plus tard."
else
    echo "Security group non trouve."
fi

echo ""
echo "[4/5] Suppression des roles IAM..."

delete_role() {
    local ROLE_NAME=$1

    echo "Suppression du role : $ROLE_NAME"

    if aws iam get-role --role-name "$ROLE_NAME" > /dev/null 2>&1; then
        aws iam remove-role-from-instance-profile \
            --instance-profile-name "$ROLE_NAME" \
            --role-name "$ROLE_NAME" 2>/dev/null || true

        aws iam delete-instance-profile \
            --instance-profile-name "$ROLE_NAME" 2>/dev/null || true

        POLICIES=$(aws iam list-role-policies \
            --role-name "$ROLE_NAME" \
            --query "PolicyNames[]" \
            --output text 2>/dev/null)

        for POLICY in $POLICIES; do
            aws iam delete-role-policy \
                --role-name "$ROLE_NAME" \
                --policy-name "$POLICY" 2>/dev/null
        done

        aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null
        echo "Role $ROLE_NAME supprime."
    else
        echo "Role $ROLE_NAME non trouve."
    fi
}

delete_role "CreativeFlow-Developer"
delete_role "CreativeFlow-Contributor"

echo ""
echo "[5/5] Suppression de la paire de cles..."
aws ec2 delete-key-pair --key-name creativeflow-key --region "$AWS_REGION" 2>/dev/null && \
    echo "Paire de cles creativeflow-key supprimee." || \
    echo "Paire de cles non trouvee ou deja supprimee."

echo ""
echo "============================================="
echo "Nettoyage termine"
echo "============================================="
echo ""
echo "Ressources supprimees :"
echo "  - Instances EC2"
echo "  - Bucket S3 : $S3_BUCKET_NAME"
echo "  - Security Group : creativeflow-webapp-sg"
echo "  - Roles IAM : CreativeFlow-Developer, CreativeFlow-Contributor"
echo "  - Paire de cles : creativeflow-key"
echo ""
echo "============================================="
