#!/bin/bash
# =============================================================================
# StartupExcuses - Script de nettoyage du monitoring CloudWatch
# Supprime Dashboard, Alarmes et Topic SNS
# =============================================================================

set -e

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
DASHBOARD_NAME="StartupExcuses-Dashboard"
SNS_TOPIC_NAME="StartupExcuses-Alerts"
ALARM_PREFIX="StartupExcuses"

# Fichier de ressources
SCRIPT_DIR="$(dirname "$0")"
RESOURCE_FILE="$SCRIPT_DIR/../resources-ids.txt"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=============================================${NC}"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERREUR]${NC} $1"
}

print_step() {
    echo -e "\n${BLUE}[$1]${NC} $2"
}

# =============================================================================
print_header "StartupExcuses - Nettoyage du Monitoring"
echo "Region: $AWS_REGION"
echo ""

# Charger les IDs si le fichier existe
if [ -f "$RESOURCE_FILE" ]; then
    source "$RESOURCE_FILE"
    print_info "Fichier de ressources charge"
fi

# =============================================================================
# PHASE 1: SUPPRESSION DES ALARMES CLOUDWATCH
# =============================================================================
print_step "1/3" "Suppression des alarmes CloudWatch..."

# Lister les alarmes avec le prefixe
ALARMS=$(aws cloudwatch describe-alarms \
    --region "$AWS_REGION" \
    --alarm-name-prefix "$ALARM_PREFIX" \
    --query "MetricAlarms[].AlarmName" \
    --output text 2>/dev/null || echo "")

if [ -n "$ALARMS" ]; then
    for alarm in $ALARMS; do
        aws cloudwatch delete-alarms \
            --region "$AWS_REGION" \
            --alarm-names "$alarm" 2>/dev/null || true
        print_success "Alarme supprimee: $alarm"
    done
else
    print_info "Aucune alarme trouvee avec le prefixe $ALARM_PREFIX"
fi

# =============================================================================
# PHASE 2: SUPPRESSION DU DASHBOARD
# =============================================================================
print_step "2/3" "Suppression du dashboard CloudWatch..."

DASHBOARD_EXISTS=$(aws cloudwatch list-dashboards \
    --region "$AWS_REGION" \
    --dashboard-name-prefix "$DASHBOARD_NAME" \
    --query "DashboardEntries[].DashboardName" \
    --output text 2>/dev/null || echo "")

if [ -n "$DASHBOARD_EXISTS" ]; then
    aws cloudwatch delete-dashboards \
        --region "$AWS_REGION" \
        --dashboard-names "$DASHBOARD_NAME" 2>/dev/null || true
    print_success "Dashboard supprime: $DASHBOARD_NAME"
else
    print_info "Dashboard non trouve: $DASHBOARD_NAME"
fi

# =============================================================================
# PHASE 3: SUPPRESSION DU TOPIC SNS
# =============================================================================
print_step "3/3" "Suppression du topic SNS..."

# Trouver l'ARN du topic
if [ -z "$SNS_TOPIC_ARN" ]; then
    SNS_TOPIC_ARN=$(aws sns list-topics \
        --region "$AWS_REGION" \
        --query "Topics[?contains(TopicArn, '$SNS_TOPIC_NAME')].TopicArn" \
        --output text 2>/dev/null || echo "")
fi

if [ -n "$SNS_TOPIC_ARN" ]; then
    # Supprimer tous les abonnements d'abord
    SUBSCRIPTIONS=$(aws sns list-subscriptions-by-topic \
        --region "$AWS_REGION" \
        --topic-arn "$SNS_TOPIC_ARN" \
        --query "Subscriptions[].SubscriptionArn" \
        --output text 2>/dev/null || echo "")

    for sub in $SUBSCRIPTIONS; do
        if [ "$sub" != "PendingConfirmation" ]; then
            aws sns unsubscribe \
                --region "$AWS_REGION" \
                --subscription-arn "$sub" 2>/dev/null || true
            print_info "Abonnement supprime: $sub"
        fi
    done

    # Supprimer le topic
    aws sns delete-topic \
        --region "$AWS_REGION" \
        --topic-arn "$SNS_TOPIC_ARN" 2>/dev/null || true
    print_success "Topic SNS supprime: $SNS_TOPIC_ARN"
else
    print_info "Topic SNS non trouve: $SNS_TOPIC_NAME"
fi

# =============================================================================
# Nettoyage du fichier de ressources
# =============================================================================
if [ -f "$RESOURCE_FILE" ]; then
    rm -f "$RESOURCE_FILE"
    print_info "Fichier de ressources supprime"
fi

# =============================================================================
print_header "Nettoyage du Monitoring termine!"
echo ""
print_info "Ressources supprimees:"
echo "  - Alarmes CloudWatch (prefixe: $ALARM_PREFIX)"
echo "  - Dashboard: $DASHBOARD_NAME"
echo "  - Topic SNS: $SNS_TOPIC_NAME"
echo ""
print_info "Note: L'infrastructure 3-tier (VPC, EC2, RDS) n'a pas ete supprimee"
print_info "Utilisez le script cleanup du lab Deploy_basic_3-tier_app si necessaire"
