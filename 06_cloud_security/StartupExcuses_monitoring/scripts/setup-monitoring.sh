#!/bin/bash
# =============================================================================
# StartupExcuses - Script de configuration du monitoring CloudWatch
# Cree Dashboard, Alarmes, Topic SNS et configure les metriques custom
# =============================================================================

set -e

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
DASHBOARD_NAME="StartupExcuses-Dashboard"
SNS_TOPIC_NAME="StartupExcuses-Alerts"
ALARM_PREFIX="StartupExcuses"
RDS_IDENTIFIER="startupexcuses-db"

# Fichiers de ressources
SCRIPT_DIR="$(dirname "$0")"
OUTPUT_FILE="$SCRIPT_DIR/../resources-ids.txt"
PARENT_RESOURCES="$SCRIPT_DIR/../../Deploy_basic_3-tier_app/resources-ids.txt"

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

save_resource_id() {
    echo "$1=$2" >> "$OUTPUT_FILE"
}

# =============================================================================
print_header "StartupExcuses - Configuration du Monitoring"
echo "Region: $AWS_REGION"
echo "Dashboard: $DASHBOARD_NAME"
echo "Topic SNS: $SNS_TOPIC_NAME"
echo ""

# Methode 1: Variable d'environnement INSTANCE_ID
if [ -n "$INSTANCE_ID" ]; then
    print_info "INSTANCE_ID fourni via variable d'environnement: $INSTANCE_ID"

# Methode 2: Fichier resources-ids.txt du lab precedent
elif [ -f "$PARENT_RESOURCES" ]; then
    source "$PARENT_RESOURCES"
    print_info "IDs charges depuis: $PARENT_RESOURCES"

# Methode 3: Recherche par tag AWS
else
    print_info "Recherche de l'instance EC2 par tag Name=StartupExcuses-WebServer..."
    INSTANCE_ID=$(aws ec2 describe-instances \
        --region "$AWS_REGION" \
        --filters "Name=tag:Name,Values=StartupExcuses-WebServer" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].InstanceId" \
        --output text 2>/dev/null || echo "")
fi

# Verification finale
if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "None" ]; then
    print_error "Instance EC2 StartupExcuses non trouvee"
    echo ""
    print_info "Solutions possibles:"
    echo "  1. Deployez d'abord l'infrastructure 3-tier (lab Deploy_basic_3-tier_app)"
    echo "  2. Specifiez l'ID manuellement: export INSTANCE_ID=i-xxxxxxxxx"
    echo "  3. Verifiez que l'instance a le tag Name=StartupExcuses-WebServer"
    exit 1
fi

print_info "Instance EC2 trouvee: $INSTANCE_ID"

# Initialiser le fichier de sortie
echo "# Ressources Monitoring AWS creees le $(date)" > "$OUTPUT_FILE"
echo "AWS_REGION=$AWS_REGION" >> "$OUTPUT_FILE"
echo "INSTANCE_ID=$INSTANCE_ID" >> "$OUTPUT_FILE"

# =============================================================================
# PHASE 1: CREATION DU TOPIC SNS
# =============================================================================
print_step "1/4" "Creation du topic SNS pour les alertes..."

SNS_TOPIC_ARN=$(aws sns create-topic \
    --region "$AWS_REGION" \
    --name "$SNS_TOPIC_NAME" \
    --query "TopicArn" \
    --output text)

print_success "Topic SNS cree: $SNS_TOPIC_ARN"
save_resource_id "SNS_TOPIC_ARN" "$SNS_TOPIC_ARN"

print_info "Pour recevoir les alertes, abonnez votre email:"
echo "  aws sns subscribe --topic-arn $SNS_TOPIC_ARN --protocol email --notification-endpoint votre@email.com"

# =============================================================================
# PHASE 2: CREATION DES ALARMES CLOUDWATCH
# =============================================================================
print_step "2/4" "Creation des alarmes CloudWatch..."

# Alarme CPU EC2 - seuil >80% pendant 2 periodes consecutives
aws cloudwatch put-metric-alarm \
    --region "$AWS_REGION" \
    --alarm-name "${ALARM_PREFIX}-HighCPU" \
    --alarm-description "Alerte quand CPU EC2 depasse 80% pendant 2 periodes consecutives" \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --statistic Average \
    --period 300 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2 \
    --dimensions Name=InstanceId,Value="$INSTANCE_ID" \
    --alarm-actions "$SNS_TOPIC_ARN" \
    --treat-missing-data notBreaching

print_success "Alarme HighCPU creee (seuil: >80%, periodes: 2)"

# Alarme connexions RDS - alerte a 10 connexions
aws cloudwatch put-metric-alarm \
    --region "$AWS_REGION" \
    --alarm-name "${ALARM_PREFIX}-DBConnections" \
    --alarm-description "Alerte quand le nombre de connexions RDS approche la limite (10)" \
    --metric-name DatabaseConnections \
    --namespace AWS/RDS \
    --statistic Average \
    --period 300 \
    --threshold 10 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 1 \
    --dimensions Name=DBInstanceIdentifier,Value="$RDS_IDENTIFIER" \
    --alarm-actions "$SNS_TOPIC_ARN" \
    --treat-missing-data notBreaching

print_success "Alarme DBConnections creee (seuil: >=10 connexions)"

save_resource_id "ALARM_CPU" "${ALARM_PREFIX}-HighCPU"
save_resource_id "ALARM_DB" "${ALARM_PREFIX}-DBConnections"

# =============================================================================
# PHASE 3: CREATION DU DASHBOARD CLOUDWATCH
# =============================================================================
print_step "3/4" "Creation du dashboard CloudWatch..."

DASHBOARD_BODY=$(cat <<EOF
{
    "widgets": [
        {
            "type": "metric",
            "x": 0,
            "y": 0,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "EC2 CPU utilization",
                "metrics": [
                    ["AWS/EC2", "CPUUtilization", "InstanceId", "$INSTANCE_ID"]
                ],
                "period": 300,
                "stat": "Average",
                "region": "$AWS_REGION",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 12,
            "y": 0,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "RDS CPU utilization",
                "metrics": [
                    ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", "$RDS_IDENTIFIER"]
                ],
                "period": 300,
                "stat": "Average",
                "region": "$AWS_REGION",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 6,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "RDS database connections",
                "metrics": [
                    ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", "$RDS_IDENTIFIER"]
                ],
                "period": 300,
                "stat": "Average",
                "region": "$AWS_REGION",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 12,
            "y": 6,
            "width": 12,
            "height": 6,
            "properties": {
                "title": "Application metrics",
                "metrics": [
                    ["StartupExcuses/Application", "PageViews"],
                    ["StartupExcuses/Application", "ExcuseSubmissions"]
                ],
                "period": 300,
                "stat": "Sum",
                "region": "$AWS_REGION",
                "view": "timeSeries"
            }
        },
        {
            "type": "metric",
            "x": 0,
            "y": 12,
            "width": 24,
            "height": 6,
            "properties": {
                "title": "EC2 network traffic",
                "metrics": [
                    ["AWS/EC2", "NetworkIn", "InstanceId", "$INSTANCE_ID"],
                    ["AWS/EC2", "NetworkOut", "InstanceId", "$INSTANCE_ID"]
                ],
                "period": 300,
                "stat": "Average",
                "region": "$AWS_REGION",
                "view": "timeSeries"
            }
        }
    ]
}
EOF
)

aws cloudwatch put-dashboard \
    --region "$AWS_REGION" \
    --dashboard-name "$DASHBOARD_NAME" \
    --dashboard-body "$DASHBOARD_BODY"

print_success "Dashboard CloudWatch cree: $DASHBOARD_NAME"
save_resource_id "DASHBOARD_NAME" "$DASHBOARD_NAME"

# =============================================================================
# PHASE 4: VERIFICATION
# =============================================================================
print_step "4/4" "Verification de la configuration..."

# Verifier les alarmes
ALARMS=$(aws cloudwatch describe-alarms \
    --region "$AWS_REGION" \
    --alarm-name-prefix "$ALARM_PREFIX" \
    --query "MetricAlarms[].AlarmName" \
    --output text)

print_success "Alarmes configurees: $ALARMS"

# Verifier le dashboard
DASHBOARDS=$(aws cloudwatch list-dashboards \
    --region "$AWS_REGION" \
    --dashboard-name-prefix "$DASHBOARD_NAME" \
    --query "DashboardEntries[].DashboardName" \
    --output text)

print_success "Dashboard disponible: $DASHBOARDS"

# =============================================================================
print_header "Configuration du Monitoring terminee!"
echo ""
print_info "Ressources creees:"
echo "  - Topic SNS: $SNS_TOPIC_ARN"
echo "  - Alarme CPU: ${ALARM_PREFIX}-HighCPU"
echo "  - Alarme DB: ${ALARM_PREFIX}-DBConnections"
echo "  - Dashboard: $DASHBOARD_NAME"
echo ""
print_info "Acces au dashboard:"
echo "  https://${AWS_REGION}.console.aws.amazon.com/cloudwatch/home?region=${AWS_REGION}#dashboards:name=${DASHBOARD_NAME}"
echo ""
print_info "Pour activer les metriques custom, mettez a jour l'application avec le nouveau app.py"
print_info "et assurez-vous que l'instance EC2 a les permissions CloudWatch (IAM role)"
echo ""
print_info "IDs sauvegardes dans: $OUTPUT_FILE"
