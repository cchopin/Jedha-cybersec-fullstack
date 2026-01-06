#!/bin/bash
# =============================================================================
# Generateur de trafic pour tester les metriques CloudWatch
# =============================================================================

# Configuration
APP_URL="${APP_URL:-http://localhost:5000}"
REQUESTS=${1:-20}
DELAY=${2:-1}

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}Generateur de trafic StartupExcuses${NC}"
echo -e "${BLUE}=============================================${NC}"
echo "URL: $APP_URL"
echo "Requetes: $REQUESTS"
echo "Delai: ${DELAY}s"
echo ""

# Verifier que l'app repond
echo -e "${YELLOW}[INFO]${NC} Test de connectivite..."
if ! curl -s --connect-timeout 5 "$APP_URL/health" > /dev/null 2>&1; then
    echo -e "${YELLOW}[WARN]${NC} L'application ne repond pas sur $APP_URL"
    echo "Utilisez: export APP_URL=http://<EC2_PUBLIC_IP>"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Application accessible"
echo ""

# Generer du trafic
echo -e "${YELLOW}[INFO]${NC} Generation de trafic..."

for i in $(seq 1 $REQUESTS); do
    # Page d'accueil (PageViews)
    curl -s "$APP_URL/" > /dev/null
    echo -e "${GREEN}[$i/$REQUESTS]${NC} PageView envoye"

    # Soumettre une excuse (ExcuseSubmissions) - 1 fois sur 3
    if [ $((i % 3)) -eq 0 ]; then
        curl -s -X POST -d "excuse=Test excuse number $i - $(date +%H:%M:%S)" "$APP_URL/submit" > /dev/null
        echo -e "${GREEN}[$i/$REQUESTS]${NC} ExcuseSubmission envoye"
    fi

    sleep $DELAY
done

echo ""
echo -e "${GREEN}[OK]${NC} Trafic genere: $REQUESTS PageViews, $((REQUESTS/3)) ExcuseSubmissions"
echo ""
echo -e "${YELLOW}[INFO]${NC} Verifiez les metriques dans CloudWatch (delai ~5 min):"
echo "  aws cloudwatch list-metrics --namespace 'StartupExcuses/Application'"
