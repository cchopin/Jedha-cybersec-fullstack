# Fiche de révision - Monitoring et sécurité AWS

## Vue d'ensemble des services de sécurité AWS

```
+------------------------------------------------------------------+
|                    AWS Security Services                          |
+------------------------------------------------------------------+
|                                                                   |
|  [CloudTrail]     [GuardDuty]      [Config]      [Security Hub]  |
|   Audit logs      Threat          Compliance      Unified        |
|   API calls       detection       monitoring      dashboard      |
|                                                                   |
+------------------------------------------------------------------+
|                                                                   |
|  [CloudWatch]     [Inspector]     [Macie]        [Detective]     |
|   Metrics &       Vulnerability   Data           Investigation   |
|   Logs            scanning        protection                     |
|                                                                   |
+------------------------------------------------------------------+
```

---

## AWS CloudTrail

### Description
CloudTrail enregistre toutes les actions effectuées dans un compte AWS (appels API, connexions console, etc.).

### Points clés
- **Activé par défaut** : 90 jours d'historique gratuit
- **Trail personnalisé** : conservation à long terme dans S3
- **Événements** : Management, Data, Insights

### Types d'événements

| Type | Description | Exemples |
|------|-------------|----------|
| **Management** | Opérations de gestion | CreateBucket, RunInstances |
| **Data** | Opérations sur les données | GetObject, PutObject |
| **Insights** | Détection d'anomalies | Pics d'activité inhabituels |

### Commandes CLI

```bash
# Lister les trails
aws cloudtrail describe-trails

# Créer un trail
aws cloudtrail create-trail \
    --name mon-trail \
    --s3-bucket-name mon-bucket-cloudtrail \
    --is-multi-region-trail \
    --enable-log-file-validation

# Démarrer la journalisation
aws cloudtrail start-logging --name mon-trail

# Rechercher des événements récents
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --max-results 10

# Rechercher par utilisateur
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=alice
```

### Exemple d'événement CloudTrail

```json
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "userName": "alice",
        "arn": "arn:aws:iam::123456789012:user/alice"
    },
    "eventTime": "2024-01-15T10:30:00Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "RunInstances",
    "awsRegion": "eu-west-3",
    "sourceIPAddress": "203.0.113.50",
    "userAgent": "aws-cli/2.0"
}
```

### Cas d'usage sécurité
- Audit des accès et modifications
- Détection d'activités suspectes
- Conformité réglementaire
- Forensics après incident

---

## Amazon GuardDuty

### Description
Service de détection des menaces utilisant le machine learning pour identifier les comportements malveillants.

### Sources de données analysées
- VPC Flow Logs
- CloudTrail Events
- DNS Logs
- EKS Audit Logs
- S3 Data Events

### Types de findings

| Catégorie | Exemples |
|-----------|----------|
| **Reconnaissance** | PortProbeUnprotectedPort, Recon:EC2/PortProbeUnprotectedPort |
| **Compromission instance** | CryptoCurrency:EC2/BitcoinTool, UnauthorizedAccess:EC2/SSHBruteForce |
| **Compromission compte** | UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration |
| **Exfiltration données** | Exfiltration:S3/ObjectRead.Unusual |

### Commandes CLI

```bash
# Activer GuardDuty
aws guardduty create-detector --enable

# Lister les détecteurs
aws guardduty list-detectors

# Obtenir les findings
aws guardduty list-findings --detector-id xxxxxxxx

# Détails d'un finding
aws guardduty get-findings \
    --detector-id xxxxxxxx \
    --finding-ids finding-id-xxx

# Archiver un finding (faux positif)
aws guardduty archive-findings \
    --detector-id xxxxxxxx \
    --finding-ids finding-id-xxx
```

### Niveaux de sévérité

| Niveau | Score | Action recommandée |
|--------|-------|-------------------|
| **Low** | 1.0 - 3.9 | Surveiller |
| **Medium** | 4.0 - 6.9 | Investiguer |
| **High** | 7.0 - 8.9 | Priorité haute |
| **Critical** | 9.0 - 10.0 | Action immédiate |

---

## AWS Config

### Description
Service qui évalue la conformité des ressources AWS par rapport à des règles définies.

### Fonctionnalités
- Inventaire des ressources
- Historique des configurations
- Règles de conformité (managed ou custom)
- Remediation automatique

### Règles managées courantes

| Règle | Description |
|-------|-------------|
| `s3-bucket-public-read-prohibited` | S3 ne doit pas être public |
| `encrypted-volumes` | EBS doit être chiffré |
| `iam-password-policy` | Politique de mot de passe IAM |
| `rds-instance-public-access-check` | RDS ne doit pas être public |
| `restricted-ssh` | SSH ne doit pas être ouvert à 0.0.0.0/0 |

### Commandes CLI

```bash
# Activer AWS Config
aws configservice put-configuration-recorder \
    --configuration-recorder name=default,roleARN=arn:aws:iam::xxx:role/ConfigRole

# Lister les règles
aws configservice describe-config-rules

# Ajouter une règle managée
aws configservice put-config-rule \
    --config-rule '{
        "ConfigRuleName": "s3-bucket-public-read-prohibited",
        "Source": {
            "Owner": "AWS",
            "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
        }
    }'

# Vérifier la conformité
aws configservice get-compliance-details-by-config-rule \
    --config-rule-name s3-bucket-public-read-prohibited

# Obtenir le statut global
aws configservice get-compliance-summary-by-config-rule
```

### États de conformité

- **COMPLIANT** : ressource conforme
- **NON_COMPLIANT** : ressource non conforme
- **NOT_APPLICABLE** : règle non applicable
- **INSUFFICIENT_DATA** : données insuffisantes

---

## AWS Security Hub

### Description
Tableau de bord centralisé qui agrège les findings de plusieurs services de sécurité AWS.

### Services intégrés
- GuardDuty
- Inspector
- Macie
- IAM Access Analyzer
- Firewall Manager
- Config
- Partenaires tiers

### Standards de sécurité

| Standard | Description |
|----------|-------------|
| **AWS Foundational Security Best Practices** | Bonnes pratiques AWS |
| **CIS AWS Foundations Benchmark** | Standard CIS |
| **PCI DSS** | Conformité paiement |
| **NIST 800-171** | Standard gouvernemental US |

### Commandes CLI

```bash
# Activer Security Hub
aws securityhub enable-security-hub

# Activer un standard
aws securityhub batch-enable-standards \
    --standards-subscription-requests '[{
        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
    }]'

# Lister les findings
aws securityhub get-findings

# Filtrer les findings critiques
aws securityhub get-findings \
    --filters '{"SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}]}'

# Obtenir le score de sécurité
aws securityhub get-insight-results \
    --insight-arn arn:aws:securityhub:::insight/securityhub/default/1
```

---

## Amazon CloudWatch

### Description
Service de monitoring et d'observabilité pour les ressources et applications AWS.

### Composants principaux

#### 1. Metrics
Données numériques sur les performances.

```bash
# Lister les métriques EC2
aws cloudwatch list-metrics --namespace AWS/EC2

# Obtenir les stats CPU d'une instance
aws cloudwatch get-metric-statistics \
    --namespace AWS/EC2 \
    --metric-name CPUUtilization \
    --dimensions Name=InstanceId,Value=i-xxx \
    --start-time 2024-01-15T00:00:00Z \
    --end-time 2024-01-15T23:59:59Z \
    --period 3600 \
    --statistics Average

# Publier une métrique custom
aws cloudwatch put-metric-data \
    --namespace MonApp \
    --metric-name RequestCount \
    --value 100 \
    --unit Count
```

#### 2. Alarms
Notifications basées sur des seuils.

```bash
# Créer une alarme CPU
aws cloudwatch put-metric-alarm \
    --alarm-name HighCPU \
    --alarm-description "CPU > 80%" \
    --metric-name CPUUtilization \
    --namespace AWS/EC2 \
    --statistic Average \
    --period 300 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --dimensions Name=InstanceId,Value=i-xxx \
    --evaluation-periods 2 \
    --alarm-actions arn:aws:sns:eu-west-3:xxx:AlertTopic

# Lister les alarmes
aws cloudwatch describe-alarms

# Supprimer une alarme
aws cloudwatch delete-alarms --alarm-names HighCPU
```

#### 3. Logs
Centralisation et analyse des logs.

```bash
# Créer un log group
aws logs create-log-group --log-group-name /app/monapp

# Définir la rétention
aws logs put-retention-policy \
    --log-group-name /app/monapp \
    --retention-in-days 30

# Rechercher dans les logs
aws logs filter-log-events \
    --log-group-name /app/monapp \
    --filter-pattern "ERROR"

# Créer un filtre de métriques
aws logs put-metric-filter \
    --log-group-name /app/monapp \
    --filter-name ErrorCount \
    --filter-pattern "ERROR" \
    --metric-transformations \
        metricName=ErrorCount,metricNamespace=MonApp,metricValue=1
```

#### 4. Dashboards
Visualisation centralisée.

```bash
# Créer un dashboard
aws cloudwatch put-dashboard \
    --dashboard-name MonDashboard \
    --dashboard-body file://dashboard.json

# Lister les dashboards
aws cloudwatch list-dashboards
```

### CloudWatch Agent
Pour collecter des métriques système et des logs depuis EC2.

```bash
# Installation sur Amazon Linux
sudo yum install amazon-cloudwatch-agent

# Configuration
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-config-wizard

# Démarrer l'agent
sudo systemctl start amazon-cloudwatch-agent
```

---

## Tableau récapitulatif des services

| Service | Fonction | Données analysées | Sortie |
|---------|----------|-------------------|--------|
| **CloudTrail** | Audit | Appels API | Logs JSON |
| **GuardDuty** | Détection menaces | Flow Logs, DNS, CloudTrail | Findings |
| **Config** | Conformité | Configuration ressources | Compliance status |
| **Security Hub** | Agrégation | Tous les services | Dashboard unifié |
| **CloudWatch** | Monitoring | Métriques, logs | Alarmes, dashboards |

---

## Workflow de réponse aux incidents

```
1. DÉTECTION
   └── GuardDuty finding ou CloudWatch alarm

2. ANALYSE
   ├── CloudTrail : qui a fait quoi ?
   ├── VPC Flow Logs : quel trafic ?
   └── CloudWatch Logs : erreurs applicatives ?

3. CONTAINMENT
   ├── Security Group : isoler l'instance
   ├── NACL : bloquer les IPs
   └── IAM : révoquer les credentials

4. REMEDIATION
   ├── Terminer les instances compromises
   ├── Rotation des secrets
   └── Patching des vulnérabilités

5. POST-INCIDENT
   ├── AWS Config : vérifier la conformité
   └── Documentation et lessons learned
```

---

## Commandes CLI - diagnostic rapide

```bash
# Identité actuelle
aws sts get-caller-identity

# Dernières connexions console (CloudTrail)
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --max-results 5

# Findings GuardDuty récents
aws guardduty list-findings --detector-id xxx --max-results 10

# Ressources non conformes (Config)
aws configservice get-compliance-summary-by-config-rule

# Alarmes en état ALARM
aws cloudwatch describe-alarms --state-value ALARM

# Erreurs récentes dans les logs
aws logs filter-log-events \
    --log-group-name /app/xxx \
    --filter-pattern "ERROR" \
    --start-time $(date -d '1 hour ago' +%s000)
```

---

## Bonnes pratiques monitoring sécurité

- [ ] CloudTrail activé avec trail multi-région vers S3
- [ ] Validation de l'intégrité des logs CloudTrail activée
- [ ] GuardDuty activé dans toutes les régions utilisées
- [ ] AWS Config activé avec règles de base
- [ ] Security Hub activé avec standards appropriés
- [ ] Alarmes CloudWatch pour les métriques critiques
- [ ] Rétention des logs définie (30-365 jours selon criticité)
- [ ] Notifications SNS configurées pour les alertes
- [ ] Dashboard CloudWatch pour la vue d'ensemble

---

## Ressources

- [AWS CloudTrail](https://docs.aws.amazon.com/cloudtrail/latest/userguide/)
- [Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/)
- [AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/)
- [AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/)
- [Amazon CloudWatch](https://docs.aws.amazon.com/cloudwatch/latest/monitoring/)
- [AWS CLI CloudWatch Reference](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/)
- [AWS CLI Logs Reference](https://docs.aws.amazon.com/cli/latest/reference/logs/)
