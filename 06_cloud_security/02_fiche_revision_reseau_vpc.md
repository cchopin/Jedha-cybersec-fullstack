# Fiche de révision - Réseau et VPC AWS

## Amazon VPC - Virtual Private Cloud

### Définition
Un VPC est un réseau virtuel isolé logiquement dans AWS où vous déployez vos ressources. C'est votre propre datacenter virtuel dans le cloud.

### Composants fondamentaux

#### 1. VPC
- Plage d'adresses IP privées (CIDR block)
- Isolation logique complète
- Un VPC par défaut existe dans chaque région

```bash
# Créer un VPC
aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=MonVPC}]"

# Activer DNS hostnames
aws ec2 modify-vpc-attribute \
    --vpc-id vpc-xxx \
    --enable-dns-hostnames

# Lister les VPCs
aws ec2 describe-vpcs
```

#### 2. Subnets
- Sous-réseaux dans une zone de disponibilité
- **Public** : accès direct à Internet (via IGW)
- **Private** : pas d'accès direct à Internet

```bash
# Créer un subnet public
aws ec2 create-subnet \
    --vpc-id vpc-xxx \
    --cidr-block 10.0.1.0/24 \
    --availability-zone eu-west-3a \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Public-Subnet}]"

# Activer l'auto-assign IP publique
aws ec2 modify-subnet-attribute \
    --subnet-id subnet-xxx \
    --map-public-ip-on-launch

# Créer un subnet privé
aws ec2 create-subnet \
    --vpc-id vpc-xxx \
    --cidr-block 10.0.3.0/24 \
    --availability-zone eu-west-3a \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=Private-Subnet}]"
```

#### 3. Internet Gateway (IGW)
- Point d'accès à Internet pour le VPC
- Un seul IGW par VPC
- Doit être attaché au VPC

```bash
# Créer un Internet Gateway
aws ec2 create-internet-gateway \
    --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=Mon-IGW}]"

# Attacher au VPC
aws ec2 attach-internet-gateway \
    --internet-gateway-id igw-xxx \
    --vpc-id vpc-xxx
```

#### 4. NAT Gateway
- Permet aux instances privées d'accéder à Internet
- Placé dans un subnet public
- Requiert une Elastic IP
- Facturation à l'heure + données transférées

```bash
# Allouer une Elastic IP
aws ec2 allocate-address --domain vpc

# Créer un NAT Gateway
aws ec2 create-nat-gateway \
    --subnet-id subnet-public-xxx \
    --allocation-id eipalloc-xxx \
    --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=Mon-NAT}]"

# Attendre que le NAT soit disponible
aws ec2 wait nat-gateway-available --nat-gateway-ids nat-xxx
```

#### 5. Route Tables
- Règles de routage du trafic
- Chaque subnet est associé à une route table
- Route table principale par défaut

```bash
# Créer une route table
aws ec2 create-route-table \
    --vpc-id vpc-xxx \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=Public-RT}]"

# Ajouter route vers Internet (pour subnet public)
aws ec2 create-route \
    --route-table-id rtb-xxx \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id igw-xxx

# Ajouter route vers NAT (pour subnet privé)
aws ec2 create-route \
    --route-table-id rtb-private-xxx \
    --destination-cidr-block 0.0.0.0/0 \
    --nat-gateway-id nat-xxx

# Associer un subnet à une route table
aws ec2 associate-route-table \
    --route-table-id rtb-xxx \
    --subnet-id subnet-xxx
```

---

## Security Groups vs NACLs

### Comparaison

| Caractéristique | Security Group | NACL |
|-----------------|----------------|------|
| **Niveau** | Instance (ENI) | Subnet |
| **État** | Stateful | Stateless |
| **Règles** | Allow uniquement | Allow et Deny |
| **Évaluation** | Toutes les règles | Par ordre de priorité |
| **Retour trafic** | Automatique | Règle explicite requise |
| **Par défaut** | Deny all entrant | Allow all |

### Security Groups (stateful)

**Stateful** signifie que si le trafic entrant est autorisé, le trafic de retour l'est automatiquement.

```bash
# Créer un security group
aws ec2 create-security-group \
    --group-name WebServerSG \
    --description "Security group for web servers" \
    --vpc-id vpc-xxx

# Autoriser HTTP entrant
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0

# Autoriser SSH depuis une IP spécifique
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 22 \
    --cidr 203.0.113.0/32

# Autoriser trafic depuis un autre security group
aws ec2 authorize-security-group-ingress \
    --group-id sg-db-xxx \
    --protocol tcp \
    --port 5432 \
    --source-group sg-web-xxx

# Lister les règles d'un SG
aws ec2 describe-security-groups --group-ids sg-xxx

# Révoquer une règle
aws ec2 revoke-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0
```

### Network ACLs (stateless)

**Stateless** signifie que les règles entrantes et sortantes sont évaluées indépendamment.

```bash
# Créer une NACL
aws ec2 create-network-acl \
    --vpc-id vpc-xxx \
    --tag-specifications "ResourceType=network-acl,Tags=[{Key=Name,Value=Public-NACL}]"

# Ajouter règle entrante HTTP
aws ec2 create-network-acl-entry \
    --network-acl-id acl-xxx \
    --rule-number 100 \
    --protocol tcp \
    --port-range From=80,To=80 \
    --cidr-block 0.0.0.0/0 \
    --rule-action allow \
    --ingress

# Ajouter règle sortante (ports éphémères pour réponses)
aws ec2 create-network-acl-entry \
    --network-acl-id acl-xxx \
    --rule-number 100 \
    --protocol tcp \
    --port-range From=1024,To=65535 \
    --cidr-block 0.0.0.0/0 \
    --rule-action allow \
    --egress

# Associer NACL à un subnet
aws ec2 replace-network-acl-association \
    --association-id aclassoc-xxx \
    --network-acl-id acl-xxx
```

### Ports éphémères
Les réponses aux requêtes utilisent des ports éphémères (1024-65535). Avec les NACLs, il faut explicitement les autoriser en sortie.

---

## Segmentation réseau - bonnes pratiques

### Architecture multi-tier typique

```
                        Internet
                            |
                    [Internet Gateway]
                            |
    +-------------------------------------------+
    |              PUBLIC TIER                  |
    |   (Load Balancers, Bastion, NAT)         |
    |   10.0.1.0/24  |  10.0.2.0/24            |
    +-------------------------------------------+
                            |
    +-------------------------------------------+
    |             APPLICATION TIER              |
    |   (Web Servers, App Servers)             |
    |   10.0.11.0/24  |  10.0.12.0/24          |
    +-------------------------------------------+
                            |
    +-------------------------------------------+
    |               DATA TIER                   |
    |   (Databases, Cache)                     |
    |   10.0.21.0/24  |  10.0.22.0/24          |
    +-------------------------------------------+
```

### Principes de segmentation

1. **Séparation par fonction**
   - Public : ressources accessibles depuis Internet
   - Application : logique métier
   - Data : stockage de données sensibles

2. **Haute disponibilité**
   - Déployer dans au moins 2 zones de disponibilité
   - Chaque tier dupliqué dans chaque AZ

3. **Principe du moindre privilège**
   - Chaque tier n'accède qu'à ce dont il a besoin
   - Le tier Data n'est accessible que depuis le tier Application

### Règles de communication typiques

| Source | Destination | Port | Description |
|--------|-------------|------|-------------|
| Internet | Public Tier | 80, 443 | Trafic web |
| Admin IP | Public Tier | 22 | SSH bastion |
| Public Tier | App Tier | 8080 | Application |
| App Tier | Data Tier | 5432 | PostgreSQL |
| Private Tiers | NAT Gateway | * | Accès Internet sortant |

---

## AWS Network Security Services

### AWS WAF (Web Application Firewall)

Protège les applications web contre les attaques courantes.

**Fonctionnalités** :
- Protection contre SQL injection, XSS
- Rate limiting
- Geo-blocking
- Règles managées AWS ou personnalisées

```bash
# Lister les Web ACLs
aws wafv2 list-web-acls --scope REGIONAL

# Créer une règle de rate limiting
aws wafv2 create-rule-group \
    --name RateLimitRule \
    --scope REGIONAL \
    --capacity 100 \
    --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=RateLimitRule
```

### AWS Shield

Protection DDoS managée.

| Version | Protection | Coût |
|---------|-----------|------|
| **Standard** | Couche 3/4 automatique | Gratuit |
| **Advanced** | Couche 7, DRT 24/7, remboursement | ~3000$/mois |

### AWS Network Firewall

Firewall managé pour inspection approfondie du trafic.

**Capacités** :
- Inspection stateful et stateless
- Filtrage par domaine
- IPS/IDS intégré
- Règles Suricata compatibles

### VPC Flow Logs

Capture le trafic réseau des interfaces réseau.

```bash
# Activer Flow Logs vers CloudWatch
aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids vpc-xxx \
    --traffic-type ALL \
    --log-destination-type cloud-watch-logs \
    --log-group-name /aws/vpc/flowlogs \
    --deliver-logs-permission-arn arn:aws:iam::xxx:role/FlowLogsRole

# Activer Flow Logs vers S3
aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids vpc-xxx \
    --traffic-type ALL \
    --log-destination-type s3 \
    --log-destination arn:aws:s3:::mon-bucket-flowlogs
```

**Format des logs** :
```
<version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>
```

**Exemple** :
```
2 123456789012 eni-abc123 10.0.1.5 10.0.2.10 443 49152 6 25 5000 1620000000 1620000060 ACCEPT OK
```

---

## Commandes CLI essentielles - réseau

```bash
# VPC
aws ec2 describe-vpcs
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-xxx"
aws ec2 describe-route-tables --filters "Name=vpc-id,Values=vpc-xxx"

# Internet Gateway
aws ec2 describe-internet-gateways

# NAT Gateway
aws ec2 describe-nat-gateways

# Security Groups
aws ec2 describe-security-groups --filters "Name=vpc-id,Values=vpc-xxx"
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=sg-xxx"

# NACLs
aws ec2 describe-network-acls --filters "Name=vpc-id,Values=vpc-xxx"

# Flow Logs
aws ec2 describe-flow-logs

# Elastic IPs
aws ec2 describe-addresses
```

---

## Checklist sécurité réseau

- [ ] VPC avec DNS hostnames activé
- [ ] Subnets privés pour les bases de données
- [ ] NAT Gateway pour l'accès Internet sortant des subnets privés
- [ ] Security Groups restrictifs (moindre privilège)
- [ ] NACLs pour défense en profondeur
- [ ] VPC Flow Logs activés
- [ ] Pas de 0.0.0.0/0 en SSH sauf pour bastion
- [ ] RDS dans subnets privés avec accès limité au tier application

---

## Ressources

- [Documentation VPC](https://docs.aws.amazon.com/vpc/latest/userguide/)
- [AWS CLI VPC Reference](https://docs.aws.amazon.com/cli/latest/reference/ec2/)
- [Security Groups vs NACLs](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/)
- [AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/)
