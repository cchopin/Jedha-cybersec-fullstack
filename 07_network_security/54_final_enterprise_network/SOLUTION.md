# Lab 54: Final enterprise network - Solution

Éléments de réponse pour l'architecture réseau Greentech Dynamics Inc.

---

## 1. Architecture réseau d'entreprise

### Modèle de design recommandé

**Choix : Modèle Core-Distribution-Access (Three-Tier)**

**Justification :**
- 400 employés = taille moyenne, pas besoin de la complexité Leaf-Spine
- Modèle éprouvé pour les campus d'entreprise
- Facilité de gestion et troubleshooting
- Personnel IT probablement familier avec ce modèle
- Coût d'implémentation inférieur au Leaf-Spine

**Structure proposée :**

```
                    ┌─────────────────────┐
                    │      CORE           │
                    │  (2x switches L3)   │
                    │   Redundant pair    │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
    ┌──────┴──────┐     ┌──────┴──────┐     ┌──────┴──────┐
    │ DISTRIBUTION│     │ DISTRIBUTION│     │ DISTRIBUTION│
    │   Bldg A    │     │   Bldg B    │     │ Data Center │
    └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
           │                   │                   │
    ┌──────┴──────┐     ┌──────┴──────┐     ┌──────┴──────┐
    │   ACCESS    │     │   ACCESS    │     │   ACCESS    │
    │  Switches   │     │  Switches   │     │ (Leaf-Spine)│
    └─────────────┘     └─────────────┘     └─────────────┘
```

### Placement des liens redondants

| Niveau | Type de redondance | Protocole |
|--------|-------------------|-----------|
| Core | Dual switches, cross-links | HSRP/VRRP + LACP |
| Core-Distribution | Dual uplinks par distribution switch | ECMP/LACP |
| Distribution-Access | Single/Dual uplinks selon criticité | LACP |
| WAN | Dual ISP + MPLS backup | BGP multihoming |

**Justification :**
- Core : point critique, aucun SPOF acceptable
- Distribution : redondance nécessaire pour maintenir la connectivité des étages/bâtiments
- Access : redondance selon la criticité du département (R&D = dual, Marketing = single acceptable)

### Segmentation du trafic

**VLANs par département :**

| VLAN ID | Nom | Usage | Sécurité |
|---------|-----|-------|----------|
| 10 | MGMT | Management réseau | Très élevé |
| 20 | RD | Recherche & Développement | Critique |
| 30 | FINANCE | Département financier | Élevé |
| 40 | IOT | Capteurs et devices IoT | Élevé |
| 50 | CORP | Marketing, RH, général | Standard |
| 60 | GUEST | Visiteurs | Isolé |
| 70 | VOIP | Téléphonie IP | QoS prioritaire |
| 100 | DMZ | Services exposés | Isolé |

**Inter-VLAN routing :**
- Routage au niveau Distribution (pas au niveau Access)
- ACLs entre VLANs pour contrôler les flux
- Firewall interne pour les flux sensibles (vers/depuis R&D, Finance)

### Policy enforcement au niveau accès

**Mécanismes recommandés :**

1. **802.1X Authentication**
   - RADIUS avec Active Directory
   - Certificats machine pour les postes corporate
   - Dynamic VLAN assignment basé sur l'identité

2. **MAC Authentication Bypass (MAB)**
   - Pour les devices ne supportant pas 802.1X (imprimantes, IoT)
   - Whitelisting des MAC addresses connues

3. **Port-Security**
   - Maximum 2 MAC par port (poste + téléphone IP)
   - Violation mode : restrict avec logging

4. **Storm Control**
   - Broadcast : 10%
   - Multicast : 10%
   - Unicast : 80%

---

## 2. Redondance WAN et Internet

### Architecture WAN recommandée

**Choix : SD-WAN avec MPLS backup**

```
                         ┌─────────────┐
                         │   INTERNET  │
                         │  (ISP1+ISP2)│
                         └──────┬──────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
             ┌──────┴──────┐         ┌──────┴──────┐
             │    ISP 1    │         │    ISP 2    │
             │  (Primary)  │         │ (Secondary) │
             └──────┬──────┘         └──────┬──────┘
                    │                       │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │      SD-WAN Edge      │
                    │    (Lyon HQ)          │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │       MPLS VPN        │
                    │   (Backup/Premium)    │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │      SD-WAN Edge      │
                    │    (Paris Branch)     │
                    └───────────────────────┘
```

### Techniques de failover et traffic engineering

**BGP Multihoming :**
- AS number propre ou provider-assigned
- Annonce des préfixes aux deux ISPs
- Local preference pour le trafic sortant
- AS-path prepending pour influencer le trafic entrant

**SD-WAN :**
- Application-aware routing
- Trafic critique (Salesforce, Office 365) : lien primaire avec failover < 1s
- Trafic bulk (backups) : load balancing sur tous les liens
- Trafic voix/vidéo : QoS prioritaire sur MPLS

**MPLS :**
- Réservé pour le trafic business-critical
- SLA garanti avec le provider
- Backup pour les applications legacy ne supportant pas bien la latence variable

### Connexion Paris - Lyon

**Solution : SD-WAN avec tunnels chiffrés**

| Méthode | Usage |
|---------|-------|
| IPsec over Internet | Trafic standard |
| MPLS VPN | Trafic critique, voix |
| Direct Internet Breakout | Office 365, SaaS (Paris) |

**Configuration :**
- Zero Touch Provisioning pour le déploiement
- Split tunneling pour le trafic SaaS local
- Full tunnel pour le trafic interne vers Lyon
- Failover automatique Internet ↔ MPLS

---

## 3. Topologie data center

### Architecture recommandée

**Choix : Leaf-Spine pour le data center**

**Justification :**
- Trafic est-ouest dominant (VM à VM, microservices)
- Évolutivité horizontale simple (ajout de Leaf)
- Latence prévisible (max 2 hops)
- Support de VXLAN/EVPN pour la mobilité des workloads

```
              ┌─────────┐     ┌─────────┐
              │ Spine 1 │     │ Spine 2 │
              └────┬────┘     └────┬────┘
                   │               │
         ┌─────────┼───────────────┼─────────┐
         │         │               │         │
    ┌────┴────┐ ┌──┴───┐     ┌────┴────┐ ┌──┴───┐
    │ Leaf 1  │ │Leaf 2│     │ Leaf 3  │ │Leaf 4│
    │ (Compute│ │(Comp)│     │(Storage)│ │(Mgmt)│
    └────┬────┘ └──┬───┘     └────┬────┘ └──┬───┘
         │         │               │         │
    ┌────┴────┐ ┌──┴───┐     ┌────┴────┐ ┌──┴───┐
    │ Servers │ │Server│     │ Storage │ │ Mgmt │
    │ Rack 1  │ │Rack 2│     │  Array  │ │ Srvs │
    └─────────┘ └──────┘     └─────────┘ └──────┘
```

### Efficacité du trafic est-ouest

**Technologies :**

1. **VXLAN/EVPN**
   - Overlay network pour la mobilité L2
   - Multi-tenancy avec VNI séparés
   - Distributed anycast gateway

2. **ECMP (Equal-Cost Multi-Path)**
   - Load balancing sur tous les chemins Spine
   - Utilisation optimale de la bande passante

3. **BGP Underlay**
   - eBGP entre Leaf et Spine
   - Convergence rapide (< 1s)

### Failover Production ↔ DR

**Architecture DR :**

| Site | Rôle | Distance | RPO | RTO |
|------|------|----------|-----|-----|
| Lyon DC1 | Production | - | - | - |
| Lyon DC2 | Disaster Recovery | 10 km | 15 min | 1 heure |

**Mécanismes :**

1. **Réplication synchrone** (critique)
   - Base de données financières
   - Données R&D actives
   - Latence < 5ms requise

2. **Réplication asynchrone** (standard)
   - Backups
   - Archives
   - Données non-critiques

3. **Failover automatisé**
   - GSLB (Global Server Load Balancing) pour les services web
   - DNS failover pour les services internes
   - Orchestration avec Ansible/Terraform pour le basculement infra

---

## 4. Automatisation et gestion réseau

### Outils recommandés

| Fonction | Outil | Justification |
|----------|-------|---------------|
| Configuration Management | Ansible | Agentless, YAML, large support réseau |
| Config Backup | Oxidized | Léger, multi-vendor, Git integration |
| Monitoring | Prometheus + Grafana | Open source, flexible, alerting |
| Log Management | ELK Stack | Centralisation, recherche, corrélation |
| IPAM | NetBox | Source of truth, API-first |

### Utilisation d'Ansible

**Cas d'usage :**

1. **Déploiement initial**
   - Templates Jinja2 pour la configuration de base
   - Inventaire dynamique depuis NetBox
   - Playbooks par rôle (access, distribution, core)

2. **Changements récurrents**
   - VLAN provisioning
   - ACL updates
   - Firmware upgrades

3. **Compliance checks**
   - Validation des configurations
   - Audit des paramètres de sécurité
   - Rapports de conformité

**Exemple de structure :**

```
ansible/
├── inventory/
│   ├── production/
│   └── dr/
├── group_vars/
│   ├── all.yml
│   ├── core.yml
│   ├── distribution.yml
│   └── access.yml
├── roles/
│   ├── base_config/
│   ├── vlans/
│   ├── security/
│   └── monitoring/
└── playbooks/
    ├── deploy_new_switch.yml
    ├── update_vlans.yml
    └── security_audit.yml
```

### Utilisation d'Oxidized

**Configuration :**
- Collecte automatique toutes les 4 heures
- Stockage dans Git (versioning)
- Alertes sur changements non-planifiés
- Intégration avec ticketing (diff dans les tickets)

### Stratégie de backup et versioning

| Élément | Fréquence | Rétention | Stockage |
|---------|-----------|-----------|----------|
| Running config | 4h | 90 jours | Git + S3 |
| Startup config | Quotidien | 1 an | Git + S3 |
| Firmware | À chaque upgrade | Permanent | S3 |
| Documentation | Continue | Permanent | Git |

**Workflow de changement :**

1. Changement créé dans Git (branch)
2. Review par pair
3. Test en environnement lab (si disponible)
4. Déploiement via Ansible
5. Validation automatique post-déploiement
6. Merge dans main branch
7. Backup automatique via Oxidized

---

## 5. Sécurité et policy enforcement

### NAC recommandé

**Solution : Cisco ISE ou PacketFence (open source)**

**Fonctionnalités requises :**

| Fonction | Description |
|----------|-------------|
| 802.1X | Authentification port-based |
| MAB | Device authentication par MAC |
| Profiling | Identification automatique des devices |
| Posture | Vérification conformité endpoint |
| Guest Access | Portail captif pour visiteurs |

### Vérifications de posture

**Critères de conformité :**

| Critère | Action si non-conforme |
|---------|----------------------|
| Antivirus actif et à jour | Quarantine VLAN |
| OS patches récents | Quarantine VLAN |
| Firewall activé | Warning + log |
| Certificat machine valide | Deny access |
| Domain membership | Dynamic VLAN assignment |

**Workflow de remediation :**

```
Device Connect → 802.1X Auth → Posture Check
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                Compliant      Non-Compliant    Unknown
                    │               │               │
              Production      Quarantine       Guest
                VLAN            VLAN           VLAN
                                    │
                              Remediation
                               Portal
                                    │
                              Re-assess
```

### Contrôle d'accès aux segments sensibles

**Matrice d'accès :**

| Source | R&D | Finance | IoT | Corp | Guest |
|--------|-----|---------|-----|------|-------|
| R&D | ✓ | ✗ | ✗ | ✗ | ✗ |
| Finance | ✗ | ✓ | ✗ | Limited | ✗ |
| IoT | ✗ | ✗ | ✓ | ✗ | ✗ |
| Corp | ✗ | Limited | ✗ | ✓ | ✗ |
| Guest | ✗ | ✗ | ✗ | ✗ | Internet |

**Implémentation :**

1. **ACLs au niveau Distribution**
   - Blocage inter-VLAN par défaut
   - Whitelist des flux autorisés

2. **Firewall interne**
   - Inspection L7 pour les flux vers R&D/Finance
   - IPS activé pour détecter les menaces

3. **Micro-segmentation (data center)**
   - NSX ou ACI pour les workloads critiques
   - Policy basée sur les tags applicatifs

---

## 6. Considérations bonus

### Expansion Amérique du Nord

**Architecture proposée :**

```
                    ┌─────────────────┐
                    │   Global SASE   │
                    │    Platform     │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
   ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
   │  Lyon   │          │  Paris  │          │ New York│
   │   HQ    │          │ Branch  │          │  Branch │
   └─────────┘          └─────────┘          └─────────┘
```

**Considérations :**
- SD-WAN global avec points de présence multi-région
- Office 365 : routing vers le POP le plus proche
- Data residency : données EU restent en EU (RGPD)
- Follow-the-sun support : outils de collaboration unifiés

### Intégrations cloud et WAN hybride

**Office 365 :**
- Direct Internet breakout sur chaque site
- ExpressRoute/Azure Peering pour le trafic critique
- Conditional Access policies

**AWS (IoT data) :**
- AWS Direct Connect depuis Lyon DC
- VPN backup over Internet
- Transit Gateway pour le multi-VPC

**Salesforce :**
- Direct Internet avec SD-WAN optimization
- Private Connect si volume justifié

### Zero Trust Integration

**Principes appliqués :**

| Principe | Implémentation |
|----------|----------------|
| Never trust, always verify | 802.1X + posture check |
| Least privilege | RBAC + micro-segmentation |
| Assume breach | IPS + NDR + logging complet |
| Verify explicitly | MFA + device certificates |

**Architecture Zero Trust :**

1. **Identity-based access**
   - Authentification forte (MFA) obligatoire
   - Certificats machine
   - Conditional Access basé sur le contexte

2. **Device trust**
   - Posture assessment continu
   - EDR/XDR sur tous les endpoints
   - MDM pour les mobiles

3. **Network segmentation**
   - Micro-segmentation par application
   - Default deny entre segments
   - Inspection de tout le trafic

4. **Continuous monitoring**
   - SIEM centralisé
   - UEBA pour la détection d'anomalies
   - Automated response (SOAR)

---

## Schéma d'architecture global

```
                              ┌─────────────────────────────────────┐
                              │            INTERNET                 │
                              │         ┌─────┬─────┐               │
                              │         │ISP1 │ISP2 │               │
                              └─────────┴──┬──┴──┬──┴───────────────┘
                                           │     │
                                    ┌──────┴─────┴──────┐
                                    │    SD-WAN Edge    │
                                    │  + BGP Multihom   │
                                    └────────┬──────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
                    │                  ┌─────┴─────┐                  │
                    │                  │   CORE    │                  │
                    │                  │ (2x L3 SW)│                  │
                    │                  └─────┬─────┘                  │
                    │                        │                        │
         ┌──────────┴──────────┐   ┌────────┴────────┐   ┌───────────┴──────────┐
         │                     │   │                 │   │                      │
    ┌────┴────┐           ┌────┴───┴───┐        ┌────┴───┴───┐            ┌─────┴─────┐
    │ DISTRIB │           │   DISTRIB  │        │   DISTRIB  │            │  DISTRIB  │
    │ Campus  │           │   R&D/Fin  │        │    DC Prod │            │   DC DR   │
    └────┬────┘           └────┬───────┘        └────┬───────┘            └─────┬─────┘
         │                     │                     │                          │
    ┌────┴────┐           ┌────┴───────┐        ┌────┴───────┐            ┌─────┴─────┐
    │ ACCESS  │           │   ACCESS   │        │ LEAF-SPINE │            │LEAF-SPINE │
    │ Corp/HR │           │ R&D/Finance│        │   (Prod)   │            │   (DR)    │
    │ Mktg    │           │   (Secured)│        └────────────┘            └───────────┘
    └─────────┘           └────────────┘

                                    ┌─────────────────┐
                                    │   MPLS VPN      │
            Lyon HQ ◄───────────────┤                 ├───────────────► Paris Branch
                                    │   + SD-WAN      │
                                    └─────────────────┘
```

---

## Checklist de validation

### Architecture
- [x] Modèle Core-Distribution-Access pour le campus
- [x] Leaf-Spine pour les data centers
- [x] Redondance à tous les niveaux critiques
- [x] Segmentation par département (VLANs)

### WAN
- [x] Dual ISP avec BGP multihoming
- [x] SD-WAN pour l'optimisation applicative
- [x] MPLS comme backup premium
- [x] Connexion sécurisée Paris-Lyon

### Sécurité
- [x] NAC avec 802.1X et posture checking
- [x] Micro-segmentation pour les zones sensibles
- [x] ACLs inter-VLAN
- [x] Firewall interne pour R&D/Finance

### Automatisation
- [x] Ansible pour la gestion de configuration
- [x] Oxidized pour le backup des configs
- [x] NetBox comme source of truth
- [x] Git pour le versioning

### Évolutivité
- [x] Design modulaire extensible
- [x] Support de croissance 400 → 1000
- [x] Préparation expansion internationale
- [x] Intégrations cloud prévues
