# Application des Politiques avec NAC (Network Access Control)

## Objectifs du cours

Alors que les endpoints deviennent plus diversifiés et mobiles, et que les cybermenaces deviennent de plus en plus sophistiquées, il n'est plus acceptable de laisser n'importe quel équipement se connecter à votre réseau. Le NAC est votre réponse à la visibilité, au contrôle et à l'application des politiques à la périphérie du réseau.

Dans cette session, vous apprendrez :

- Comment les solutions NAC identifient, authentifient et autorisent les utilisateurs et équipements
- Ce qu'est l'évaluation de posture et comment elle affecte les décisions d'accès
- Comment l'application des politiques est implémentée via VLANs, ACLs et quarantaines
- Quels outils alimentent le NAC d'entreprise : Cisco ISE, Aruba ClearPass, et plus
- Les modèles de déploiement réels et les bonnes pratiques

---

## Glossaire

### Termes NAC

| Sigle | Nom complet | Description |
|-------|-------------|-------------|
| **NAC** | Network Access Control | Contrôle d'accès au réseau |
| **802.1X** | Port-Based Network Access Control | Standard d'authentification basé sur les ports |
| **MAB** | MAC Authentication Bypass | Authentification par adresse MAC |
| **EAP** | Extensible Authentication Protocol | Protocole d'authentification extensible |
| **RADIUS** | Remote Authentication Dial-In User Service | Protocole AAA pour authentification |

### Termes de Posture

| Terme | Description |
|-------|-------------|
| **Posture** | État de conformité d'un endpoint |
| **Compliant** | Conforme aux politiques de sécurité |
| **Non-Compliant** | Non conforme, accès restreint |
| **Remediation** | Processus de mise en conformité |
| **Quarantine** | VLAN d'isolation pour équipements non conformes |

### Outils NAC

| Outil | Vendeur | Description |
|-------|---------|-------------|
| **ISE** | Cisco | Identity Services Engine |
| **ClearPass** | Aruba/HPE | Solution NAC multi-vendeur |
| **FortiNAC** | Fortinet | NAC avec détection IoT |
| **Forescout** | Forescout | NAC pour environnements OT/industriels |

---

## Le rôle du NAC dans la sécurité d'entreprise

### Pourquoi le NAC est plus important que jamais

Les réseaux d'entreprise ne sont plus des périmètres verrouillés. Ce sont des écosystèmes poreux, orientés utilisateur et mobile-first. Les employés se connectent depuis des téléphones, laptops, tablettes, voire des équipements personnels. Les prestataires, vendeurs et invités ont besoin d'un accès temporaire. Les équipements IoT apparaissent dans les usines, hôpitaux et bâtiments intelligents. Sans contrôle, cela mène au chaos.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LE PROBLÈME : RÉSEAU SANS NAC                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   QUI SE CONNECTE À VOTRE RÉSEAU ?                                           │
│   ─────────────────────────────────                                          │
│                                                                              │
│   [Laptop Corporate] ──┐                                                     │
│   [Téléphone perso]  ──┤                                                     │
│   [Laptop infecté]   ──┼──► [Switch] ──► RÉSEAU ──► Serveurs, Données        │
│   [Caméra IoT]       ──┤         │                                           │
│   [Imprimante]       ──┤         │                                           │
│   [Attaquant ???]    ──┘         │                                           │
│                                  │                                           │
│                              AUCUN CONTRÔLE                                  │
│                                                                              │
│   PROBLÈMES :                                                                │
│   • Pas de visibilité sur qui/quoi est connecté                              │
│   • Équipements non patchés = vecteurs d'attaque                             │
│   • Mouvement latéral possible pour un attaquant                             │
│   • Pas de segmentation par rôle/confiance                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Ce que le NAC apporte

Le **Network Access Control** résout ces problèmes en appliquant **qui** est autorisé sur le réseau, **quoi** ils peuvent accéder, et sous quelles **conditions**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RÉSEAU AVEC NAC                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   [Laptop Corporate] ──┐                                                     │
│                        │      ┌─────────┐                                    │
│   [Téléphone perso]  ──┼──►   │   NAC   │  ──► Vérification                  │
│                        │      │ Server  │      │                             │
│   [Laptop infecté]   ──┤      └────┬────┘      │                             │
│                        │           │           ▼                             │
│   [Caméra IoT]       ──┤           │      ┌─────────────────┐                │
│                        │           │      │ DÉCISION        │                │
│   [Imprimante]       ──┤           │      ├─────────────────┤                │
│                        │           │      │ ✓ Autorisé      │                │
│   [Attaquant ???]    ──┘           │      │ ✗ Refusé        │                │
│                                    │      │ ⚠ Quarantaine   │                │
│                                    │      └────────┬────────┘                │
│                                    │               │                         │
│                                    ▼               ▼                         │
│                              [Switch]         [VLANs]                        │
│                                    │               │                         │
│                              ┌─────┴─────┬────────┴────────┐                 │
│                              │           │                 │                 │
│                          VLAN 10     VLAN 20          VLAN 100               │
│                         Corporate    Invités         Quarantine              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Les 4 Fonctions du NAC

| Fonction | Description |
|----------|-------------|
| **Identification** | Reconnaître l'équipement/utilisateur qui se connecte |
| **Authentification** | Vérifier l'identité via credentials, certificats, 802.1X |
| **Autorisation** | Décider quel niveau d'accès accorder |
| **Évaluation de Posture** | Inspecter l'endpoint pour assurer la conformité |

Le NAC n'est pas seulement un outil de sécurité. C'est aussi un **moteur d'application de politiques réseau**, votre pont entre l'ingénierie réseau et la cybersécurité.

---

## Identification, Authentification & Autorisation

### Flux NAC typique

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FLUX NAC TYPIQUE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. CONNEXION                                                               │
│   ────────────                                                               │
│   [Device] ──► Se connecte au port switch ou AP WiFi                         │
│                                                                              │
│   2. AUTHENTIFICATION                                                        │
│   ────────────────────                                                       │
│   [Switch/AP] ──► Initie 802.1X ou MAB                                       │
│        │                                                                     │
│        ▼                                                                     │
│   [NAC Server] ◄── Reçoit la demande d'authentification                      │
│        │                                                                     │
│        ▼                                                                     │
│   [Active Directory / LDAP / PKI] ◄── Vérifie l'identité                     │
│                                                                              │
│   3. ÉVALUATION DE POSTURE                                                   │
│   ────────────────────────                                                   │
│   [NAC Agent] ──► Vérifie antivirus, patches, firewall...                    │
│        │                                                                     │
│        ▼                                                                     │
│   [NAC Server] ──► Évalue conformité vs politiques                           │
│                                                                              │
│   4. AUTORISATION                                                            │
│   ────────────────                                                           │
│   [NAC Server] ──► Retourne la décision au switch/AP                         │
│        │                                                                     │
│        │    ┌─────────────────────────────────────────┐                      │
│        └───►│ VLAN 10 (Corporate) + ACL spécifique    │                      │
│             │ ou                                      │                      │
│             │ VLAN 100 (Quarantine) + remediation     │                      │
│             │ ou                                      │                      │
│             │ REFUS TOTAL                             │                      │
│             └─────────────────────────────────────────┘                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

Ce processus est souvent invisible pour les utilisateurs finaux mais fournit un contrôle puissant pour les administrateurs.

### Méthodes d'Authentification

| Méthode | Description | Cas d'usage |
|---------|-------------|-------------|
| **802.1X** | Standard pour l'authentification port-based. Utilise EAP et RADIUS | Laptops, postes de travail |
| **MAB** | Authentification par adresse MAC quand 802.1X n'est pas possible | Imprimantes, téléphones IP, IoT |
| **Web Auth** | Redirection vers portail captif pour saisir credentials | Invités, BYOD |

### Intégration avec les Sources d'Identité

Les méthodes d'authentification s'intègrent avec :

| Source | Description |
|--------|-------------|
| **Microsoft Active Directory** | Groupes, utilisateurs, attributs |
| **LDAP** | Annuaires standards |
| **PKI** | Validation basée sur certificats |
| **Base interne** | Pour équipements ou utilisateurs locaux |

### Décisions d'Autorisation

Une fois l'authentification réussie, le NAC détermine ce qui se passe ensuite :

| Action | Description |
|--------|-------------|
| **VLAN Assignment** | Placement dans un VLAN spécifique |
| **ACL Application** | Application d'ACLs sur le port switch |
| **Remediation Portal** | Redirection vers portail de mise en conformité |
| **Quarantine** | Placement en quarantaine |
| **Access Denied** | Refus total d'accès |

Ces décisions sont basées sur plusieurs facteurs dynamiques :

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FACTEURS DE DÉCISION NAC                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   RÔLE DE L'UTILISATEUR                                                      │
│   ─────────────────────                                                      │
│   • Employé, Prestataire, Invité                                             │
│   • Département : RH, IT, Finance, Ventes                                    │
│   • Membre de quel groupe AD ?                                               │
│                                                                              │
│   TYPE D'ÉQUIPEMENT                                                          │
│   ─────────────────                                                          │
│   • Laptop corporate vs personnel                                            │
│   • Smartphone, tablette                                                     │
│   • IoT, imprimante, caméra                                                  │
│                                                                              │
│   CONTEXTE                                                                   │
│   ────────                                                                   │
│   • Localisation : sur site, distant                                         │
│   • Heure de connexion                                                       │
│   • Type de connexion : filaire, WiFi                                        │
│                                                                              │
│   POSTURE                                                                    │
│   ───────                                                                    │
│   • Antivirus à jour ?                                                       │
│   • OS patché ?                                                              │
│   • Firewall activé ?                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

Les conditions de politique peuvent être simples ("L'utilisateur est-il membre du groupe AD Sales ?") ou complexes ("L'utilisateur est-il aux RH ET utilise un laptop corporate sous Windows 11 avec antivirus à jour ET firewall conforme ?").

---

## Évaluation de Posture et Vérifications de Conformité

### Qu'est-ce que l'Évaluation de Posture ?

L'évaluation de posture est là où le NAC devient **dynamique**. Il ne suffit pas de savoir qui est l'utilisateur, vous devez aussi savoir à quel point leur équipement est sain ou fiable.

L'évaluation de posture évalue l'équipement basé sur des critères comme :

| Critère | Description |
|---------|-------------|
| **Antivirus** | Installé et à jour ? |
| **Patches OS** | Niveau de mise à jour système |
| **Services actifs** | Processus ou services en arrière-plan |
| **Logiciels requis** | Agent de chiffrement présent ? |
| **Firewall** | Paramètres conformes ? |

Le client NAC (ex. Cisco AnyConnect ou Aruba Agent) effectue ces vérifications avant d'autoriser l'accès.

### Résultats de l'Évaluation de Posture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    RÉSULTATS DE POSTURE                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   COMPLIANT (Conforme)                                                       │
│   ════════════════════                                                       │
│   ✓ Antivirus à jour                                                         │
│   ✓ OS patché                                                                │
│   ✓ Firewall activé                                                          │
│                                                                              │
│   → ACCÈS COMPLET accordé (VLAN Corporate)                                   │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   NON-COMPLIANT (Non conforme)                                               │
│   ═════════════════════════════                                              │
│   ✓ Antivirus à jour                                                         │
│   ✗ OS pas patché (vulnérabilité critique)                                   │
│   ✓ Firewall activé                                                          │
│                                                                              │
│   → ACCÈS RESTREINT ou QUARANTAINE                                           │
│   → Redirection vers portail de remediation                                  │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   UNKNOWN (Inconnu)                                                          │
│   ═════════════════                                                          │
│   ? Pas d'agent NAC installé                                                 │
│   ? Impossible d'évaluer                                                     │
│                                                                              │
│   → Traité avec prudence (accès invité limité)                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

Les équipements non conformes sont souvent redirigés vers un **VLAN de remediation**, où ils peuvent télécharger des patches, mises à jour ou agents. Après remediation réussie, ils sont réévalués et autorisés à revenir sur le réseau corporate.

### Application de politique dynamique

Les politiques NAC peuvent être dynamiques et contextuelles :

| Contexte | Politique |
|----------|-----------|
| Sur campus + laptop corporate + conforme | Accès complet |
| Distant + équipement personnel | Intranet uniquement |
| Caméra IoT | VLAN isolé sans accès Internet |
| Invité | WiFi invité, Internet seulement |

Ce contrôle d'accès contextuel est bien plus sophistiqué que la segmentation traditionnelle basée sur VLANs ou ACLs.

---

## Mécanismes d'Application : VLANs, ACLs & Quarantaine

### Assignation de VLAN

L'une des techniques d'application les plus courantes en NAC est l'**assignation dynamique de VLAN**. Quand un utilisateur ou équipement s'authentifie avec succès, le serveur NAC communique avec le switch ou point d'accès pour l'assigner à un VLAN spécifique.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ASSIGNATION DYNAMIQUE DE VLAN                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   AVANT (sans NAC) :                                                         │
│   ──────────────────                                                         │
│                                                                              │
│   Port 1 ──► VLAN 10 (configuré manuellement)                                │
│   Port 2 ──► VLAN 10 (configuré manuellement)                                │
│   ...                                                                        │
│                                                                              │
│   AVEC NAC :                                                                 │
│   ──────────                                                                 │
│                                                                              │
│   [Utilisateur RH] ──► 802.1X ──► NAC vérifie ──► VLAN 20 (RH)               │
│   [Utilisateur IT] ──► 802.1X ──► NAC vérifie ──► VLAN 30 (IT)               │
│   [Invité]         ──► Web Auth ──► NAC vérifie ──► VLAN 100 (Guest)         │
│   [Imprimante]     ──► MAB ──► NAC vérifie ──► VLAN 50 (IoT)                 │
│                                                                              │
│   Même port physique, VLAN différent selon l'identité !                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

Chaque VLAN correspond à un niveau de confiance ou segment réseau défini. Cette stratégie de segmentation aide à isoler le trafic entre groupes et réduit significativement le risque de mouvement latéral par des attaquants.

### Exemple d'Assignation

| Utilisateur/Équipement | VLAN | Accès |
|------------------------|------|-------|
| Employés RH | VLAN 20 | Systèmes RH + Internet |
| Staff IT | VLAN 30 | Tout le réseau |
| Invités | VLAN 100 | Internet seulement |
| IoT/Imprimantes | VLAN 50 | Ressources limitées |
| Non-conforme | VLAN 999 | Remediation seulement |

Tout cela se passe automatiquement, basé sur l'identité et la politique, pas de configurations de port manuelles.

### Access control lists (ACLs)

En plus des VLANs, le NAC peut appliquer dynamiquement des **ACLs** sur les ports switch ou sessions wireless. Ces ACLs autorisent ou refusent des flux de trafic spécifiques.

| Cas d'usage | ACL |
|-------------|-----|
| Avant posture complète | Autoriser DNS et DHCP seulement |
| Équipement managé | Permettre RDP et SSH vers serveurs |
| IoT | Bloquer accès Internet |

Ces ACLs peuvent être téléchargées depuis le serveur NAC et appliquées par switches, APs ou firewalls.

### Réseaux de Quarantaine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         QUARANTAINE NAC                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ÉQUIPEMENT NON-CONFORME DÉTECTÉ                                            │
│   ───────────────────────────────                                            │
│                                                                              │
│   [Laptop] ──► Posture Check ──► ÉCHEC (antivirus obsolète)                  │
│        │                                                                     │
│        ▼                                                                     │
│   PLACEMENT EN QUARANTAINE (VLAN 999)                                        │
│        │                                                                     │
│        ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────┐       │
│   │                    VLAN QUARANTINE                               │       │
│   ├─────────────────────────────────────────────────────────────────┤       │
│   │                                                                  │       │
│   │   Accès autorisé :                                               │       │
│   │   ✓ Serveur de patches                                           │       │
│   │   ✓ Serveur antivirus updates                                    │       │
│   │   ✓ Portail de remediation (instructions)                        │       │
│   │                                                                  │       │
│   │   Accès bloqué :                                                 │       │
│   │   ✗ Serveurs internes                                            │       │
│   │   ✗ Internet général                                             │       │
│   │   ✗ Autres VLANs                                                 │       │
│   │                                                                  │       │
│   └─────────────────────────────────────────────────────────────────┘       │
│        │                                                                     │
│        ▼                                                                     │
│   REMEDIATION                                                                │
│   [Laptop] télécharge les updates, installe les patches                      │
│        │                                                                     │
│        ▼                                                                     │
│   RE-ÉVALUATION                                                              │
│   [NAC] réévalue la posture ──► CONFORME ──► VLAN Corporate                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Outils NAC : Cisco ISE et Aruba ClearPass

### Cisco Identity Services Engine (ISE)

**Cisco ISE** est un leader du marché en NAC et accès réseau basé sur l'identité. C'est un moteur de politique complet qui s'intègre avec les switches, routeurs, firewalls et contrôleurs wireless Cisco.

| Capacité | Description |
|----------|-------------|
| **Authentification** | 802.1X et MAB |
| **Politiques** | Création et application centralisées |
| **Posture** | Via Cisco AnyConnect |
| **Guest** | Portails d'accès invités et onboarding BYOD |
| **Intégration** | AD, LDAP, PKI |
| **Threat Response** | Intégration avec Cisco SecureX et Firepower |

ISE fonctionne avec tout l'écosystème Cisco et supporte **TrustSec**, la technologie de segmentation policy-based scalable de Cisco.

### Aruba ClearPass

**Aruba ClearPass**, partie du portfolio réseau HPE, est une solution NAC versatile connue pour son approche **vendor-agnostic**.

| Fonctionnalité | Description |
|----------------|-------------|
| **RBAC** | Contrôle d'accès basé sur les rôles |
| **Posture** | Health checking complet |
| **Device Insight** | Fingerprinting extensif des équipements |
| **OnGuard** | Agent pour enforcement de posture |
| **Guest** | Self-registration et portail captif |
| **Intégration** | Firewalls tiers, SIEMs, MDM |

ClearPass est réputé pour sa flexibilité et est souvent utilisé dans des environnements multi-vendeurs où tous les switches ne sont pas du même fabricant.

### Autres plateformes NAC

| Plateforme | Vendeur | Points forts |
|------------|---------|--------------|
| **FortiNAC** | Fortinet | Détection IoT forte, scalable |
| **Portnox** | Portnox | Cloud-native, déploiement simple |
| **Forescout CounterACT** | Forescout | OT et environnements industriels |

Le bon choix dépend de votre écosystème vendeur, du niveau de contrôle requis, de la complexité de déploiement acceptable, et de l'intégration avec vos outils de sécurité existants.

---

## Considérations de Déploiement Réel

### Stratégies de Design

Déployer le NAC sur un réseau en production peut être challengeant. Il est sage de commencer en **mode monitor-only**, où l'authentification est effectuée mais aucun enforcement n'est appliqué.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHASES DE DÉPLOIEMENT NAC                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   PHASE 1 : MONITOR MODE                                                     │
│   ══════════════════════                                                     │
│   • NAC observe et log toutes les connexions                                 │
│   • Pas d'enforcement (tout le monde accède)                                 │
│   • Permet d'identifier les équipements et patterns                          │
│   • Durée : 2-4 semaines                                                     │
│                                                                              │
│   PHASE 2 : LOW-RISK ENFORCEMENT                                             │
│   ══════════════════════════════                                             │
│   • Enforcement sur VLANs Guest uniquement                                   │
│   • Posture-based DNS blocking                                               │
│   • Test avec groupe pilote                                                  │
│   • Durée : 2-4 semaines                                                     │
│                                                                              │
│   PHASE 3 : PROGRESSIVE ROLLOUT                                              │
│   ═════════════════════════════                                              │
│   • Enforcement par département/bâtiment                                     │
│   • Exceptions documentées                                                   │
│   • Ajustement des politiques                                                │
│   • Durée : 1-3 mois                                                         │
│                                                                              │
│   PHASE 4 : FULL ENFORCEMENT                                                 │
│   ══════════════════════════                                                 │
│   • NAC actif sur tout le réseau                                             │
│   • Toutes les politiques appliquées                                         │
│   • Monitoring continu                                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Décisions clés de design

| Question | Options |
|----------|---------|
| **Authentification** | 802.1X ou fallback MAB ? |
| **Conditions de posture** | Quels critères sont critiques ? |
| **Politique de fallback** | Que faire si NAC indisponible ? |
| **Équipements non-user** | Comment gérer caméras, imprimantes ? |

### Redondance et Haute Disponibilité

Une fois l'enforcement NAC actif, il devient un composant **mission-critical** de votre infrastructure.

| Aspect | Recommandation |
|--------|----------------|
| **Serveurs backup** | Cluster ClearPass ou nœuds ISE multiples |
| **RADIUS timeouts** | Configurer appropriés |
| **Fail-open policy** | Éviter de bloquer pendant les pannes |
| **Logging** | Audit complet de toute l'activité |

### Intégration et Automatisation

Les déploiements NAC les plus puissants s'intègrent avec :

| Système | Intégration |
|---------|-------------|
| **SIEM** (Splunk, QRadar) | Corréler événements identité et réseau |
| **Endpoint Protection** | Lier posture avec antivirus et MDM |
| **SDN Controllers** | Orchestration de politique dynamique |
| **Ticketing** | Création auto d'incidents pour échecs posture |

L'automatisation fait évoluer le NAC d'un outil réactif à un composant proactif de votre stratégie de défense.

---

## Synthèse : NAC dans l'Architecture de Sécurité

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NAC DANS L'ÉCOSYSTÈME DE SÉCURITÉ                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         ┌─────────────┐                                      │
│                         │    SIEM     │                                      │
│                         │  (Splunk)   │                                      │
│                         └──────┬──────┘                                      │
│                                │                                             │
│   ┌─────────────┐      ┌──────┴──────┐      ┌─────────────┐                  │
│   │   Active    │◄────►│    NAC      │◄────►│  Endpoint   │                  │
│   │  Directory  │      │  (ISE/      │      │ Protection  │                  │
│   │             │      │  ClearPass) │      │  (EDR/AV)   │                  │
│   └─────────────┘      └──────┬──────┘      └─────────────┘                  │
│                                │                                             │
│                    ┌───────────┼───────────┐                                 │
│                    │           │           │                                 │
│                    ▼           ▼           ▼                                 │
│              ┌──────────┐ ┌──────────┐ ┌──────────┐                          │
│              │ Switches │ │   APs    │ │Firewalls │                          │
│              └────┬─────┘ └────┬─────┘ └────┬─────┘                          │
│                   │            │            │                                │
│                   └────────────┼────────────┘                                │
│                                │                                             │
│              ┌─────────────────┼─────────────────┐                           │
│              │                 │                 │                           │
│              ▼                 ▼                 ▼                           │
│         [Employees]       [Guests]          [IoT]                            │
│          VLAN 10          VLAN 100         VLAN 50                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Ressources

- [Cisco ISE Product Page](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html)
- [Aruba ClearPass Overview](https://www.arubanetworks.com/products/security/network-access-control/)
- [What is 802.1X](https://www.cisco.com/c/en/us/support/docs/lan-switching/8021x/29723-portsec-faq.html)
- [FortiNAC](https://www.fortinet.com/products/network-access-control)
