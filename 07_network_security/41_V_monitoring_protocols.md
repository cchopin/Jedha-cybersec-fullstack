# Protocoles de Monitoring - Version Simplifiée

## L'idée en une phrase

Le monitoring réseau, c'est comme avoir des caméras (NetFlow), des capteurs d'état (SNMP) et un journal de bord (Syslog) pour savoir ce qui se passe sur le réseau.

---

## SNMP : le check-up des équipements

### C'est quoi SNMP ?

SNMP permet d'interroger les équipements pour connaître leur état : CPU, mémoire, interfaces...

```
┌─────────────┐                    ┌─────────────┐
│   Manager   │                    │    Agent    │
│ (Monitoring)│                    │ (Routeur)   │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │── "Quel est le CPU ?" ─────────>│
       │<── "75%" ───────────────────────│
       │                                  │
       │<── "ALERTE: Interface down!" ───│
```

### Polling vs Traps : deux façons de communiquer

```
POLLING (le manager demande) :

Manager: "État ?" ... (5 min) ... "État ?" ... (5 min) ... "État ?"
Agent:   "OK"                    "OK"                     "Problème!"

→ Détection après 5 minutes max

TRAPS (l'agent alerte) :

Agent: *problème détecté* → "ALERTE!" → Manager

→ Détection immédiate
```

### Les versions SNMP

| Version | Sécurité | À retenir |
|---------|----------|-----------|
| **v1** | Nulle | Mot de passe en clair, obsolète |
| **v2c** | Nulle | Plus rapide, mais toujours pas sécurisé |
| **v3** | Bonne | Chiffré et authentifié, à utiliser ! |

### MIB et OID : le vocabulaire SNMP

Chaque métrique a une "adresse" appelée OID :

```
1.3.6.1.2.1.1.1.0 = Description du système
1.3.6.1.2.1.1.3.0 = Uptime
1.3.6.1.2.1.2.2   = Table des interfaces

C'est comme une adresse postale pour chaque information.
```

---

## NetFlow : la caméra du réseau

### C'est quoi NetFlow ?

NetFlow enregistre QUI parle à QUI, sur quel port, et combien de données.

```
┌──────────────────────────────────────────────────────┐
│                     NetFlow                          │
├──────────────────────────────────────────────────────┤
│  Source: 192.168.1.10                                │
│  Destination: 8.8.8.8                                │
│  Port: 443 (HTTPS)                                   │
│  Bytes: 15 MB                                        │
│  Durée: 5 minutes                                    │
└──────────────────────────────────────────────────────┘

"L'utilisateur 192.168.1.10 a téléchargé 15 MB
 depuis Google pendant 5 minutes"
```

### Pourquoi c'est utile ?

```
1. QUI CONSOMME LA BANDE PASSANTE ?

   Top Talkers:
   192.168.1.50  →  45 GB (YouTube ?)
   192.168.1.23  →  28 GB (Backup ?)

2. DÉTECTER DES ANOMALIES

   Normal: 100 connexions/heure
   Maintenant: 10,000 connexions/heure
   → Possible attaque !

3. VOIR LE MOUVEMENT LATÉRAL

   Poste A → Poste B → Poste C
   (inhabituel = possible attaquant)
```

---

## Syslog : le journal de bord

### C'est quoi Syslog ?

Syslog centralise tous les logs (événements) des équipements.

```
Routeur ────┐
Serveur ────┼──────> Serveur Syslog ──────> SIEM
Firewall ───┘        (centralise)          (analyse)
```

### Les niveaux de gravité

| Niveau | Nom | Signification |
|--------|-----|---------------|
| 0 | Emergency | Catastrophe ! |
| 1 | Alert | Agir maintenant ! |
| 2 | Critical | Sérieux |
| 3 | Error | Erreur |
| 4 | Warning | Attention |
| 5 | Notice | Info importante |
| 6 | Info | Info normale |
| 7 | Debug | Détails techniques |

```
Exemple de logs:

[ERROR]   Interface eth0 down
[WARNING] CPU > 80%
[INFO]    User admin logged in
[DEBUG]   Packet received on port 443
```

### Pourquoi centraliser ?

```
SANS centralisation:
"L'attaque a touché 10 serveurs...
 je dois me connecter à chacun pour voir les logs"

AVEC centralisation:
"Tous les logs sont au même endroit,
 je vois l'attaque complète en un coup d'oeil"
```

---

## Comment ça s'assemble ?

### Scénario : détecter une attaque

```
1. SNMP détecte:
   "CPU du serveur à 100%"

2. Syslog montre:
   "Login SSH depuis IP externe"
   "Nouveau processus suspect"

3. NetFlow révèle:
   "Gros transfert de données vers IP inconnue"

CONCLUSION: Serveur compromis + exfiltration de données !
```

### Vue d'ensemble

```
┌─────────────────────────────────────────────────────────┐
│                    MONITORING COMPLET                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  SNMP          NetFlow         Syslog                   │
│  ────          ───────         ──────                   │
│  "Comment      "Qui parle      "Que s'est-il           │
│   vont les     à qui ?"        passé ?"                │
│   équipements?"                                         │
│                                                         │
│       │            │              │                     │
│       └────────────┼──────────────┘                     │
│                    │                                    │
│                    ▼                                    │
│            ┌──────────────┐                             │
│            │    Zabbix    │                             │
│            │   (ou SIEM)  │                             │
│            │ Tout-en-un ! │                             │
│            └──────────────┘                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Zabbix : le chef d'orchestre

### C'est quoi Zabbix ?

Zabbix est un outil qui rassemble tout : SNMP, agents, scripts, alertes...

```
┌─────────────────────────────────────┐
│              ZABBIX                 │
├─────────────────────────────────────┤
│ • Collecte SNMP                     │
│ • Agents sur les serveurs           │
│ • Alertes par email/SMS             │
│ • Dashboards visuels                │
│ • Auto-découverte du réseau         │
└─────────────────────────────────────┘

Un seul outil pour tout surveiller !
```

### Installation express

```bash
# 1. Cloner
git clone https://github.com/karthick-dkk/zabbix.git

# 2. Permissions
chmod u+x zabbix/installation/zabbix-server_docker_installation.sh

# 3. Lancer
./zabbix/installation/zabbix-server_docker_installation.sh

# 4. Accéder
URL: http://localhost:8080
User: Admin
Pass: zabbix
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **SNMP** | Protocole pour interroger l'état des équipements |
| **MIB** | Dictionnaire des métriques SNMP |
| **OID** | Adresse d'une métrique |
| **Polling** | Le manager demande régulièrement |
| **Trap** | L'agent alerte spontanément |
| **SNMPv3** | Version sécurisée (chiffrée) |
| **NetFlow** | Enregistrement du trafic réseau |
| **Flow** | Une conversation réseau |
| **Syslog** | Centralisation des logs |
| **Severity** | Niveau de gravité (0-7) |
| **SIEM** | Outil qui analyse tous les logs |
| **Zabbix** | Solution de monitoring tout-en-un |

---

## Résumé en 30 secondes

```
SNMP     = "Comment vont les équipements ?"
         → CPU, mémoire, interfaces...

NetFlow  = "Qui parle à qui ?"
         → Trafic, bande passante, anomalies

Syslog   = "Que s'est-il passé ?"
         → Logs centralisés, événements

Zabbix   = "Je veux tout voir au même endroit"
         → Dashboard unifié
```

---

## Schéma récapitulatif

```
SNMP - L'INTERROGATEUR :

Manager ────> "État ?" ────> Agent
        <──── "OK" ────────<
        <──── "TRAP!" ─────< (alerte)


NETFLOW - LA CAMÉRA :

    ┌─────────────────────────────────────┐
    │ Flow: 192.168.1.10 → 8.8.8.8:443    │
    │       15 MB en 5 minutes            │
    └─────────────────────────────────────┘


SYSLOG - LE JOURNAL :

    Routeur:  [ERROR] Interface down
    Serveur:  [WARNING] Disk 90%
    Firewall: [INFO] Connection blocked
           │
           ▼
    Serveur Syslog (centralise tout)


VERSIONS SNMP :

    v1/v2c                    v3
    ──────                    ──
    "public"            Chiffré + Authentifié
    (en clair!)         (sécurisé)
       ↓                      ↓
    À éviter !           À utiliser !


ARCHITECTURE COMPLÈTE :

    Équipements
         │
    ┌────┴────┬────────────┐
    │         │            │
   SNMP    NetFlow      Syslog
    │         │            │
    └────┬────┴────────────┘
         │
         ▼
    ┌─────────┐
    │ Zabbix  │  ← Tout centraliser ici
    │  SIEM   │
    └─────────┘
```
