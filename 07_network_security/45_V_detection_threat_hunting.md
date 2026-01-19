# Détection et Chasse aux Menaces - Version Simplifiée

## L'idée en une phrase

La détection de menaces, c'est comme être détective : NetFlow vous dit qui parle à qui, SNMP révèle ce que les attaquants cherchent à savoir, et le SIEM connecte tous les indices.

---

## NetFlow : Qui parle à qui ?

### C'est quoi NetFlow ?

NetFlow enregistre les métadonnées du trafic : qui, quoi, quand, combien.

```
┌────────────────────────────────────────────┐
│           ENREGISTREMENT NETFLOW           │
├────────────────────────────────────────────┤
│  Source:       192.168.1.50                │
│  Destination:  185.143.223.47              │
│  Port:         443 (HTTPS)                 │
│  Durée:        13 minutes                  │
│  Volume:       808 MB                      │
└────────────────────────────────────────────┘

"Le poste 192.168.1.50 a envoyé 808 MB
 vers une IP externe pendant 13 min"
```

### Détecter l'exfiltration

| Signal d'alarme | Ce que ça veut dire |
|-----------------|---------------------|
| Volume inhabituel | PC qui envoie soudainement des GB au lieu de MB |
| Nouvelle destination | Connexion vers un pays inhabituel |
| Nouveau protocole | PC qui utilise soudainement FTP ou SSH |
| Connexion très longue | Flux actif pendant des heures |
| Pattern régulier | Connexion toutes les 60 secondes = malware |

### Exemple de détection

```
NORMAL:                         SUSPECT:
───────                         ───────
PC comptabilité                 PC comptabilité
  → ERP: 100 MB/jour             → ERP: 100 MB/jour
  → Mail: 50 MB/jour             → Mail: 50 MB/jour
                                  → IP russe: 15 GB ← ALERTE !
```

---

## SNMP : Ce que les attaquants cherchent

### Le risque SNMP

SNMP permet de récupérer des infos sur les équipements. Si mal configuré, les attaquants en profitent.

```
Attaquant                        Le réseau
─────────                        ──────────

"SNMP ouvert ?" ──────────────> Port 161 ouvert
                                     │
"Community = public ?" ──────────────│
                                     │
        <──────────────────── "Oui, entrez !"
                                     │
Récupère :                           │
• Nom des serveurs                   │
• Version des OS                     │
• Table de routage                   │
• Utilisateurs connectés             │
```

### Se protéger

| Action | Pourquoi |
|--------|----------|
| Désactiver SNMP si non utilisé | Moins de surface d'attaque |
| Utiliser SNMPv3 | Chiffré et authentifié |
| Changer "public"/"private" | Strings par défaut = danger |
| Restreindre l'accès | Seulement depuis stations autorisées |

---

## SIEM : tout voir au même endroit

### C'est quoi un SIEM ?

Le SIEM collecte tous les logs du réseau et les analyse ensemble.

```
Firewall ────┐
             │
Serveurs ────┼────> SIEM ────> Analyse ────> Alertes
             │
Endpoints ───┘

"Un seul endroit pour tout voir"
```

### La magie de la corrélation

```
ÉVÉNEMENT 1 (seul = OK)          ÉVÉNEMENT 2 (seul = OK)
────────────────────────         ────────────────────────
09:00 - Login Paris              09:03 - Login VPN Chine
User: jean.dupont                User: jean.dupont

         │                              │
         └──────────────┬───────────────┘
                        │
                   CORRÉLATION
                        │
                        ▼
              IMPOSSIBLE ! → ALERTE
              (Paris et Chine en 3 min)
```

### Exemples de détection

| Ce que le SIEM voit | Ce que ça veut dire |
|---------------------|---------------------|
| 100 logins échoués puis 1 réussi | Attaque brute-force |
| Téléchargement 10GB à minuit | Menace interne |
| Connexion vers domaine C2 connu | Malware |
| Nouveau compte admin + accès sensible | Compromission |

---

## Threat hunting : chercher activement

### C'est quoi le Threat Hunting ?

Au lieu d'attendre les alertes, on cherche les menaces cachées.

```
ALERTES (passif)              HUNTING (actif)
────────────────              ───────────────

Attendre que                  Chercher dans les logs :
l'alerte sonne                "Y a-t-il des connexions
                               vers cette IP suspecte ?"
```

### Exemples de hunts

| Question | Requête SIEM |
|----------|--------------|
| Qui s'est connecté à cette IP malveillante ? | `dst_ip = "185.x.x.x"` |
| Quel PC fait beaucoup de DNS ? | `dns_queries > 1000/hour` |
| Où PowerShell est exécuté ? | `process_name = "powershell.exe"` |
| Mouvement latéral ? | `protocol = "RDP" AND src != admin_stations` |

---

## Réduire le bruit

### Le problème

```
SIEM mal configuré:
  1000 alertes/jour → Analyste fatigué → Vraie alerte ignorée

SIEM bien configuré:
  10 alertes/jour → Chaque alerte compte → Menaces détectées
```

### Solutions

| Technique | Description |
|-----------|-------------|
| Baseline | Alerter seulement si différent du normal |
| Sévérité | Peu d'alertes critiques, claires |
| Threat intel | Ignorer les IP/domaines bénins connus |
| Affiner | Les analystes améliorent les règles |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **NetFlow** | Logs de qui parle à qui sur le réseau |
| **SIEM** | Outil qui centralise et analyse tous les logs |
| **Exfiltration** | Vol de données vers l'extérieur |
| **Beaconing** | Malware qui "appelle maison" régulièrement |
| **C2** | Serveur de contrôle des malwares |
| **Mouvement latéral** | Attaquant qui se déplace dans le réseau |
| **Threat Hunting** | Chercher activement les menaces |
| **Corrélation** | Relier des événements pour détecter des patterns |
| **Baseline** | Le comportement "normal" de référence |

---

## Résumé en 30 secondes

```
NETFLOW    = Qui parle à qui, combien de données
             → Détecter exfiltration, beaconing

SNMP       = Fenêtre sur votre réseau
             → Protéger ou les attaquants l'utilisent

SIEM       = Tous les logs au même endroit
             → Corréler pour détecter les attaques

HUNTING    = Chercher activement les menaces
             → Ne pas attendre les alertes
```

---

## Schéma récapitulatif

```
WORKFLOW DE DÉTECTION :

    COLLECTE              ANALYSE              ACTION
    ────────              ───────              ──────

    NetFlow ───┐
               │
    SNMP ──────┼────> SIEM ────> Corrélation ────> Alerte
               │
    Logs ──────┘
               │
               └────> Threat Hunting ────> Investigation


INDICATEURS SUSPECTS (NetFlow) :

    ✓ Normal                    ✗ Suspect
    ────────                    ─────────
    50 MB/jour                  15 GB/2h
    Destinations connues        IP étrangère
    HTTP/HTTPS                  FTP/SSH nouveau
    Connexions courtes          8h non-stop
    Pattern aléatoire           Toutes les 60s


CORRÉLATION = PUISSANCE DU SIEM :

    Événement A    +    Événement B    =    Pattern détecté
    (seul = OK)         (seul = OK)         → ALERTE !


DÉFENSE SNMP :

    ✗ Vulnérable                ✓ Sécurisé
    ────────────                ──────────
    SNMPv1/v2c                  SNMPv3
    "public"                    Mot de passe fort
    Tout le monde               Stations autorisées
    Pas de logs                 Logs surveillés
```
