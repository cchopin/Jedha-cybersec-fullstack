# Firewall et IDS/IPS - version simplifiée

## L'idée en une phrase

Le firewall est le gardien qui contrôle QUI entre et sort, tandis que l'IDS/IPS est le détective qui surveille le COMPORTEMENT du trafic pour détecter et bloquer les attaques.

---

## Firewall : le gardien du réseau

### Qu'est-ce qu'un firewall ?

Un firewall filtre le trafic réseau selon des règles : il autorise ou bloque les connexions.

```
Internet ──────────────────────────────────────> LAN
              │
              ▼
         ┌─────────┐
         │FIREWALL │  "Autorisé ?"
         └─────────┘
              │
        ┌─────┴─────┐
        │           │
        ▼           ▼
     AUTORISÉ    BLOQUÉ
```

### Fonctionnement des règles

Les règles sont évaluées de **haut en bas** :

```
Règle 1: Autoriser HTTP vers serveur web
Règle 2: Autoriser DNS
Règle 3: Bloquer tout le reste ← (deny implicite)

Premier match = action exécutée
```

---

## IDS vs IPS : détecter ou bloquer ?

### IDS (Intrusion Detection System)

L'IDS **observe** et **alerte**, mais ne bloque pas :

```
              Trafic ────────────────────────> Destination
                │
                │ (copie)
                ▼
           ┌─────────┐
           │   IDS   │
           │ Analyse │
           └────┬────┘
                │
                ▼
            ALERTE !
         (pas de blocage)

Un garde qui surveille les caméras
et appelle la police en cas de problème
```

### IPS (Intrusion Prevention System)

L'IPS **observe**, **alerte** ET **bloque** :

```
     Trafic ─────────────────────────> Destination
                    │
                    ▼
               ┌─────────┐
               │   IPS   │
               │ Analyse │
               └────┬────┘
                    │
              ┌─────┴─────┐
              │           │
              ▼           ▼
           Légitime   Malveillant
              │           │
              │           ▼
              │       BLOQUÉ !
              ▼
         Destination

Un garde qui voit l'intrus
ET ferme la porte avant son entrée
```

### Comparaison

| Aspect | IDS | IPS |
|--------|-----|-----|
| **Action** | Alerte seulement | Alerte + blocage |
| **Position** | Hors du flux (passif) | Dans le flux (inline) |
| **Risque** | Faible | Peut bloquer du légitime |
| **Usage** | Monitoring, forensics | Protection temps réel |

---

## Fonctionnement de la détection des attaques

### Détection par signatures

L'IDS/IPS connaît les "empreintes" des attaques connues :

```
Base de signatures :
- "GET /etc/passwd" → Alerte !
- Pattern SQL injection → Alerte !
- Scan Nmap détecté → Alerte !

Avantage : Peu de faux positifs
Inconvénient : Ne détecte pas les nouvelles attaques
```

### Détection par anomalies

Compare le comportement au "normal" :

```
Normal : 100 connexions/minute
Maintenant : 10,000 connexions/minute

→ Anomalie détectée ! Possible DDoS
```

---

## pfSense : firewall open-source

### Qu'est-ce que pfSense ?

pfSense est un firewall gratuit et puissant, basé sur FreeBSD. Il propose :
- Firewall stateful
- NAT
- VPN
- IDS/IPS (avec Suricata/Snort)

### Configuration d'une règle pfSense

| Paramètre | Valeur |
|-----------|--------|
| Interface | LAN |
| Action | Pass (autoriser) |
| Protocol | TCP |
| Source | LAN net |
| Destination | any |
| Port | 80, 443 |
| Description | Navigation web |

---

## Suricata : l'IDS/IPS moderne

### Installation sur pfSense

```
1. System > Package Manager
2. Rechercher "Suricata"
3. Installer
4. Services > Suricata > Configurer
```

### Déploiement recommandé

```
1. Phase IDS (2 semaines)
   - Mode détection uniquement
   - Observer les alertes
   - Identifier les faux positifs

2. Phase Tuning
   - Désactiver les règles bruyantes
   - Whitelister les IPs de confiance

3. Phase IPS
   - Activer le blocage progressivement
   - Monitorer les impacts
```

---

## Faux positifs : le cauchemar des IDS

### Le problème

```
Scanner de vulnérabilité interne (autorisé)
         ↓
     Détecté comme "attaque"
         ↓
     Alerte ! Alerte ! Alerte !
         ↓
     L'admin devient sourd aux vraies alertes
```

### Les solutions

| Solution | Comment |
|----------|---------|
| **Whitelisting** | Ignorer les IPs de confiance |
| **Tuning** | Désactiver les règles trop sensibles |
| **Threshold** | Alerter seulement si > N occurrences |

---

## Actions du firewall

| Action | Comportement |
|--------|--------------|
| **Pass** | Autorise le trafic |
| **Block** | Bloque silencieusement (drop) |
| **Reject** | Bloque et envoie une réponse |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **Firewall** | Gardien qui autorise/bloque le trafic |
| **IDS** | Détecte et alerte |
| **IPS** | Détecte et bloque |
| **Stateful** | Se souvient des connexions |
| **Signature** | Empreinte d'une attaque connue |
| **Faux positif** | Alerte sur du trafic légitime |
| **Suricata** | IDS/IPS open-source moderne |
| **pfSense** | Firewall open-source |

---

## Résumé en 30 secondes

1. **Firewall** = autorise ou bloque selon des règles
2. **IDS** = détecte et alerte (passif)
3. **IPS** = détecte ET bloque (actif)
4. **Signatures** = patterns d'attaques connus
5. **Faux positifs** = gérer avec tuning et whitelisting
6. **pfSense + Suricata** = combo puissant et gratuit

---

## Schéma récapitulatif

```
FIREWALL vs IDS vs IPS :

    FIREWALL :                    IDS :                     IPS :

    "Qui peut entrer ?"          "Que se passe-t-il ?"     "Stop, attaquant !"

    ┌─────────┐                   Trafic ──────> Dest      Trafic ─────┐
    │ RÈGLES  │                      │                           │
    │ IP, Port│                      │ (copie)                   ▼
    └────┬────┘                      ▼                      ┌─────────┐
         │                      ┌─────────┐                 │   IPS   │
    ┌────┴────┐                 │   IDS   │                 │ Analyse │
    │         │                 └────┬────┘                 └────┬────┘
 Autorisé  Bloqué                    │                      ┌────┴────┐
                                 ALERTE !                   │         │
                              (pas de blocage)           Passe    BLOQUÉ


DÉPLOIEMENT RECOMMANDÉ :

    Phase 1                Phase 2                 Phase 3
    ┌──────────┐           ┌──────────┐           ┌──────────┐
    │   IDS    │    →      │  TUNING  │    →      │   IPS    │
    │ (2 sem)  │           │          │           │          │
    │ Observer │           │ Ajuster  │           │ Bloquer  │
    └──────────┘           └──────────┘           └──────────┘


ARCHITECTURE PFSENSE :

                    Internet
                        │
                        ▼
                   ┌─────────┐
                   │pfSense  │
                   │  WAN    │ ← Suricata IDS
                   ├─────────┤
                   │  LAN    │ ← Suricata IPS
                   ├─────────┤
                   │  DMZ    │ ← Suricata IPS
                   └─────────┘
```
