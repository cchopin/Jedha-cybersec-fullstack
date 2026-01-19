# ACL et filtrage firewall - version simplifiée

## L'idée en une phrase

Les ACLs sont des listes de règles qui autorisent ou bloquent le trafic réseau, comme des vigiles à l'entrée d'un bâtiment qui vérifient les badges.

---

## Qu'est-ce qu'une ACL ?

```
Paquet arrive au routeur :

"Source: 192.168.1.10
 Destination: 10.0.0.5
 Port: 80 (HTTP)"

ACL vérifie :
├─ Règle 1 : Autoriser 192.168.1.0/24 vers 10.0.0.5 port 80 ? OUI → PASSE
├─ Règle 2 : ...
├─ Règle 3 : ...
└─ Fin : BLOQUER tout le reste (deny implicite)
```

**Points clés** :
- Les règles sont vérifiées **de haut en bas**
- Le **premier match** détermine l'action
- Tout ce qui n'est pas autorisé est **bloqué** (deny implicite)

---

## ACL Standard vs Étendue

### ACL Standard (simple)

Filtre uniquement sur l'**adresse source** :

```cisco
! Bloquer 192.168.1.50, autoriser le reste
access-list 10 deny host 192.168.1.50
access-list 10 permit any
```

**Usage** : Simple, pour bloquer une source entière.

### ACL Étendue (précise)

Filtre sur **source, destination, protocole ET port** :

```cisco
! Autoriser HTTP depuis le LAN vers le serveur web
access-list 100 permit tcp 192.168.1.0 0.0.0.255 host 10.0.0.5 eq 80
access-list 100 deny ip any any
```

**Usage** : Précis, pour contrôler exactement quel trafic.

### Comparaison

| Aspect | Standard | Étendue |
|--------|----------|---------|
| **Filtre sur** | Source uniquement | Source, dest, proto, ports |
| **Placement** | Près de la destination | Près de la source |
| **Numéros** | 1-99 | 100-199 |
| **Précision** | Faible | Élevée |

---

## Le Wildcard Mask

Le wildcard est l'**inverse** du masque réseau :

```
Masque réseau : 255.255.255.0
Wildcard      : 0.0.0.255

0 = doit correspondre exactement
1 = peut être n'importe quoi (ignoré)
```

### Exemples courants

| Objectif | Wildcard |
|----------|----------|
| Un seul hôte | 0.0.0.0 (ou `host`) |
| Réseau /24 | 0.0.0.255 |
| Réseau /16 | 0.0.255.255 |
| Tout | 255.255.255.255 (ou `any`) |

```cisco
! Ces deux lignes sont équivalentes :
access-list 10 permit host 192.168.1.50
access-list 10 permit 192.168.1.50 0.0.0.0
```

---

## Où placer les ACLs ?

```
ACL STANDARD = Près de la DESTINATION
(car elle ne filtre que la source)

ACL ÉTENDUE = Près de la SOURCE
(pour bloquer le trafic au plus tôt)


Source ──────────────────────────────→ Destination
   │                                        │
   ACL Étendue ici                    ACL Standard ici
```

---

## Stateless vs Stateful

### Filtrage Stateless (ACL classique)

Chaque paquet est évalué **indépendamment**, sans mémoire :

```
Paquet 1 → Vérif ACL → Décision
Paquet 2 → Vérif ACL → Décision
Paquet 3 → Vérif ACL → Décision

Problème : le retour doit être explicitement autorisé !
```

### Filtrage Stateful (Firewall)

Le firewall **mémorise les connexions** :

```
1. Client initie connexion → Firewall note dans sa table
2. Réponse du serveur → Firewall reconnaît, autorise automatiquement

Avantage : pas besoin de règle pour le retour
```

### Comparaison

| Aspect | Stateless | Stateful |
|--------|-----------|----------|
| **Mémoire** | Aucune | Table de sessions |
| **Config retour** | Manuelle | Automatique |
| **Sécurité** | Basique | Avancée |
| **Performance** | Plus rapide | Plus lente |
| **Coût** | Faible | Plus élevé |

---

## Configuration pratique

### ACL nommée (recommandée)

```cisco
! ACL étendue nommée
ip access-list extended WEB-TRAFFIC
 remark === Autoriser HTTP/HTTPS ===
 permit tcp any host 10.0.0.5 eq 80
 permit tcp any host 10.0.0.5 eq 443
 remark === Bloquer le reste ===
 deny ip any any log

! Application sur l'interface
interface GigabitEthernet0/0
 ip access-group WEB-TRAFFIC in
```

### Ports communs

| Port | Service |
|------|---------|
| 22 | SSH |
| 80 | HTTP |
| 443 | HTTPS |
| 53 | DNS |
| 25 | SMTP |
| 3389 | RDP |

---

## Commandes de vérification

```cisco
! Voir les ACLs configurées
show access-lists

! Voir les statistiques (combien de paquets matchés)
show access-lists 100

! Voir où l'ACL est appliquée
show ip interface GigabitEthernet0/0
```

### Exemple de sortie

```
Extended IP access list 100
    10 permit tcp any host 10.0.0.5 eq www (1250 matches)
    20 deny ip any any log (15 matches)
```

---

## Bonnes pratiques

### L'ordre est CRITIQUE

```cisco
! MAUVAIS : le permit any passe avant le deny
access-list 100 permit ip any any
access-list 100 deny tcp any any eq 23   ← Jamais atteint !

! BON : deny spécifique avant permit général
access-list 100 deny tcp any any eq 23
access-list 100 permit ip any any
```

### Toujours logger les denys

```cisco
access-list 100 deny ip any any log
! Permet de voir ce qui est bloqué
```

### Documenter les règles

```cisco
ip access-list extended FIREWALL-RULES
 remark === Autoriser le web depuis le LAN ===
 permit tcp 192.168.0.0 0.0.255.255 any eq 80
 remark === Bloquer Telnet (non sécurisé) ===
 deny tcp any any eq 23 log
```

---

## Sécurité : anti-spoofing

```cisco
! Bloquer les adresses privées venant d'Internet
ip access-list extended ANTISPOOFING
 deny ip 10.0.0.0 0.255.255.255 any
 deny ip 172.16.0.0 0.15.255.255 any
 deny ip 192.168.0.0 0.0.255.255 any
 deny ip 127.0.0.0 0.255.255.255 any
 permit ip any any

interface GigabitEthernet0/0
 description Vers Internet
 ip access-group ANTISPOOFING in
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **ACL** | Liste de règles pour filtrer le trafic |
| **ACL Standard** | Filtre sur l'IP source uniquement |
| **ACL Étendue** | Filtre sur source, destination, proto, ports |
| **Wildcard Mask** | Inverse du masque réseau |
| **Implicit Deny** | Refus implicite = tout ce qui n'est pas explicitement autorisé est bloqué automatiquement |
| **Stateless** | Chaque paquet évalué indépendamment |
| **Stateful** | Firewall qui mémorise les connexions |
| **permit/deny** | Autoriser/Bloquer |
| **in/out** | Entrant/Sortant sur l'interface |

---

## Résumé en 30 secondes

1. **ACL** = liste de règles permit/deny
2. **Standard** = filtre sur source uniquement
3. **Étendue** = filtre sur source + destination + protocole + port
4. **Wildcard** = inverse du masque (0 = doit correspondre)
5. **Stateless** = pas de mémoire (ACL classique)
6. **Stateful** = firewall qui suit les connexions

---

## Schéma récapitulatif

```
TRAITEMENT D'UNE ACL :

Paquet arrive
    │
    ▼
┌─────────────────┐
│ Première règle  │──── Match? ──── Oui ───> Action (permit/deny)
└────────┬────────┘
         │ Non
         ▼
┌─────────────────┐
│ Deuxième règle  │──── Match? ──── Oui ───> Action
└────────┬────────┘
         │ Non
         ▼
┌─────────────────┐
│ Implicit Deny   │───────────────────────> BLOQUÉ
└─────────────────┘


PLACEMENT DES ACLs :

    Source                              Destination
       │                                     │
       │ ACL Étendue                         │ ACL Standard
       │ (bloque au plus tôt)                │ (bloque près de dest)
       ▼                                     ▼


STATELESS vs STATEFUL :

Stateless :
  Paquet → Vérif ACL → Décision
  Paquet → Vérif ACL → Décision
  (pas de mémoire)

Stateful :
  Connexion → Note dans table → Retour auto-autorisé
  ┌────────────────────────────┐
  │    TABLE DE SESSIONS       │
  │ 192.168.1.10:54321 → 80    │
  │ 192.168.1.11:49152 → 443   │
  └────────────────────────────┘
```
