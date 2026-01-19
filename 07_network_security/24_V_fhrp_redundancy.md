# Redondance du premier saut (FHRP) - version simplifiée

## L'idée en une phrase

FHRP permet d'avoir plusieurs routeurs qui se partagent une même adresse IP virtuelle, pour que si l'un tombe, l'autre prenne le relais automatiquement.

---

## Le problème : un seul routeur = point de faiblesse

Exemple de situation où la passerelle par défaut (le routeur vers Internet) tombe en panne :

```
Situation normale :
PC → Routeur (192.168.1.1) → Internet ✓

Panne :
PC → Routeur X (mort) → Pas d'Internet !
```

**Tous les utilisateurs** perdent leur connexion Internet. C'est catastrophique !

---

## La solution : FHRP (First Hop Redundancy Protocol)

### Le principe

Au lieu d'avoir une seule passerelle, on en met deux (ou plus) qui se partagent une **adresse IP virtuelle** :

```
                    ┌─────────────────┐
                    │ IP Virtuelle    │
                    │ 192.168.1.1     │
                    └────────┬────────┘
                             │
               ┌─────────────┼─────────────┐
               │                           │
        ┌──────┴──────┐             ┌──────┴──────┐
        │  Routeur 1  │             │  Routeur 2  │
        │   ACTIF     │             │   STANDBY   │
        │ 192.168.1.2 │             │ 192.168.1.3 │
        └─────────────┘             └─────────────┘

Si Routeur 1 tombe → Routeur 2 devient ACTIF
Les PCs ne voient rien, ils continuent avec 192.168.1.1
```

**Analogie** : c'est comme avoir deux standardistes avec le même numéro de téléphone. Si l'un est absent, l'autre décroche.

---

## Les protocoles FHRP

### HSRP (Hot Standby Router Protocol)

- **Cisco propriétaire** (le plus répandu en entreprise Cisco)
- Un routeur ACTIF, un STANDBY

### VRRP (Virtual Router Redundancy Protocol)

- **Standard ouvert** (fonctionne avec tous les équipements)
- Un routeur MASTER, un BACKUP

### Comparaison

| Aspect | HSRP | VRRP |
|--------|------|------|
| Propriétaire | Cisco | Standard ouvert |
| Terminologie | Active/Standby | Master/Backup |
| Préemption | Désactivée par défaut | Activée par défaut |

---

## Comment ça fonctionne ?

### L'élection

Les routeurs s'envoient des messages "Hello" et celui avec la **priorité la plus élevée** devient actif.

```
Routeur 1 : priorité 110 → ACTIF
Routeur 2 : priorité 100 → STANDBY (backup)
```

**Priorité par défaut** : 100 (valeur possible : 0-255)

### La détection de panne

Si le routeur actif ne répond plus (plus de Hello), le standby prend le relais :

```
Temps 0 : R1 (actif) envoie Hello
Temps 3s : R1 envoie Hello
Temps 6s : R1 envoie Hello
Temps 9s : Pas de Hello... R1 est mort ?
Temps 10s : R2 devient ACTIF !
```

**Temps de basculement** : ~10-15 secondes (configurable)

---

## Priorité et préemption

### Priorité

```cisco
standby 1 priority 150    ! Plus haute = devient actif
```

### Préemption

Si le routeur principal revient après une panne, doit-il reprendre le rôle actif ?

**Sans préemption** : R2 reste actif même quand R1 revient
**Avec préemption** : R1 reprend automatiquement le rôle actif

```cisco
standby 1 preempt    ! Active la préemption
```

### Interface tracking

Si le routeur perd son lien vers Internet, sa priorité baisse automatiquement :

```cisco
standby 1 track GigabitEthernet0/2 decrement 20
! Si Gi0/2 tombe, priorité = 150 - 20 = 130
```

---

## Configuration basique HSRP

```cisco
interface GigabitEthernet0/0
 ip address 192.168.10.2 255.255.255.0
 standby version 2
 standby 1 ip 192.168.10.1          ! IP virtuelle
 standby 1 priority 110             ! Priorité
 standby 1 preempt                  ! Reprendre le rôle si possible
 standby 1 authentication md5 key-string SecretKey  ! Sécurité
```

---

## Sécurité : les attaques FHRP

### FHRP Hijacking

Un attaquant peut **devenir la passerelle** en annonçant une priorité maximale :

```
1. L'attaquant envoie des paquets HSRP avec priorité 255
2. Les routeurs légitimes cèdent le rôle
3. Tout le trafic passe par l'attaquant !
4. Man-in-the-Middle = vol de données
```

**Analogie** : c'est comme si quelqu'un criait "C'est moi le chef !" plus fort que le vrai chef, et que tout le monde lui obéissait.

### Outils d'attaque

| Outil | Description |
|-------|-------------|
| Loki | Attaques FHRP (HSRP, VRRP, GLBP) |
| Yersinia | Attaques Layer 2 diverses |
| Scapy | Craft de paquets personnalisés |

---

## Protections

### 1. Authentification MD5

```cisco
standby 1 authentication md5 key-string MonMotDePasse
```

Sans le mot de passe, l'attaquant ne peut pas participer à l'élection.

### 2. Bloquer FHRP sur les ports utilisateurs

```cisco
ip access-list extended BLOCK-FHRP
 deny udp any any eq 1985      ! HSRP
 deny 112 any any              ! VRRP
 permit ip any any

interface range FastEthernet0/1-24
 ip access-group BLOCK-FHRP in
```

### 3. Surveiller les changements

Configurer des alertes si le routeur actif change de façon inattendue.

---

## Commandes de vérification

```cisco
! Voir l'état HSRP
show standby
show standby brief

! Exemple de sortie
GigabitEthernet0/0 - Group 1
  State is Active
  Virtual IP address is 192.168.10.1
  Priority 110 (configured 110)
  Preemption enabled
```

---

## Niveaux de disponibilité

| SLA | Downtime/an | Usage |
|-----|-------------|-------|
| 99% | 3.65 jours | Non-critique |
| 99.9% | 8.76 heures | Standard |
| 99.99% | 52 minutes | Critique |
| 99.999% | 5 minutes | Mission-critique |

FHRP aide à atteindre 99.9% et plus.

---

## Checklist sécurité FHRP

```
□ Authentification MD5 activée
□ Paquets FHRP bloqués sur les ports utilisateurs
□ Préemption configurée selon la politique
□ Interface tracking pour les liens critiques
□ Monitoring des changements d'état
□ Documentation de la topologie attendue
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **FHRP** | Famille de protocoles de redondance de passerelle |
| **HSRP** | Protocole Cisco de redondance |
| **VRRP** | Protocole standard de redondance |
| **VIP** | Virtual IP - adresse IP virtuelle partagée par les routeurs |
| **Active/Master** | Routeur qui répond actuellement |
| **Standby/Backup** | Routeur prêt à prendre le relais |
| **Priorité** | Détermine qui devient actif (plus élevé = prioritaire) |
| **Préemption** | Reprendre le rôle actif après récupération |
| **Tracking** | Ajuster la priorité selon l'état d'un lien |

---

## Résumé en 30 secondes

1. **FHRP** = plusieurs routeurs partagent une IP virtuelle
2. Si l'**actif** tombe, le **standby** prend le relais automatiquement
3. La **priorité** détermine qui est actif (plus élevé gagne)
4. **Préemption** = reprendre le rôle si le routeur revient en ligne
5. **Sécurité** : authentification MD5 obligatoire !
6. Sinon, un attaquant peut devenir la passerelle (hijacking)

---

## Schéma récapitulatif

```
FONCTIONNEMENT NORMAL :

       Clients
          │
          │ Passerelle : 192.168.1.1 (VIP)
          │
    ┌─────┴─────┐
    │           │
┌───┴───┐   ┌───┴───┐
│ R1    │   │ R2    │
│ACTIF  │   │STANDBY│
│prio110│   │prio100│
└───────┘   └───────┘
    │           │
    └─────┬─────┘
          │
      Internet


APRÈS PANNE DE R1 :

       Clients
          │
          │ (même IP : 192.168.1.1)
          │
    ┌─────┴─────┐
    │           │
┌───┴───┐   ┌───┴───┐
│ R1    │   │ R2    │
│ MORT  │   │ACTIF !│
│  X    │   │       │
└───────┘   └───────┘
                │
            Internet

→ Les clients ne voient aucune différence !


ATTAQUE FHRP :

       Clients
          │
    ┌─────┼─────────────────┐
    │     │                 │
┌───┴───┐ │ ┌───────┐   ┌───┴───┐
│ R1    │ │ │ATTACK │   │ R2    │
│ancien │ │ │prio255│   │       │
│ actif │ │ │ ACTIF │   │       │
└───────┘ │ └───┬───┘   └───────┘
          │     │
          │     ↓
          │  Intercepte tout le trafic !
          │
      Internet
```
