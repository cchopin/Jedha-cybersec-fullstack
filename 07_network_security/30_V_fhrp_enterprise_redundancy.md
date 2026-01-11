# FHRP et Redondance Entreprise - Version Simplifiée

## L'idée en une phrase

FHRP permet d'avoir plusieurs routeurs qui se partagent une même adresse IP virtuelle : si l'un tombe, l'autre prend le relais sans que les utilisateurs ne s'en aperçoivent.

---

## Le problème à résoudre

```
Sans redondance :

PC ──→ Routeur ──→ Internet
           │
           X (panne)
           │
      Plus d'Internet !

Avec FHRP :

PC ──→ IP Virtuelle ──→ Internet
           │
     ┌─────┴─────┐
     │           │
  Routeur 1   Routeur 2
   (Actif)    (Standby)

Si R1 tombe → R2 prend le relais automatiquement
```

**Analogie** : c'est comme avoir deux standardistes avec le même numéro. Si l'un est absent, l'autre décroche.

---

## HSRP vs VRRP

### Les deux protocoles principaux

| Aspect | HSRP | VRRP |
|--------|------|------|
| Qui l'a créé ? | Cisco (propriétaire) | Standard ouvert |
| Terminologie | Active / Standby | Master / Backup |
| Préemption | Désactivée par défaut | Activée par défaut |
| Port | UDP 1985 | IP Protocol 112 |

### Comment ça marche ?

```
1. ÉLECTION
   Les routeurs s'envoient des "Hello"
   Celui avec la plus haute PRIORITÉ devient Actif

2. SURVEILLANCE
   Le Standby écoute les Hello de l'Actif
   Si plus de Hello pendant 10 secondes...

3. FAILOVER
   Le Standby devient Actif !
   Même IP virtuelle = transparent pour les PCs
```

---

## Priorité et Préemption

### Priorité

```
Valeur : 0 à 255 (défaut = 100)
Plus élevé = plus prioritaire

Exemple :
  R1 : priorité 110 → devient ACTIF
  R2 : priorité 100 → devient STANDBY
```

### Préemption

```
SANS préemption :                AVEC préemption :

R1 (prio 110) = Actif            R1 (prio 110) = Actif
R1 tombe...                      R1 tombe...
R2 devient Actif                 R2 devient Actif
R1 revient...                    R1 revient...
R2 reste Actif (pas de chgt)     R1 reprend le rôle Actif !
```

### Interface Tracking

Le routeur baisse sa priorité si son lien vers Internet tombe :

```
R1 avec lien Internet :
  Priorité = 110 → ACTIF

R1 perd son lien Internet :
  Priorité = 110 - 20 = 90 → STANDBY
  R2 (priorité 100) devient ACTIF

= Bascule automatique vers le routeur qui a encore Internet !
```

---

## Configuration Active/Active

Au lieu d'avoir un routeur qui ne fait rien (standby), on répartit la charge :

```
R1 : Actif pour VLAN 10, Standby pour VLAN 20
R2 : Actif pour VLAN 20, Standby pour VLAN 10

    VLAN 10           VLAN 20
       │                 │
   ┌───┴───┐         ┌───┴───┐
   │  R1   │         │  R2   │
   │ ACTIF │         │ ACTIF │
   └───────┘         └───────┘

Les deux routeurs travaillent !
= Meilleure utilisation des ressources
```

---

## Niveaux de disponibilité (SLA)

| Niveau | Uptime | Downtime par an |
|--------|--------|-----------------|
| 99% | "Two nines" | 3.65 jours |
| 99.9% | "Three nines" | 8.76 heures |
| 99.99% | "Four nines" | 52 minutes |
| 99.999% | "Five nines" | 5 minutes |

**FHRP permet d'atteindre 99.9% et plus** avec un failover de quelques secondes.

---

## Attaques sur FHRP

### FHRP Hijacking

```
1. L'attaquant écoute le trafic HSRP/VRRP
2. Il annonce une priorité de 255 (maximum)
3. Il devient la passerelle active !
4. Tout le trafic passe par lui = Man-in-the-Middle

    Clients
       │
   ┌───┴───┐
   │ATTACK │ ← Priorité 255 = devient ACTIF
   │ MitM  │
   └───┬───┘
       │
    Internet
```

### Outils d'attaque

| Outil | Usage |
|-------|-------|
| **Yersinia** | Attaques HSRP/VRRP automatisées |
| **Loki** | Framework d'attaque L2/L3 |
| **Scapy** | Création de paquets personnalisés |

---

## Protections

### 1. Authentification MD5

```cisco
! Sans le mot de passe, impossible de participer
standby 1 authentication md5 key-string SecretKey123
```

### 2. Bloquer FHRP sur les ports utilisateurs

```cisco
! ACL pour bloquer les paquets HSRP non autorisés
ip access-list extended BLOCK-HSRP
 permit udp host 192.168.10.2 any eq 1985  ! R1 autorisé
 permit udp host 192.168.10.3 any eq 1985  ! R2 autorisé
 deny udp any any eq 1985 log              ! Bloquer le reste
 permit ip any any

! Appliquer sur les ports clients
interface range GigabitEthernet0/1 - 24
 ip access-group BLOCK-HSRP in
```

### 3. Monitoring

Configurer des alertes si le routeur Actif change de manière inattendue :

```cisco
snmp-server enable traps hsrp
logging trap notifications
```

---

## Checklist sécurité FHRP

```
□ Authentification MD5 sur tous les groupes
□ Clés complexes et uniques
□ Paquets FHRP bloqués sur ports utilisateurs
□ Monitoring des changements d'état
□ Documentation des priorités autorisées
□ Tests de failover réguliers
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **FHRP** | Famille de protocoles de redondance de passerelle |
| **HSRP** | Protocole Cisco de redondance |
| **VRRP** | Protocole standard de redondance |
| **VIP** | IP virtuelle partagée par les routeurs |
| **Active/Master** | Routeur qui répond actuellement |
| **Standby/Backup** | Routeur prêt à prendre le relais |
| **Priorité** | Détermine qui devient actif (plus élevé = gagne) |
| **Préemption** | Reprendre le rôle actif après récupération |
| **Tracking** | Ajuster la priorité selon l'état d'un lien |
| **Failover** | Basculement automatique vers le backup |
| **SLA** | Engagement de niveau de service (uptime) |

---

## Résumé en 30 secondes

1. **FHRP** = plusieurs routeurs partagent une IP virtuelle
2. **HSRP** = Cisco, **VRRP** = standard ouvert
3. **Priorité** la plus haute = devient Actif
4. **Préemption** = reprendre le rôle si on revient
5. **Tracking** = baisser la priorité si un lien tombe
6. **Sécurité** = authentification MD5 obligatoire !

---

## Schéma récapitulatif

```
PRINCIPE FHRP :

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


INTERFACE TRACKING :

R1 prio 110 ───────────┐
       │               │ Lien Internet
       │               │ tombe !
       ↓               │
R1 prio 90  ←──────────┘
(110 - 20 = 90)

R2 prio 100 > 90 → R2 devient ACTIF


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
          │  Intercepte tout !

Protection : Authentification MD5 !
```
