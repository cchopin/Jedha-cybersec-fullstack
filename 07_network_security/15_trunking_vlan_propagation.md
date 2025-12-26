# Trunking et propagation des VLANs

## Objectifs du cours

Ce cours couvre la configuration des trunks Cisco et la propagation des VLANs, avec des exemples pratiques essentiels pour la certification CCNA.

Compétences visées :
- Configurer des ports trunk et gérer la propagation des VLANs
- Comprendre et configurer le Dynamic Trunking Protocol (DTP)
- Maîtriser le comportement du Native VLAN
- Diagnostiquer les erreurs de configuration courantes
- Sécuriser les ports trunk

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **Trunk** | Lien transportant plusieurs VLANs entre équipements |
| **DTP** | Dynamic Trunking Protocol - Négociation automatique de trunk (Cisco) |
| **dot1q** | Abréviation de 802.1Q, le standard de tagging VLAN |
| **Native VLAN** | VLAN dont les trames ne sont pas taguées sur un trunk |
| **Allowed VLANs** | Liste des VLANs autorisés à traverser un trunk |
| **BPDU** | Bridge Protocol Data Unit - Messages Spanning Tree |

---

## Qu'est-ce qu'un trunk ?

Un **trunk** est un lien qui transporte le trafic de plusieurs VLANs sur une seule connexion physique. Sans trunk, il faudrait un câble séparé pour chaque VLAN entre deux switches.

```
SANS TRUNK (inefficace) :                 AVEC TRUNK (efficace) :

Switch A          Switch B                Switch A          Switch B
┌────────┐        ┌────────┐              ┌────────┐        ┌────────┐
│ VLAN10 │────────│ VLAN10 │              │ VLAN10 │        │ VLAN10 │
│ VLAN20 │────────│ VLAN20 │              │ VLAN20 │───────│ VLAN20 │
│ VLAN30 │────────│ VLAN30 │              │ VLAN30 │  trunk │ VLAN30 │
└────────┘        └────────┘              └────────┘        └────────┘
   3 câbles nécessaires                      1 seul câble
```

Le trunk utilise le **tagging 802.1Q** pour identifier chaque trame avec son VLAN d'origine.

---

## Configuration d'un trunk (Cisco)

### Configuration de base

```cisco
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport trunk encapsulation dot1q
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20,30
```

| Commande | Description |
|----------|-------------|
| `switchport trunk encapsulation dot1q` | Active l'encapsulation 802.1Q |
| `switchport mode trunk` | Force le port en mode trunk |
| `switchport trunk allowed vlan 10,20,30` | Limite les VLANs autorisés |

### Vérification

```cisco
Switch# show interfaces trunk

Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       on           802.1q         trunking      1

Port        Vlans allowed on trunk
Gi0/1       10,20,30

Port        Vlans allowed and active in management domain
Gi0/1       10,20,30
```

---

## Dynamic Trunking Protocol (DTP)

### Qu'est-ce que DTP ?

**DTP** est un protocole propriétaire Cisco qui permet aux switches de négocier automatiquement si un port doit devenir trunk ou rester en mode access.

### Modes DTP

| Mode | Comportement | Commande |
|------|--------------|----------|
| **Access** | Port access uniquement, pas de négociation | `switchport mode access` |
| **Trunk** | Port trunk forcé | `switchport mode trunk` |
| **Dynamic Auto** | Devient trunk SI l'autre côté le demande | `switchport mode dynamic auto` |
| **Dynamic Desirable** | Demande activement à devenir trunk | `switchport mode dynamic desirable` |

### Matrice de négociation DTP

| Port A \ Port B | Access | Trunk | Dynamic Auto | Dynamic Desirable |
|-----------------|--------|-------|--------------|-------------------|
| **Access** | Access | ❌ | Access | Access |
| **Trunk** | ❌ | Trunk | Trunk | Trunk |
| **Dynamic Auto** | Access | Trunk | Access | Trunk |
| **Dynamic Desirable** | Access | Trunk | Trunk | Trunk |

❌ = Mismatch (problème de configuration)

### Risque de sécurité avec DTP

**Problème :** Un attaquant peut envoyer des paquets DTP pour négocier un trunk et accéder à tous les VLANs.

**Solution :** Désactiver DTP sur tous les ports :

```cisco
! Sur les ports access
Switch(config-if)# switchport mode access
Switch(config-if)# switchport nonegotiate

! Sur les ports trunk
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport nonegotiate
```

---

## Configuration du Native VLAN

### Rappel

Le **Native VLAN** est le VLAN dont les trames ne sont **pas taguées** sur un trunk. Par défaut, c'est le VLAN 1.

### Changer le Native VLAN

```cisco
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport trunk native vlan 99
```

**Important :** Le Native VLAN doit être **identique** des deux côtés du trunk, sinon les trames seront mal acheminées.

### Vérification

```cisco
Switch# show interfaces GigabitEthernet0/1 trunk

Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       on           802.1q         trunking      99
```

---

## Dépannage des trunks

### Problèmes courants et solutions

#### 1. Native VLAN Mismatch

**Symptôme :** Message d'erreur CDP ou trafic mal acheminé

```
%CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch discovered on GigabitEthernet0/1
```

**Diagnostic :**
```cisco
Switch# show interfaces trunk
```

**Solution :** Configurer le même Native VLAN des deux côtés :
```cisco
Switch(config-if)# switchport trunk native vlan 99
```

#### 2. VLAN non propagé

**Symptôme :** Les machines d'un VLAN ne communiquent pas entre switches

**Diagnostic :**
```cisco
! Vérifier que le VLAN existe
Switch# show vlan brief

! Vérifier les VLANs autorisés sur le trunk
Switch# show interfaces trunk
```

**Causes possibles :**
- Le VLAN n'existe pas sur un des switches
- Le VLAN n'est pas dans la liste `allowed vlan`

**Solution :**
```cisco
! Créer le VLAN si nécessaire
Switch(config)# vlan 50
Switch(config-vlan)# name Marketing

! Ajouter le VLAN au trunk
Switch(config-if)# switchport trunk allowed vlan add 50
```

#### 3. Trunk qui ne se forme pas

**Symptôme :** Le lien reste en mode access

**Diagnostic :**
```cisco
Switch# show interfaces GigabitEthernet0/1 switchport
```

**Causes possibles :**
- DTP désactivé ou mode incompatible
- Encapsulation différente

**Solution :**
```cisco
! Forcer le trunk des deux côtés
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk encapsulation dot1q
```

#### 4. Boucle réseau (Broadcast Storm)

**Symptôme :** Réseau saturé, switches surchargés

**Diagnostic :**
```cisco
Switch# show spanning-tree
```

**Solution :** Vérifier la configuration STP (voir cours 18)

---

## Commandes de diagnostic essentielles

### Vue d'ensemble des trunks

```cisco
Switch# show interfaces trunk

Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       on           802.1q         trunking      99
Gi0/2       on           802.1q         trunking      99

Port        Vlans allowed on trunk
Gi0/1       10,20,30
Gi0/2       10,20,30,40

Port        Vlans allowed and active in management domain
Gi0/1       10,20,30
Gi0/2       10,20,30,40
```

### Détails d'un port

```cisco
Switch# show interfaces GigabitEthernet0/1 switchport

Name: Gi0/1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: dot1q
Negotiation of Trunking: Off
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 99 (VLAN99)
Trunking VLANs Enabled: 10,20,30
```

### Liste des VLANs

```cisco
Switch# show vlan brief

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Fa0/1, Fa0/2
10   RH                               active    Fa0/3, Fa0/4
20   IT                               active    Fa0/5, Fa0/6
30   Serveurs                         active    Fa0/7, Fa0/8
99   Native                           active
999  Unused                           active    Fa0/23, Fa0/24
```

---

## Sécurisation des trunks

### Checklist de sécurité

```
□ Désactiver DTP (switchport nonegotiate)
□ Limiter les VLANs autorisés
□ Changer le Native VLAN (≠ VLAN 1)
□ Ne pas utiliser VLAN 1 pour le trafic utilisateur
□ Surveiller les trunks régulièrement
```

### Configuration sécurisée complète

```cisco
interface GigabitEthernet0/1
 description TRUNK-VERS-CORE
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30
 switchport nonegotiate
 no shutdown
```

### Surveillance

```cisco
! Vérifier périodiquement l'état des trunks
Switch# show interfaces trunk

! Vérifier les changements de topologie
Switch# show spanning-tree detail

! Voir les logs
Switch# show logging | include trunk
```

---

## Résumé

| Concept | Point clé |
|---------|-----------|
| **Trunk** | Lien transportant plusieurs VLANs (tagging 802.1Q) |
| **DTP** | Négociation automatique - À DÉSACTIVER pour la sécurité |
| **Native VLAN** | VLAN non taggé - Doit être identique des deux côtés |
| **Allowed VLANs** | Toujours limiter aux VLANs nécessaires |

### Commandes essentielles

| Commande | Usage |
|----------|-------|
| `show interfaces trunk` | Vue d'ensemble des trunks |
| `show vlan brief` | Liste des VLANs |
| `switchport mode trunk` | Forcer le mode trunk |
| `switchport nonegotiate` | Désactiver DTP |
| `switchport trunk allowed vlan` | Limiter les VLANs |
| `switchport trunk native vlan` | Changer le Native VLAN |

---

## Ressources

| Ressource | Lien |
|-----------|------|
| Cisco VLAN Configuration Guide | https://www.cisco.com/c/en/us/support/docs/lan-switching/vlan/ |
| Dynamic Trunking Protocol (DTP) | https://www.cisco.com/c/en/us/support/docs/lan-switching/vtp/ |
| CCNA Exam Blueprint | https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna.html |

---

## Labs TryHackMe

| Room | Description | Lien |
|------|-------------|------|
| **Layer 2 MAC Flooding & ARP Spoofing** | Attaques Layer 2 et manipulation de VLANs | https://tryhackme.com/r/room/dvwa |
| **Intro to Networking** | Fondamentaux reseau incluant switching | https://tryhackme.com/room/introtonetworking |
| **Network Services** | Services reseau et configuration | https://tryhackme.com/room/networkservices |

> **Note** : Les concepts de trunking sont principalement pratiques sur GNS3 ou Packet Tracer car TryHackMe ne propose pas de labs specifiques a la configuration de switches Cisco.
