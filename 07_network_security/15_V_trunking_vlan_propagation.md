# Trunking et Propagation des VLANs - Version Simplifiée

## L'idée en une phrase

Un trunk est un câble "spécial" qui transporte plusieurs VLANs entre deux switches, permettant aux mêmes VLANs d'exister sur plusieurs switches.

---

## Pourquoi les trunks sont-ils nécessaires ?

### Le problème

Deux switches avec les mêmes VLANs :

```
Switch A                                    Switch B
┌───────────────┐                          ┌───────────────┐
│ VLAN 10 (RH)  │                          │ VLAN 10 (RH)  │
│ VLAN 20 (IT)  │                          │ VLAN 20 (IT)  │
│ VLAN 30 (FIN) │                          │ VLAN 30 (FIN) │
└───────────────┘                          └───────────────┘
```

**Sans trunk** : il faudrait 3 câbles (un par VLAN) !

**Avec trunk** : 1 seul câble transporte les 3 VLANs.

---

## Comment le switch sait-il à quel VLAN appartient chaque trame ?

### L'étiquetage (tagging)

Quand une trame passe sur un trunk, le switch lui ajoute une étiquette :

```
Avant (port access) :
┌────────────────────────────────────┐
│ [MAC Dest] [MAC Source] [Données] │
└────────────────────────────────────┘

Sur le trunk :
┌──────────────────────────────────────────┐
│ [MAC Dest] [MAC Source] [VLAN 20] [Données] │
└──────────────────────────────────────────┘
                            ↑
                     Tag 802.1Q (4 octets)
```

À l'arrivée, l'autre switch lit l'étiquette et sait où envoyer la trame.

---

## DTP : la négociation automatique (dangereuse !)

### Qu'est-ce que DTP ?

**DTP** (Dynamic Trunking Protocol) est un protocole Cisco qui permet aux switches de décider automatiquement si un lien devient trunk.

### Les modes DTP

| Mode | Comportement |
|------|--------------|
| **Access** | Jamais trunk, refuse la négociation |
| **Trunk** | Toujours trunk |
| **Dynamic Auto** | Devient trunk si l'autre le demande |
| **Dynamic Desirable** | Demande activement à devenir trunk |

### Pourquoi est-ce dangereux ?

Un attaquant peut envoyer des paquets DTP et demander un trunk :

```
Attaquant : [DTP] "Je demande un trunk !"
Switch : "OK, voilà accès à tous les VLANs !"
```

### Solution : désactiver DTP

```
Switch(config-if)# switchport nonegotiate
```

---

## Le Native VLAN : le VLAN "sans étiquette"

### Principe

Sur un trunk, un VLAN spécial n'est pas étiqueté : le **Native VLAN**.

Par défaut, c'est le **VLAN 1**.

```
Trame VLAN 10 sur trunk : [VLAN 10][Données] ← avec étiquette
Trame VLAN 1 sur trunk  : [Données]          ← sans étiquette !
```

### Pourquoi est-ce un problème ?

L'attaque "double tagging" exploite le Native VLAN :

```
1. L'attaquant met 2 étiquettes : [VLAN 1][VLAN 20][Données]
2. Switch A enlève VLAN 1 (natif, pas d'étiquette)
3. Reste : [VLAN 20][Données]
4. Switch B croit que c'est du VLAN 20 !
```

### Solution

Utiliser un VLAN inutilisé comme Native VLAN :

```
Switch(config-if)# switchport trunk native vlan 999
```

---

## Problèmes courants et dépannage

### 1. Native VLAN différent des deux côtés

**Symptôme** : le switch affiche un warning

```
%CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch discovered
```

**Solution** : configurer le même Native VLAN des deux côtés

### 2. VLAN qui ne passe pas

**Symptôme** : les machines d'un VLAN ne se voient pas entre switches

**Causes possibles** :
- Le VLAN n'est pas créé sur un des switches
- Le VLAN n'est pas autorisé sur le trunk

**Vérification** :
```
Switch# show vlan brief
Switch# show interfaces trunk
```

### 3. Le trunk ne se forme pas

**Symptôme** : le port reste en mode access

**Solution** : forcer le trunk des deux côtés :
```
Switch(config-if)# switchport mode trunk
```

---

## Configuration sécurisée d'un trunk

```cisco
interface GigabitEthernet0/1
 description TRUNK-SECURISE
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30
 switchport nonegotiate
```

### Explication ligne par ligne

| Commande | Fonction |
|----------|----------------|
| `switchport mode trunk` | Force le mode trunk |
| `native vlan 999` | Utilise un VLAN inutilisé comme natif |
| `allowed vlan 10,20,30` | N'autorise que ces 3 VLANs |
| `switchport nonegotiate` | Désactive DTP |

---

## Commandes de vérification

| Commande | Affichage |
|----------|-------------------|
| `show interfaces trunk` | Liste des trunks et VLANs autorisés |
| `show vlan brief` | Liste de tous les VLANs |
| `show interfaces switchport` | Détail d'un port (access/trunk) |

### Exemple de sortie

```
Switch# show interfaces trunk

Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       on           802.1q         trunking      999

Port        Vlans allowed on trunk
Gi0/1       10,20,30
```

---

## Checklist sécurité des trunks

```
□ Mode trunk forcé (pas dynamic)
□ DTP désactivé (nonegotiate)
□ Native VLAN changé (pas VLAN 1)
□ VLANs autorisés limités
□ VLAN 1 inutilisé pour le trafic
□ Ports inutilisés éteints
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **Trunk** | Lien qui transporte plusieurs VLANs |
| **802.1Q** | Standard d'étiquetage des trames |
| **DTP** | Négociation automatique de trunk (à désactiver) |
| **Native VLAN** | VLAN dont les trames ne sont pas étiquetées |
| **Allowed VLANs** | Liste des VLANs autorisés sur un trunk |
| **dot1q** | Autre nom pour 802.1Q |

---

## Résumé en 30 secondes

1. **Trunk** = un câble pour plusieurs VLANs
2. Les trames sont **étiquetées** avec leur VLAN (sauf Native)
3. **DTP** = négociation automatique → à désactiver (sécurité)
4. **Native VLAN** = ne pas utiliser VLAN 1 → changer vers un VLAN inutilisé
5. Toujours **limiter les VLANs autorisés** sur un trunk
6. Vérifier avec `show interfaces trunk`

---

## Schéma récapitulatif

```
Switch A                   TRUNK                    Switch B
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│             │     │ VLAN 10 + tag   │     │             │
│ Port Access │═════│ VLAN 20 + tag   │═════│ Port Access │
│ VLAN 10     │     │ VLAN 30 + tag   │     │ VLAN 10     │
│             │     │ (VLAN 999 natif)│     │             │
└─────────────┘     └─────────────────┘     └─────────────┘
     ↑                                            ↑
   PC du RH                                    PC du RH
   (même VLAN = peuvent communiquer)
```
