# Attaques ARP et VLAN - Version Simplifiée

## L'idée en une phrase

Les attaques ARP et VLAN exploitent la confiance aveugle du réseau : ARP spoofing permet d'intercepter le trafic en mentant sur son identité, et VLAN hopping permet d'accéder à des réseaux normalement isolés.

---

## ARP Spoofing : mentir sur son identité

### Le principe

ARP est un protocole naïf : il fait confiance à toutes les réponses. Un attaquant peut donc mentir et dire "C'est moi qui ai cette IP !" alors que c'est faux.

### Comment cela fonctionne-t-il ?

**Situation normale** : Alice et Bob communiquent

```
Alice (192.168.1.10)  ←───────────→  Bob (192.168.1.20)
```

**Avec ARP Spoofing** : Mallory (l'attaquant) s'intercale

```
1. Alice : "Qui a 192.168.1.20 ?"
2. Bob répond : "C'est moi, MAC = BB:BB:BB"
3. Mallory répond AUSSI : "C'est moi, MAC = MM:MM:MM" ← MENSONGE

4. Alice croit Mallory (réponse plus rapide ou reçue après)

5. Résultat :
   Alice → Mallory → Bob
         (intercepte tout !)
```

**Analogie** : quelqu'un crie "C'est moi Pierre !" alors qu'il ne s'appelle pas Pierre. Si cette personne est crue, elle reçoit les messages destinés à Pierre.

### Conséquences

| Attaque | Action de l'attaquant |
|---------|------------------------|
| **Man-in-the-Middle** | Intercepte et lit tout le trafic |
| **Vol d'identifiants** | Capture les mots de passe |
| **Modification de données** | Change les messages au passage |
| **Denial of Service** | Redirige le trafic vers nulle part |

---

## Outils d'ARP Spoofing

### Les outils courants (Red Team)

| Outil | Description |
|-------|-------------|
| **ettercap** | Outil complet pour MitM |
| **bettercap** | Version moderne et puissante |
| **arpspoof** | Outil simple et léger |

### Exemple avec arpspoof

```bash
# Terminal 1 : Empoisonner la victime
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Terminal 2 : Empoisonner la passerelle
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100

# Activer le relais (sinon le trafic est bloqué)
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### Exemple avec bettercap

```bash
sudo bettercap -iface eth0
bettercap > arp.spoof on
bettercap > net.sniff on
```

---

## Se protéger contre l'ARP Spoofing

### 1. Dynamic ARP Inspection (DAI)

Le switch vérifie que les réponses ARP sont légitimes :

```cisco
Switch(config)# ip arp inspection vlan 10
Switch(config-if)# ip arp inspection trust  ! Pour les ports sûrs
```

### 2. Entrées ARP statiques

Pour les équipements critiques (serveurs, routeurs) :

```bash
# Linux
sudo arp -s 192.168.1.1 00:11:22:33:44:55

# Windows
arp -s 192.168.1.1 00-11-22-33-44-55
```

### 3. ARPWatch

Surveille les changements d'associations IP/MAC :

```bash
sudo apt-get install arpwatch
sudo arpwatch -i eth0

# Voir les alertes
cat /var/log/syslog | grep arpwatch
```

### 4. Port Security

Limite le nombre de MAC par port :

```cisco
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 1
Switch(config-if)# switchport port-security violation shutdown
```

---

## VLAN Hopping : sauter entre VLANs

### Le principe

Les VLANs sont censés isoler les réseaux. VLAN hopping permet de contourner cette isolation.

### Technique 1 : Switch Spoofing

L'attaquant fait croire au switch qu'il est un autre switch pour obtenir un trunk :

```
1. L'attaquant envoie des messages DTP
2. Switch : "Un autre switch ! Je crée un trunk"
3. L'attaquant reçoit maintenant TOUS les VLANs

Attaquant : "Je suis un switch !"
Switch : "OK, voilà tous les VLANs !"
```

**Protection** :

```cisco
Switch(config-if)# switchport mode access
Switch(config-if)# switchport nonegotiate
```

### Technique 2 : Double Tagging

L'attaquant ajoute DEUX étiquettes VLAN à sa trame :

```
Étape 1 : L'attaquant crée une trame avec 2 tags
[VLAN 1][VLAN 20][Données]

Étape 2 : Premier switch retire le premier tag (VLAN 1 = natif)
[VLAN 20][Données]

Étape 3 : Deuxième switch voit VLAN 20
La trame arrive au VLAN 20 !
```

**Conditions nécessaires** :
- L'attaquant doit être sur le Native VLAN
- Le trafic doit traverser au moins 2 switches

**Protection** :

```cisco
Switch(config-if)# switchport trunk native vlan 999
```

---

## Détecter ces attaques

### Détection ARP Spoofing

| Méthode | Comment |
|---------|---------|
| Vérifier les doublons | `arp -a` et chercher des IPs avec plusieurs MAC |
| Wireshark | Filtre : `arp.duplicate-address-detected` |
| ARPWatch | Alertes automatiques sur changements |

### Détection VLAN Hopping

| Méthode | Commande |
|---------|----------|
| Trunks inattendus | `show interfaces trunk` |
| Vérification ports | `show interfaces switchport` |

---

## Récapitulatif des protections

### Contre ARP Spoofing

| Protection | Fonction |
|------------|----------------|
| **DAI** | Le switch valide les réponses ARP |
| **ARP statique** | Associations fixes pour les équipements critiques |
| **ARPWatch** | Surveillance et alertes |
| **Port Security** | Limite les MAC par port |

### Contre VLAN Hopping

| Protection | Fonction |
|------------|----------------|
| **Désactiver DTP** | `switchport nonegotiate` |
| **Forcer mode access** | `switchport mode access` |
| **Changer Native VLAN** | `native vlan 999` |
| **BPDU Guard** | Bloque les switches non autorisés |

---

## Checklist sécurité Layer 2

```
□ DAI activé sur les VLANs
□ DTP désactivé sur les ports access
□ Ports en mode access (pas dynamic)
□ Native VLAN changé (pas VLAN 1)
□ Port Security activé
□ BPDU Guard sur les ports utilisateurs
□ ARPWatch pour la surveillance
□ Ports inutilisés désactivés
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **ARP Spoofing** | Mentir sur son adresse MAC |
| **MitM** | Man-in-the-Middle - intercepter le trafic |
| **VLAN Hopping** | Sauter d'un VLAN à un autre |
| **Switch Spoofing** | Faire croire qu'on est un switch |
| **Double Tagging** | Mettre 2 étiquettes VLAN pour contourner l'isolation |
| **DAI** | Dynamic ARP Inspection - protection contre ARP spoofing |
| **ARPWatch** | Outil de surveillance ARP |
| **Port Security** | Limiter les MAC par port |

---

## Résumé en 30 secondes

1. **ARP Spoofing** = mentir sur sa MAC pour intercepter le trafic
2. L'attaquant peut lire, modifier ou bloquer les communications
3. **Protection ARP** : DAI, ARP statique, ARPWatch, Port Security
4. **VLAN Hopping** = contourner l'isolation entre VLANs
5. Deux techniques : Switch Spoofing et Double Tagging
6. **Protection VLAN** : désactiver DTP, changer Native VLAN

---

## Schéma récapitulatif

```
ARP SPOOFING :

   Avant                          Après

   Alice ←──────→ Bob             Alice ←──→ Mallory ←──→ Bob
                                         (intercepte tout)


DOUBLE TAGGING :

   Attaquant                Switch 1              Switch 2
   (VLAN 1)
       │                         │                    │
       │ [VLAN1][VLAN20]        │                    │
       │─────────────────────────>                   │
       │                         │                    │
       │           Retire VLAN1  │ [VLAN20]          │
       │                         │────────────────────>
       │                         │                    │
       │                         │              Livre au VLAN 20 !


PROTECTION :

   ┌─────────────────────────────────────────────────┐
   │                   SWITCH                         │
   │                                                  │
   │  DAI activé         Port Security               │
   │  DTP désactivé      BPDU Guard                  │
   │  Native VLAN 999    Ports access forcés         │
   │                                                  │
   │  → Attaques bloquées !                          │
   └─────────────────────────────────────────────────┘
```
