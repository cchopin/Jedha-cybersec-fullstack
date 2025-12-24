# Attaques ARP et VLAN

## Objectifs du cours

Bien que le CCNA prépare aux meilleures pratiques en matière de réseau et de sécurité, il est tout aussi important de comprendre comment pensent les attaquants. En apprenant la perspective Red Team, il devient possible de mieux défendre un réseau contre ces menaces.

Compétences visées :
- Comprendre comment les attaquants exploitent ARP pour les attaques Man-in-the-Middle (MitM)
- Apprendre les techniques de VLAN hopping, incluant switch spoofing et double-tagging
- Acquérir une expérience pratique avec les outils d'attaque ARP comme ettercap, bettercap et arpspoof
- Explorer les techniques de détection et stratégies de mitigation pour sécuriser un réseau
- Comprendre comment utiliser ARPwatch et les solutions automatisées pour protéger contre l'ARP spoofing

---

## Glossaire

| Terme | Description |
|-------|-------------|
| **ARP Spoofing** | Technique d'envoi de fausses réponses ARP pour rediriger le trafic |
| **ARP Poisoning** | Synonyme d'ARP spoofing - empoisonnement du cache ARP |
| **MitM** | Man-in-the-Middle - Attaque d'interception de communications |
| **VLAN Hopping** | Technique pour accéder à des VLANs non autorisés |
| **Switch Spoofing** | Imitation d'un switch pour former un trunk |
| **Double Tagging** | Injection de deux tags VLAN pour contourner la segmentation |
| **DAI** | Dynamic ARP Inspection - Validation des requêtes/réponses ARP |
| **ARPWatch** | Outil de surveillance des mappings IP-MAC |
| **Port Security** | Limitation du nombre d'adresses MAC par port |

---

## ARP Spoofing pour les attaques Man-in-the-Middle

### Qu'est-ce que l'ARP Spoofing ?

L'ARP spoofing (ou ARP poisoning) est une technique où un attaquant trompe les périphériques réseau pour leur faire envoyer du trafic via sa machine, lui permettant d'intercepter, modifier ou supprimer des paquets. Ceci est souvent utilisé dans les attaques MitM pour voler des identifiants, injecter des malwares ou manipuler des données en transit.

### Comment fonctionne l'ARP Spoofing ?

**Étape 1 : Reconnaissance**
L'attaquant scanne le réseau pour trouver les adresses IP des périphériques cibles.

**Étape 2 : Empoisonnement**
En utilisant des outils d'ARP spoofing, l'attaquant envoie de fausses réponses ARP pour associer son adresse MAC avec l'IP d'un périphérique légitime.

**Étape 3 : Interception**
Le trafic destiné au périphérique légitime est maintenant envoyé à l'attaquant.

**Étape 4 : Relais (optionnel)**
L'attaquant peut transférer le trafic (restant indétecté) ou le manipuler avant de le transmettre.

### Exemple d'attaque ARP Spoofing

Imaginons Alice et Bob communiquant sur un réseau. Un attaquant, Mallory, veut intercepter leur trafic :

**Situation normale :**
```
Alice (192.168.1.10)    ←→    Bob (192.168.1.20)
  MAC: AA:AA:AA:AA:AA:AA        MAC: BB:BB:BB:BB:BB:BB
```

**Après ARP Spoofing :**
```
1. Alice envoie une requête ARP : "Qui a 192.168.1.20 ?"
2. Le vrai Bob répond : "192.168.1.20 est à BB:BB:BB:BB:BB:BB"
3. Mallory envoie une fausse réponse : "192.168.1.20 est à MM:MM:MM:MM:MM:MM"
4. Alice met à jour son cache ARP avec l'adresse MAC de Mallory
5. Tout le trafic d'Alice vers Bob passe maintenant par Mallory
```

**Résultat :**
```
Alice (192.168.1.10) → Mallory → Bob (192.168.1.20)
```

---

## Outils d'ARP Spoofing

### Ettercap

Ettercap est un outil puissant pour l'ARP spoofing et les attaques man-in-the-middle, permettant l'interception du trafic réseau.

**Lancer une attaque ARP poisoning avec Ettercap :**

```bash
ettercap -T -M arp:remote /192.168.1.1/ /192.168.1.100/
```

**Paramètres :**
- `-T` : Lance Ettercap en mode texte (sans GUI)
- `-M arp:remote` : Utilise le module Man-in-the-Middle avec ARP spoofing sur hôtes distants
- `/192.168.1.1/` : Cible 1 (généralement la passerelle)
- `/192.168.1.100/` : Cible 2 (généralement le périphérique victime)

### Bettercap

Bettercap est un outil moderne et puissant conçu pour la flexibilité et l'extensibilité. Il supporte l'ARP spoofing et d'autres attaques réseau.

**Démarrer ARP poisoning avec Bettercap :**

```bash
sudo bettercap -iface eth0
```

**Paramètres :**
- `sudo` : Bettercap nécessite des privilèges root
- `-iface eth0` : Spécifie l'interface réseau à utiliser

**Une fois Bettercap lancé, interagir via l'interface en ligne de commande :**

```
bettercap > arp.spoof on
```

- `arp.spoof on` : Active l'ARP spoofing pour commencer l'empoisonnement du cache ARP

**Commandes utiles supplémentaires :**
```
bettercap > net.probe on               # Découvre les hôtes sur le réseau
bettercap > set arp.spoof.targets 192.168.1.100   # Cible spécifique
bettercap > net.sniff on               # Capture le trafic
```

### Arpspoof

Arpspoof est un outil léger focalisé sur l'ARP spoofing, parfait pour des attaques rapides.

**Lancer une session ARP spoofing avec Arpspoof :**

```bash
arpspoof -i eth0 -t 192.168.1.100 -r 192.168.1.1
```

**Paramètres :**
- `-i eth0` : Spécifie l'interface réseau à utiliser
- `-t 192.168.1.100` : Définit l'IP cible (victime)
- `-r 192.168.1.1` : Définit l'hôte distant (généralement le routeur/passerelle)

**Note :** Pour une attaque bidirectionnelle, lancer deux instances :

```bash
# Terminal 1 : Empoisonner Alice
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1

# Terminal 2 : Empoisonner la passerelle
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

**Activer le forwarding IP (nécessaire pour relayer le trafic) :**

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

---

## ARPWatch : Détection et mitigation de l'ARP Spoofing

### Qu'est-ce qu'ARPWatch ?

ARPWatch est un outil de surveillance réseau qui aide à détecter les attaques d'ARP spoofing en maintenant une base de données des mappings IP-vers-MAC.

### Comment fonctionne ARPWatch ?

1. Écoute les requêtes et réponses ARP sur le réseau
2. Enregistre les nouveaux mappings IP-vers-MAC et ceux modifiés
3. Si une incohérence est détectée, comme un changement dans l'adresse MAC associée à une IP, génère une alerte

### Installation et configuration

**Installation sur Linux :**

```bash
sudo apt-get install arpwatch
```

**Démarrer ARPWatch avec l'interface réseau désirée :**

```bash
sudo arpwatch -i eth0
```

**Vérifier les logs :**

```bash
sudo cat /var/log/syslog | grep arpwatch
```

**Exemple de sortie :**

```
arpwatch: new station 192.168.1.100 aa:bb:cc:dd:ee:ff eth0
arpwatch: changed ethernet address 192.168.1.100 aa:bb:cc:dd:ee:ff (old dd:ee:ff:aa:bb:cc)
```

### Protection automatisée contre l'ARP Spoofing

#### 1. Dynamic ARP Inspection (DAI)

Sur les équipements Cisco, activer DAI pour s'assurer que les réponses ARP sont valides et conformes aux mappings MAC-vers-IP attendus :

```
Switch(config)# ip arp inspection vlan 10
Switch(config)# interface gigabitEthernet 0/1
Switch(config-if)# ip arp inspection trust
```

**Vérification :**

```
Switch# show ip arp inspection
```

#### 2. Entrées ARP statiques

Configurer des entrées ARP statiques pour empêcher les périphériques de tomber victimes de l'ARP spoofing :

**Linux/macOS :**

```bash
sudo arp -s 192.168.1.1 00:11:22:33:44:55
```

**Windows :**

```cmd
arp -s 192.168.1.1 00-11-22-33-44-55
```

**Cisco :**

```
Router(config)# arp 192.168.1.1 0011.2233.4455 ARPA
```

#### 3. Port Security

Limiter le nombre d'adresses MAC autorisées sur un port, empêchant les attaquants d'inonder facilement le switch avec de fausses adresses MAC :

```
Switch(config)# interface gigabitEthernet 0/1
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 1
Switch(config-if)# switchport port-security violation restrict
Switch(config-if)# switchport port-security mac-address sticky
```

**Vérification :**

```
Switch# show port-security interface gigabitEthernet 0/1
```

---

## Techniques de VLAN Hopping

### Qu'est-ce que le VLAN Hopping ?

Le VLAN hopping est une technique qui permet aux attaquants de contourner la segmentation VLAN et d'accéder au trafic d'autres VLANs.

### 1. Switch Spoofing

Dans le switch spoofing, un attaquant configure sa machine pour agir comme un switch, trompant le switch légitime pour qu'il transmette du trafic pour plusieurs VLANs.

**Scénario d'attaque :**

```
1. Attaquant configure son interface pour négocier DTP
2. Switch reçoit messages DTP de l'attaquant
3. Switch pense que l'attaquant est un autre switch
4. Trunk est formé entre le switch et l'attaquant
5. L'attaquant reçoit maintenant le trafic de tous les VLANs
```

**Prévention :**

```
Switch(config)# interface gigabitEthernet 0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport nonegotiate
```

**Vérification :**

```
Switch# show interfaces gigabitEthernet 0/1 switchport
```

### 2. Double Tagging Attack

Dans le double-tagging, un attaquant envoie un paquet avec deux tags VLAN, permettant de transférer le trafic entre VLANs.

**Mécanisme :**

```
Étape 1 : Attaquant crée une trame avec deux tags VLAN
[MAC Dest][MAC Source][0x8100][VLAN 1][0x8100][VLAN 20][Data]

Étape 2 : Premier switch retire le premier tag (VLAN 1, native)
[MAC Dest][MAC Source][0x8100][VLAN 20][Data]

Étape 3 : La trame semble maintenant appartenir au VLAN 20
Deuxième switch transmet au VLAN 20

Étape 4 : L'attaquant a réussi à envoyer du trafic au VLAN 20
```

**Conditions requises pour l'attaque :**
- L'attaquant doit être sur le Native VLAN
- Le Native VLAN doit être le même sur les deux switches
- Le trafic doit traverser au moins deux switches

**Prévention :**

```
Switch(config)# vlan 999
Switch(config)# interface gigabitEthernet 0/24
Switch(config-if)# switchport trunk native vlan 999
```

---

## Méthodes de détection et stratégies de mitigation

### Détection de l'ARP Spoofing

#### 1. Surveiller les tables ARP

Rechercher des adresses IP dupliquées mappées à plusieurs adresses MAC.

**Linux/macOS :**

```bash
arp -a | sort
```

**Windows :**

```cmd
arp -a
```

**Cisco :**

```
Switch# show ip arp
```

#### 2. Utiliser des sniffers de paquets

Des outils comme Wireshark peuvent détecter des réponses ARP inhabituelles.

**Filtre Wireshark pour ARP :**

```
arp.duplicate-address-detected || arp.opcode == 2
```

#### 3. Activer Dynamic ARP Inspection (DAI)

Les switches Cisco valident les réponses ARP pour empêcher le spoofing.

```
Switch(config)# ip arp inspection vlan 10
Switch(config)# ip arp inspection validate src-mac dst-mac ip
```

### Détection du VLAN Hopping

#### 1. Rechercher des ports trunk inattendus

```
Switch# show interfaces trunk
```

#### 2. Vérifier les mismatches de VLAN

```
Switch# show interfaces status
Switch# show vlan brief
```

#### 3. Utiliser des systèmes IDS/IPS

Configurer des règles pour détecter le trafic inter-VLAN inhabituel.

### Stratégies de mitigation

#### 1. Entrées ARP statiques

Assigner des entrées ARP statiques là où c'est faisable pour empêcher l'ARP spoofing.

```bash
arp -s 192.168.1.1 00:11:22:33:44:55
```

#### 2. Port Security

Limiter les adresses MAC sur un port pour empêcher le flooding.

```
Switch(config-if)# switchport port-security maximum 1
Switch(config-if)# switchport port-security violation shutdown
```

#### 3. Activer BPDU Guard

Empêcher les switches non autorisés de former des connexions.

```
Switch(config-if)# spanning-tree bpduguard enable
```

#### 4. Désactiver DTP

Désactiver la négociation automatique de trunk sur tous les ports non-trunk.

```
Switch(config-if)# switchport nonegotiate
```

#### 5. Séparer le Native VLAN

Utiliser un VLAN inutilisé comme Native VLAN.

```
Switch(config-if)# switchport trunk native vlan 999
```

#### 6. Implémenter les VLAN ACLs (VACLs)

Contrôler le trafic inter-VLAN au niveau du switch.

```
Switch(config)# vlan access-map SECURITY 10
Switch(config-access-map)# match ip address ACL_BLOCK
Switch(config-access-map)# action drop
Switch(config)# vlan filter SECURITY vlan-list 10,20
```

---

## Pratique sur GNS3

Pour pratiquer ces concepts d'attaque et de défense, utilisez GNS3 sur la plateforme Jedha.

**Topologie suggérée pour les tests :**

```
┌──────────┐         ┌────────┐         ┌──────────┐
│ Attacker │         │ Switch │         │ Victim   │
│ (Kali)   │─────────│  IOU   │─────────│ (VPCS)   │
└──────────┘         └───┬────┘         └──────────┘
                         │
                    ┌────┴────┐
                    │ Gateway │
                    └─────────┘
```

**Exercices pratiques :**
1. Configurer ARPWatch et observer les alertes
2. Tester une attaque ARP spoofing avec ettercap
3. Configurer DAI et vérifier qu'il bloque l'attaque
4. Tenter une attaque de double-tagging VLAN
5. Implémenter les mitigations et vérifier leur efficacité

---

## Ressources

- Cisco ARP Spoofing Protection Guide : [Cisco Documentation](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/23563-143.html)
- Bettercap Official Documentation : [bettercap.org](https://www.bettercap.org/)
- Ettercap Official Site : [ettercap-project.org](https://www.ettercap-project.org/)
- ARPWatch Documentation : [Linux man pages](https://linux.die.net/man/8/arpwatch)
- CCNA Security Best Practices : [Cisco Press](https://www.ciscopress.com/)
