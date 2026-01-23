# Pare-feu Linux

**Durée : 55 min**

## Ce que vous allez apprendre dans ce cours

Un pare-feu est la première ligne de défense contre les connexions non autorisées. Même si un service écoute sur un port, le pare-feu peut bloquer l'accès depuis l'extérieur. Dans cette leçon, vous apprendrez :

- comment fonctionne le filtrage de paquets sous Linux,
- comment utiliser nftables (le framework moderne),
- comment utiliser ufw (l'interface simplifiée),
- les stratégies de configuration de pare-feu.

---

## Architecture du filtrage de paquets

### Netfilter

**Netfilter** est le framework du noyau Linux pour le filtrage de paquets. Il fournit des hooks à différents points du parcours des paquets réseau.

### Évolution des outils

| Génération | Outil | Statut |
|------------|-------|--------|
| 1ère | ipchains | Obsolète |
| 2ème | iptables | Legacy, encore utilisé |
| 3ème | nftables | Actuel, recommandé |

### Chaînes et tables (concepts)

Les paquets traversent différentes chaînes selon leur direction :

```
                    ENTRANT
                       |
                       v
+------------------+   |   +------------------+
|    PREROUTING    |---+-->|      INPUT       |---> Processus local
+------------------+       +------------------+
                                   ^
                                   |
+------------------+       +------------------+
|   POSTROUTING    |<------|     OUTPUT       |<--- Processus local
+------------------+       +------------------+
       |
       v
    SORTANT
```

| Chaîne | Description |
|--------|-------------|
| **INPUT** | Paquets destinés au système local |
| **OUTPUT** | Paquets générés par le système local |
| **FORWARD** | Paquets traversant le système (routage) |
| **PREROUTING** | Avant la décision de routage |
| **POSTROUTING** | Après la décision de routage |

---

## nftables

**nftables** est le framework moderne de filtrage, remplaçant iptables, ip6tables, arptables et ebtables.

### Installation et vérification

```bash
# Vérifier si nftables est installé
$ nft --version

# Installer nftables
$ sudo apt install nftables

# Activer le service
$ sudo systemctl enable nftables
$ sudo systemctl start nftables
```

### Syntaxe de base

```bash
# Lister les règles actuelles
$ sudo nft list ruleset

# Lister une table spécifique
$ sudo nft list table inet filter
```

### Créer une configuration de base

```bash
# Créer une table
$ sudo nft add table inet filter

# Créer les chaînes
$ sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
$ sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
$ sudo nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
```

### Ajouter des règles

```bash
# Accepter les connexions établies
$ sudo nft add rule inet filter input ct state established,related accept

# Accepter le loopback
$ sudo nft add rule inet filter input iif lo accept

# Accepter SSH
$ sudo nft add rule inet filter input tcp dport 22 accept

# Accepter HTTP et HTTPS
$ sudo nft add rule inet filter input tcp dport { 80, 443 } accept

# Accepter ICMP (ping)
$ sudo nft add rule inet filter input icmp type echo-request accept

# Logger les paquets refusés
$ sudo nft add rule inet filter input log prefix \"NFT-DROP: \" drop
```

### Fichier de configuration nftables

Créer `/etc/nftables.conf` :

```
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Connexions établies
        ct state established,related accept

        # Loopback
        iif lo accept

        # ICMP
        icmp type echo-request accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept

        # SSH
        tcp dport 22 accept

        # HTTP/HTTPS
        tcp dport { 80, 443 } accept

        # Tout le reste est refusé
        log prefix "NFT-DROP: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

```bash
# Appliquer la configuration
$ sudo nft -f /etc/nftables.conf

# Vérifier
$ sudo nft list ruleset
```

### Gestion des règles

```bash
# Supprimer une règle (par handle)
$ sudo nft -a list ruleset  # Voir les handles
$ sudo nft delete rule inet filter input handle 5

# Vider toutes les règles
$ sudo nft flush ruleset

# Sauvegarder la configuration actuelle
$ sudo nft list ruleset > /etc/nftables.conf
```

---

## ufw (Uncomplicated Firewall)

**ufw** est une interface simplifiée pour gérer le pare-feu, parfaite pour les débutants.

### Installation et activation

```bash
# Installer ufw
$ sudo apt install ufw

# Vérifier le statut
$ sudo ufw status

# Activer ufw
$ sudo ufw enable

# Désactiver ufw
$ sudo ufw disable
```

### Règles de base

```bash
# Politique par défaut
$ sudo ufw default deny incoming
$ sudo ufw default allow outgoing

# Autoriser SSH (important avant d'activer!)
$ sudo ufw allow ssh
# ou
$ sudo ufw allow 22/tcp

# Autoriser HTTP et HTTPS
$ sudo ufw allow 80/tcp
$ sudo ufw allow 443/tcp

# Autoriser une plage de ports
$ sudo ufw allow 6000:6007/tcp
```

### Règles avancées

```bash
# Autoriser depuis une IP spécifique
$ sudo ufw allow from 192.168.1.100

# Autoriser depuis un sous-réseau
$ sudo ufw allow from 192.168.1.0/24

# Autoriser un port depuis une IP spécifique
$ sudo ufw allow from 192.168.1.100 to any port 22

# Refuser une IP
$ sudo ufw deny from 10.0.0.5

# Limiter les tentatives de connexion (rate limiting)
$ sudo ufw limit ssh
```

### Gérer les règles

```bash
# Voir les règles avec numéros
$ sudo ufw status numbered

# Supprimer une règle par numéro
$ sudo ufw delete 3

# Supprimer une règle par spécification
$ sudo ufw delete allow 80/tcp

# Recharger les règles
$ sudo ufw reload

# Réinitialiser à zéro
$ sudo ufw reset
```

### Profils d'applications

```bash
# Lister les profils disponibles
$ sudo ufw app list
Available applications:
  Nginx Full
  Nginx HTTP
  Nginx HTTPS
  OpenSSH

# Voir les détails d'un profil
$ sudo ufw app info "Nginx Full"

# Autoriser un profil
$ sudo ufw allow "Nginx Full"
```

### Logging

```bash
# Activer les logs
$ sudo ufw logging on

# Niveaux de log: off, low, medium, high, full
$ sudo ufw logging medium

# Voir les logs
$ sudo tail -f /var/log/ufw.log
```

---

## iptables (legacy)

Bien que nftables soit recommandé, iptables reste courant. Voici les bases :

### Commandes de base

```bash
# Lister les règles
$ sudo iptables -L -n -v

# Politique par défaut
$ sudo iptables -P INPUT DROP
$ sudo iptables -P FORWARD DROP
$ sudo iptables -P OUTPUT ACCEPT

# Accepter les connexions établies
$ sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Accepter le loopback
$ sudo iptables -A INPUT -i lo -j ACCEPT

# Accepter SSH
$ sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Sauvegarder les règles
$ sudo iptables-save > /etc/iptables/rules.v4
```

### Migration vers nftables

```bash
# Convertir les règles iptables en nftables
$ sudo iptables-save | iptables-restore-translate -f /dev/stdin
```

---

## Stratégies de configuration

### Défense en profondeur

```
+----------------------------------+
|       Pare-feu périmetrique      |  <-- Premier niveau
+----------------------------------+
              |
+----------------------------------+
|       Pare-feu de l'hôte         |  <-- Deuxième niveau
+----------------------------------+
              |
+----------------------------------+
|    Configuration des services    |  <-- Troisième niveau
+----------------------------------+
```

### Principe du moindre privilège

1. **Politique par défaut : DENY** - Tout est bloqué par défaut
2. **Autoriser explicitement** - N'ouvrir que ce qui est nécessaire
3. **Limiter les sources** - Restreindre par IP quand possible

### Exemple de configuration serveur web

```bash
# Avec ufw
$ sudo ufw default deny incoming
$ sudo ufw default allow outgoing
$ sudo ufw allow ssh
$ sudo ufw allow 80/tcp
$ sudo ufw allow 443/tcp
$ sudo ufw enable

# Ou avec nftables
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        tcp dport 22 accept
        tcp dport { 80, 443 } accept
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

### Exemple de configuration base de données

```bash
# MySQL accessible uniquement depuis le serveur web (192.168.1.10)
$ sudo ufw allow from 192.168.1.10 to any port 3306
```

---

## Dépannage

### Vérifier la connectivité

```bash
# Tester si un port est accessible
$ nc -zv 192.168.1.1 22
$ telnet 192.168.1.1 22

# Depuis l'extérieur
$ nmap -p 22 192.168.1.1
```

### Analyser les logs

```bash
# Logs nftables
$ sudo journalctl -k | grep NFT

# Logs ufw
$ sudo tail -f /var/log/ufw.log

# Logs iptables
$ sudo dmesg | grep -i iptables
```

### Problèmes courants

| Problème | Cause probable | Solution |
|----------|----------------|----------|
| SSH bloqué après activation | SSH non autorisé avant activation | Toujours autoriser SSH d'abord |
| Service accessible malgré deny | Service écoute sur localhost | Vérifier avec ss -tuln |
| Règles non persistantes | Configuration non sauvegardée | Sauvegarder dans le fichier de config |

---

## Glossaire des sigles et définitions

| Sigle/Terme | Définition |
|-------------|------------|
| **Firewall** | Pare-feu - Système de filtrage du trafic réseau |
| **Netfilter** | Framework du noyau Linux pour le filtrage de paquets |
| **nftables** | Framework moderne de filtrage (successeur d'iptables) |
| **iptables** | Ancien outil de configuration du pare-feu |
| **ufw** | Uncomplicated Firewall - Interface simplifiée |
| **Chain** | Chaîne - Séquence de règles appliquées aux paquets |
| **Table** | Ensemble de chaînes pour un usage spécifique |
| **Policy** | Politique par défaut quand aucune règle ne correspond |
| **ACCEPT** | Action acceptant le paquet |
| **DROP** | Action ignorant silencieusement le paquet |
| **REJECT** | Action refusant le paquet avec notification |
| **Stateful** | Pare-feu suivant l'état des connexions |

---

## Récapitulatif des commandes

### nftables

| Commande | Description |
|----------|-------------|
| `nft list ruleset` | Lister toutes les règles |
| `nft add table inet filter` | Créer une table |
| `nft add chain inet filter input {...}` | Créer une chaîne |
| `nft add rule inet filter input tcp dport 22 accept` | Ajouter une règle |
| `nft -a list ruleset` | Lister avec handles |
| `nft delete rule inet filter input handle N` | Supprimer une règle |
| `nft flush ruleset` | Vider toutes les règles |
| `nft -f /etc/nftables.conf` | Charger un fichier |

### ufw

| Commande | Description |
|----------|-------------|
| `ufw status` | Voir le statut |
| `ufw enable/disable` | Activer/désactiver |
| `ufw default deny incoming` | Politique par défaut |
| `ufw allow 22/tcp` | Autoriser un port |
| `ufw allow from IP` | Autoriser une IP |
| `ufw limit ssh` | Rate limiting SSH |
| `ufw status numbered` | Règles numérotées |
| `ufw delete N` | Supprimer règle N |
| `ufw reset` | Réinitialiser |

### iptables

| Commande | Description |
|----------|-------------|
| `iptables -L -n -v` | Lister les règles |
| `iptables -P INPUT DROP` | Politique par défaut |
| `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` | Ajouter une règle |
| `iptables-save > fichier` | Sauvegarder |
| `iptables-restore < fichier` | Restaurer |

### Fichiers importants

| Fichier | Description |
|---------|-------------|
| `/etc/nftables.conf` | Configuration nftables |
| `/etc/ufw/` | Configuration ufw |
| `/var/log/ufw.log` | Logs ufw |
| `/etc/iptables/rules.v4` | Règles iptables sauvegardées |

---

## Ressources

- nftables Wiki - wiki.nftables.org
- Ubuntu UFW Documentation - help.ubuntu.com
- Red Hat Firewalld Documentation
- Netfilter Project - netfilter.org

### Ressources pratiques - TryHackMe / HackTheBox

| Plateforme | Room/Lab | Description |
|------------|----------|-------------|
| TryHackMe | [Linux Hardening](https://tryhackme.com/room/dvlinuxhardening) | Durcissement incluant pare-feu |
| TryHackMe | [Firewalls](https://tryhackme.com/room/dvfirewalls) | Introduction aux pare-feu |
| TryHackMe | [Network Security](https://tryhackme.com/room/dvintrotodetsec) | Sécurité réseau |
| HackTheBox | [Machines Linux](https://app.hackthebox.com/machines) | Contournement de pare-feu |
