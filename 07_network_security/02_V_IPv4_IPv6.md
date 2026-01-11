# IPv4 et IPv6 - Version Simplifiée

## L'idée en une phrase

Une adresse IP est comparable à une adresse postale pour les ordinateurs : elle permet de savoir où envoyer les données sur un réseau.

---

## Pourquoi c'est important ?

Sans adresse IP, impossible de communiquer sur un réseau. Chaque appareil (PC, téléphone, serveur) a besoin d'une adresse unique pour recevoir et envoyer des données.

---

## IPv4 : l'ancien système (encore très utilisé)

### À quoi cela ressemble-t-il ?

```
192.168.1.42
```

Il s'agit de 4 nombres séparés par des points. Chaque nombre va de 0 à 255.

### Analogie : le numéro de téléphone

Comme un numéro de téléphone à 10 chiffres, une adresse IPv4 comporte 4 "blocs" de chiffres.

### Le problème

Il n'existe "que" 4,3 milliards d'adresses IPv4 possibles. Avec tous les appareils connectés dans le monde, cela ne suffit plus.

**Solution temporaire** : réutiliser les mêmes adresses dans différents réseaux privés (voir cours sur le NAT).

---

## IPv6 : le nouveau système

### À quoi cela ressemble-t-il ?

```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

C'est beaucoup plus long : 8 groupes de 4 caractères hexadécimaux (0-9 et a-f).

### Pourquoi IPv6 ?

| Aspect | IPv4 | IPv6 |
|--------|------|------|
| Nombre d'adresses | 4,3 milliards | 340 sextillions (nombre à 39 chiffres) |
| Format | 192.168.1.1 | 2001:db8::1 |
| Sécurité intégrée | Non | Oui (IPsec prévu dès le départ) |

**Analogie** : IPv4 correspond à 10 chiffres pour les numéros de téléphone. IPv6 correspond à 39 chiffres.

### Simplification des adresses IPv6

Les adresses IPv6 peuvent être raccourcies :
- Les zéros au début de chaque groupe sont supprimés
- Une suite de zéros est remplacée par `::`

```
2001:0db8:0000:0000:0000:0000:0000:0001
devient
2001:db8::1
```

---

## Les types d'adresses à connaître

### Adresses privées (utilisables en interne)

| IPv4 | IPv6 | Usage |
|------|------|-------|
| 10.x.x.x | fd00::... | Grandes entreprises |
| 172.16.x.x à 172.31.x.x | fd00::... | Moyennes structures |
| 192.168.x.x | fd00::... | Domicile, petites entreprises |

### Adresses spéciales

| Adresse | Définition | Analogie |
|---------|------------|----------|
| 127.0.0.1 (IPv4) | Loopback - communication avec soi-même | S'envoyer une lettre à sa propre adresse |
| ::1 (IPv6) | Loopback IPv6 | Idem |
| 169.254.x.x | APIPA - quand le DHCP ne fonctionne pas | "Aucune adresse reçue, attribution automatique" |

---

## La notation CIDR : le /24, /16, etc.

### L'idée simple

Le `/24` indique combien de bits sont réservés pour identifier le réseau.

- **Plus le nombre est grand** = plus le réseau est petit
- **Plus le nombre est petit** = plus le réseau est grand

### Exemples concrets

| Notation | Nombre d'appareils possibles | Usage typique |
|----------|------------------------------|---------------|
| /8 | 16 millions | Très grande entreprise |
| /16 | 65 000 | Grande entreprise |
| /24 | 254 | Petit réseau, domicile |
| /30 | 2 | Connexion entre 2 routeurs |

### Analogie : le code postal

- `/8` correspond au département seul (75 = Paris)
- `/16` correspond à la ville (75000 = Paris)
- `/24` correspond à l'arrondissement (75001 = 1er arrondissement)

---

## ARP et NDP : trouver les voisins

### ARP (IPv4) : "Qui possède cette adresse IP ?"

Lorsqu'un PC souhaite envoyer des données à 192.168.1.50, il diffuse sur le réseau :
"Qui possède l'adresse 192.168.1.50 ?"

L'appareil concerné répond avec son adresse MAC (l'adresse physique de sa carte réseau).

**Problème de sécurité** : n'importe qui peut répondre (ARP spoofing)

### NDP (IPv6) : même principe, version améliorée

NDP remplit la même fonction qu'ARP avec des fonctionnalités supplémentaires :
- Découverte des routeurs
- Configuration automatique des adresses (SLAAC)

**Problème de sécurité** : toujours vulnérable au spoofing.

---

## DHCP : l'attribution automatique d'adresses

### Fonctionnement

1. Le PC demande : "Une adresse IP est nécessaire"
2. Le serveur DHCP répond : "L'adresse 192.168.1.42 est attribuée"
3. Le PC utilise cette adresse pendant une durée déterminée (le "bail")

### Analogie : l'hôtel

Le DHCP fonctionne comme la réception d'un hôtel qui attribue une chambre. Le numéro n'est pas choisi, il est attribué.

---

## Les risques de sécurité

| Attaque | Explication simple | Couche OSI |
|---------|-------------------|------------|
| **ARP spoofing** | Usurpation d'identité sur le réseau | Couche 2 |
| **DHCP starvation** | Épuisement de toutes les adresses IP disponibles | Couche 2-3 |
| **Rogue DHCP** | Création d'un faux serveur DHCP | Couche 2-3 |
| **IP spoofing** | Envoi de paquets avec une fausse adresse source | Couche 3 |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **IPv4** | Adresse sur 4 nombres (192.168.1.1) |
| **IPv6** | Adresse sur 8 groupes hexadécimaux |
| **CIDR** | La notation /24 qui indique la taille du réseau |
| **DHCP** | Service qui distribue les adresses IP automatiquement |
| **ARP** | Protocole pour trouver l'adresse MAC à partir de l'IP |
| **NDP** | Équivalent d'ARP pour IPv6 |
| **NAT** | Permet à plusieurs appareils de partager une seule IP publique |
| **Loopback** | Adresse pour communiquer avec soi-même (127.0.0.1) |

---

## Résumé en 30 secondes

1. **IPv4** = 4 nombres (192.168.1.1), environ 4 milliards d'adresses
2. **IPv6** = 8 groupes hexadécimaux, nombre quasi-infini d'adresses
3. **CIDR (/24)** = indique la taille du réseau
4. **DHCP** = attribue les adresses automatiquement
5. **ARP/NDP** = trouve les voisins sur le réseau local
6. **Risque principal** = usurpation d'identité (spoofing)

---

## Pour aller plus loin

- **ping** : tester si une machine répond
- **ip addr** (Linux) / **ipconfig** (Windows) : afficher la configuration IP
- **Wireshark** : observer les échanges ARP et DHCP en temps réel
