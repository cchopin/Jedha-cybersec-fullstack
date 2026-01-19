# Le modèle OSI et TCP/IP - version simplifiée

## L'idée en une phrase

Lorsqu'un message est envoyé sur Internet, il traverse plusieurs "étapes de préparation" avant d'arriver à destination, comme une lettre placée dans une enveloppe, puis dans un colis, puis dans un camion.

---

## Pourquoi c'est important ?

Lorsque le WiFi ne fonctionne plus, le problème peut provenir de différents endroits :
- Le câble est débranché ? (problème physique)
- La carte réseau est défaillante ? (problème matériel)
- L'adresse IP est incorrecte ? (problème de configuration)
- Le site web est en panne ? (problème du serveur)

Les modèles OSI et TCP/IP permettent de **découper le réseau en couches** pour identifier où se situe le problème. C'est comme un médecin qui cherche quel organe est affecté.

---

## Le modèle OSI : 7 couches comme un immeuble

Le modèle se présente comme un immeuble de 7 étages, chacun ayant un rôle précis :

```
ÉTAGE 7 - APPLICATION    → Le navigateur, l'application de messagerie
ÉTAGE 6 - PRÉSENTATION   → Traduction et chiffrement (HTTPS)
ÉTAGE 5 - SESSION        → Gestion des conversations en cours
ÉTAGE 4 - TRANSPORT      → Assure la livraison fiable (ou non)
ÉTAGE 3 - RÉSEAU         → Le GPS du paquet (routage)
ÉTAGE 2 - LIAISON        → Livraison locale (même réseau)
ÉTAGE 1 - PHYSIQUE       → Les fils et les ondes
```

### Analogie : envoyer un colis

| Couche | Analogie | Dans le réseau |
|--------|----------|----------------|
| **7-Application** | Rédaction de la lettre | Saisie de google.com |
| **6-Présentation** | Traduction en langue étrangère | Chiffrement HTTPS |
| **5-Session** | Maintien de la conversation | Connexion maintenue |
| **4-Transport** | Choix du mode d'envoi : rapide ou sûr | TCP (sûr) ou UDP (rapide) |
| **3-Réseau** | L'adresse postale | Adresse IP |
| **2-Liaison** | Le livreur local | Adresse MAC |
| **1-Physique** | Le camion, la route | Câble, WiFi |

---

## Les couches expliquées simplement

### Couche 1 : Physique - Les tuyaux

C'est le **matériel physique** : câbles, WiFi, fibre optique.

**Analogie** : La route sur laquelle roule le camion de livraison.

**Problèmes typiques** :
- Câble débranché
- Interférence WiFi
- Port réseau défectueux

**À retenir** : En cas de problème, vérifier d'abord le branchement.

---

### Couche 2 : Liaison - Le livreur du quartier

Cette couche gère la **livraison locale** au sein du réseau (entre un PC et la box, par exemple).

**Concept clé : l'adresse MAC**
- Identifiant unique de la carte réseau
- Unique au monde, gravée dans le matériel
- Exemple : `00:1A:2B:3C:4D:5E`

**Analogie** : Le livreur connaît toutes les maisons du quartier et sait à quelle porte se présenter.

**Protocoles importants** :
- **Ethernet** : le standard des câbles réseau
- **WiFi (802.11)** : le sans-fil
- **ARP** : "Qui possède cette adresse IP ?" → Trouve l'adresse MAC

**Risques sécurité** : Un attaquant peut usurper l'identité d'un autre appareil (ARP spoofing)

---

### Couche 3 : Réseau - Le GPS

Cette couche trouve **le chemin** pour aller d'un réseau à un autre.

**Concept clé : l'adresse IP**
- L'adresse postale d'un appareil sur Internet
- Exemple : `192.168.1.42`

**Analogie** : Le GPS qui calcule l'itinéraire Paris → Lyon.

**Protocoles importants** :
- **IP** : le système d'adressage
- **ICMP** : les messages d'erreur et de diagnostic (ping)
- **Routage** : comment les paquets trouvent leur chemin

**Équipement** : Les **routeurs** travaillent à cette couche

---

### Couche 4 : Transport - Le service de livraison

Cette couche décide **comment** livrer : rapidement ou de manière fiable ?

**Les deux options** :

| TCP | UDP |
|-----|-----|
| Fiable, vérifie que tout arrive | Rapide, sans vérification |
| Comme un recommandé avec accusé | Comme une carte postale |
| Web, email, téléchargement | Streaming vidéo, jeux en ligne |

**Concept clé : les ports**
- Un port = une porte d'entrée pour un service
- Port 80 = site web
- Port 443 = site web sécurisé (HTTPS)
- Port 22 = connexion SSH

**Analogie** : Le port est le numéro d'appartement, l'IP est l'adresse de l'immeuble.

---

### Couches 5-6-7 : La partie visible

Ces trois couches gèrent ce que **l'utilisateur voit et utilise**.

| Couche | Rôle | Exemple |
|--------|------|---------|
| **5-Session** | Maintient la connexion ouverte | Une session Netflix |
| **6-Présentation** | Traduit et chiffre | HTTPS, compression |
| **7-Application** | L'interface utilisateur | Chrome, Outlook |

**Protocoles courants** :
- HTTP/HTTPS : les sites web
- DNS : traduit google.com → adresse IP
- SMTP/IMAP : les emails
- SSH : connexion sécurisée à distance

---

## Le modèle TCP/IP : la version pratique

Le modèle OSI est théorique. Dans la pratique, le modèle **TCP/IP** avec 4 couches est utilisé :

```
┌─────────────────────────────────────────────┐
│  TCP/IP (4 couches)  │  OSI (7 couches)     │
├─────────────────────────────────────────────┤
│  Application         │  7 + 6 + 5           │
│  Transport           │  4                   │
│  Internet            │  3                   │
│  Accès réseau        │  2 + 1               │
└─────────────────────────────────────────────┘
```

**C'est plus simple** : les couches aux fonctions similaires sont regroupées.

---

## L'encapsulation : les poupées russes

Lors de l'envoi de données, chaque couche ajoute son "emballage" :

```
Les données           : "Salut !"
+ Couche 7 (App)      : [HTTP] "Salut !"
+ Couche 4 (Trans)    : [TCP][HTTP] "Salut !"
+ Couche 3 (Réseau)   : [IP][TCP][HTTP] "Salut !"
+ Couche 2 (Liaison)  : [MAC][IP][TCP][HTTP] "Salut !"
+ Couche 1 (Phys)     : 0101110101001... (bits)
```

**Analogie** : La lettre est placée dans une enveloppe, puis dans un colis, puis sur une palette, puis dans un camion.

À l'arrivée, le déballage s'effectue dans l'ordre inverse.

---

## Les termes à retenir

| Terme | Définition | Analogie |
|-------|------------|----------|
| **IP** | Adresse sur Internet | Adresse postale |
| **MAC** | Adresse de la carte réseau | Numéro de série |
| **Port** | Numéro du service | Numéro d'appartement |
| **TCP** | Transport fiable | Recommandé avec accusé |
| **UDP** | Transport rapide | Carte postale |
| **Routeur** | Dirige le trafic | Échangeur autoroutier |
| **Switch** | Connecte les appareils locaux | Multiprise intelligente |
| **DNS** | Traduit les noms en IP | Annuaire téléphonique |
| **DHCP** | Distribue les IP automatiquement | Attribution des places |

---

## Les risques de sécurité par couche

| Couche | Risque | Description |
|--------|--------|-------------|
| **1-Physique** | Branchement d'un câble espion | Accès physique = compromission |
| **2-Liaison** | ARP spoofing | Usurpation d'identité de la box |
| **3-Réseau** | IP spoofing | Fausse adresse d'expéditeur |
| **4-Transport** | Scan de ports, SYN flood | Recherche des portes ouvertes |
| **7-Application** | Injection SQL, XSS | Attaques sur les sites/applications |

---

## Comment s'en souvenir ?

**Moyen mnémotechnique (couches 1 → 7)** :
> "**P**our **L**e **R**éseau **T**out **S**e **P**asse **A**utomatiquement"
> (Physique, Liaison, Réseau, Transport, Session, Présentation, Application)

---

## Résumé en 30 secondes

1. **OSI = 7 couches** pour comprendre le fonctionnement du réseau
2. **TCP/IP = 4 couches** utilisé dans la pratique
3. **Chaque couche a un rôle** : physique → application
4. **Encapsulation** : les données sont emballées à chaque étape
5. **Chaque couche a ses risques** de sécurité spécifiques
6. **En cas de problème** : identifier à quelle couche se situe la panne

---

## Pour aller plus loin

- **Wireshark** : visualiser les paquets en temps réel
- **ping** : tester si une machine répond (couche 3)
- **traceroute** : visualiser le chemin des paquets
- **nmap** : scanner les ports ouverts (couche 4)
