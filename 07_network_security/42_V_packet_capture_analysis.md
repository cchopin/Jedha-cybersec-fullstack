# Capture et Analyse de Paquets - Version Simplifiée

## L'idée en une phrase

Wireshark et tcpdump sont comme des caméras de surveillance qui enregistrent tout ce qui passe sur le réseau, permettant de rejouer et analyser chaque conversation.

---

## Wireshark : le microscope du réseau

### C'est quoi Wireshark ?

Wireshark capture et affiche tous les paquets qui transitent sur le réseau.

```
┌─────────────────────────────────────────────────────────┐
│                    WIRESHARK                            │
├─────────────────────────────────────────────────────────┤
│  N°   Temps    Source        Destination    Protocole   │
│  1    0.000    192.168.1.10  8.8.8.8        DNS         │
│  2    0.023    8.8.8.8       192.168.1.10   DNS         │
│  3    0.050    192.168.1.10  142.250.185.46 HTTPS       │
├─────────────────────────────────────────────────────────┤
│  Détails du paquet sélectionné :                        │
│  ► Ethernet (MAC addresses)                             │
│  ► IP (addresses, TTL)                                  │
│  ► TCP (ports, flags)                                   │
│  ► HTTP (GET /index.html)                               │
└─────────────────────────────────────────────────────────┘
```

### Ce qui est visible

| Couche | Information |
|--------|-------------|
| Ethernet | Qui parle à qui (MAC) |
| IP | Adresses IP, TTL |
| TCP/UDP | Ports, connexions |
| Application | Requêtes HTTP, DNS, etc. |

---

## Les filtres : trouver l'aiguille dans la botte de foin

### Pourquoi filtrer ?

```
Sans filtre:
1,000,000 paquets... où est mon problème ?

Avec filtre "http":
150 paquets HTTP... voilà mon problème !
```

### Filtres courants

| Besoin | Filtre |
|--------|--------|
| Tout le HTTP | `http` |
| Tout le DNS | `dns` |
| Une IP spécifique | `ip.addr == 192.168.1.1` |
| Un port spécifique | `tcp.port == 443` |
| Requêtes GET | `http.request.method == "GET"` |
| Problèmes TCP | `tcp.analysis.retransmission` |

### Combiner les filtres

```
# HTTP depuis une IP
ip.addr == 192.168.1.10 and http

# DNS ou HTTP
dns or http

# Tout sauf ARP
not arp
```

---

## Follow TCP Stream : reconstruire une conversation

### C'est quoi ?

Wireshark peut reconstituer une conversation complète entre deux machines.

```
Avant (paquets éparpillés):
  Paquet 1: GET /index.html
  Paquet 3: HTTP/1.1 200 OK
  Paquet 5: <html>...
  Paquet 7: </html>

Après "Follow TCP Stream":
  ┌────────────────────────────────────────┐
  │ GET /index.html HTTP/1.1               │
  │ Host: www.example.com                  │
  │                                        │
  │ HTTP/1.1 200 OK                        │
  │ Content-Type: text/html                │
  │                                        │
  │ <html>                                 │
  │   <head>...</head>                     │
  │   <body>Hello World!</body>            │
  │ </html>                                │
  └────────────────────────────────────────┘
```

### Comment faire ?

```
1. Trouver un paquet TCP intéressant
2. Clic droit → Follow → TCP Stream
3. Lire la conversation complète !
```

---

## tcpdump : la capture en ligne de commande

### C'est quoi tcpdump ?

tcpdump fait la même chose que Wireshark, mais en ligne de commande. Idéal pour les serveurs sans interface graphique.

### Commandes de base

```bash
# Capturer sur eth0
tcpdump -i eth0

# Sauvegarder dans un fichier
tcpdump -i eth0 -w capture.pcap

# Lire un fichier
tcpdump -r capture.pcap

# Capturer 100 paquets seulement
tcpdump -c 100 -i eth0
```

### Filtres tcpdump

```bash
# Trafic HTTP
tcpdump -i eth0 tcp port 80

# Une IP spécifique
tcpdump -i eth0 host 192.168.1.1

# DNS uniquement
tcpdump -i eth0 port 53

# Exclure SSH
tcpdump -i eth0 not port 22
```

### Capture à distance

```bash
# Capturer sur un serveur et récupérer le fichier
ssh user@server "tcpdump -i eth0 -w -" > capture.pcap

# Puis analyser avec Wireshark localement
wireshark capture.pcap
```

---

## Analyser les performances

### Latence : le temps de réponse

```
Client                    Serveur
   │                         │
   │─── SYN ───────────────>│  t=0
   │                         │
   │<── SYN-ACK ────────────│  t=50ms
   │                         │
   │─── ACK ───────────────>│  t=51ms

Latence = 50ms (temps de l'aller-retour)
```

| Latence | Qualité |
|---------|---------|
| < 50ms | Excellente |
| 50-100ms | Bonne |
| > 200ms | Mauvaise |

### Jitter : la régularité

```
Paquets réguliers (bon):
│ │ │ │ │ │ │ │
10ms entre chaque

Paquets irréguliers (mauvais jitter):
│  │ │    ││ │   │
Variable = voix saccadée en VoIP
```

| Jitter | Impact VoIP |
|--------|-------------|
| < 20ms | Parfait |
| 20-50ms | Acceptable |
| > 50ms | Voix hachée |

### Perte de paquets

```
Envoyé:  1 2 3 4 5 6 7 8 9 10
Reçu:    1 2   4 5   7 8 9 10
              ↑     ↑
           Paquets perdus !

En TCP: retransmission
En UDP: perdu pour toujours
```

| Perte | Impact |
|-------|--------|
| 0% | Parfait |
| < 1% | Acceptable |
| > 2% | Problèmes audio/video |

### Filtres pour détecter les problèmes

```
# Retransmissions TCP (= perte)
tcp.analysis.retransmission

# Paquets en désordre
tcp.analysis.out_of_order

# Tous les problèmes TCP
tcp.analysis.flags
```

---

## Cas pratiques

### Problème : "Le site est lent"

```
1. Capturer: tcpdump -i eth0 -w web.pcap port 80

2. Ouvrir dans Wireshark

3. Filtrer: http

4. Regarder:
   - Temps entre requête et réponse
   - Retransmissions (tcp.analysis.retransmission)

5. Trouver le coupable:
   - Serveur lent ? (longue attente)
   - Réseau ? (retransmissions)
```

### Problème : "Les appels VoIP sont hachés"

```
1. Capturer: tcpdump -i eth0 -w voip.pcap udp

2. Ouvrir dans Wireshark

3. Menu: Telephony → VoIP Calls

4. Analyser:
   - Jitter (doit être < 30ms)
   - Packet loss (doit être < 1%)

5. Bonus: écouter l'appel !
```

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **PCAP** | Format de fichier de capture |
| **Display Filter** | Filtre pour afficher certains paquets |
| **BPF** | Syntaxe de filtrage (tcpdump) |
| **Follow Stream** | Reconstituer une conversation |
| **Latence** | Temps de réponse |
| **Jitter** | Irrégularité du délai |
| **Packet Loss** | Paquets perdus |
| **Retransmission** | Paquet renvoyé (TCP) |
| **RTT** | Round Trip Time (aller-retour) |

---

## Résumé en 30 secondes

```
WIRESHARK = Interface graphique pour analyser le réseau
TCPDUMP   = Même chose en ligne de commande

FILTRER   = Trouver ce qui nous intéresse
            http, dns, ip.addr == x.x.x.x

FOLLOW    = Reconstituer les conversations
            Clic droit → Follow → TCP Stream

PROBLÈMES = Latence, Jitter, Perte de paquets
            tcp.analysis.retransmission
```

---

## Schéma récapitulatif

```
WORKFLOW DE CAPTURE :

    1. CAPTURER                2. FILTRER               3. ANALYSER
    ┌──────────┐              ┌──────────┐            ┌──────────┐
    │ tcpdump  │    →         │ Wireshark│    →       │ Follow   │
    │ Wireshark│              │ Filtres  │            │ Stream   │
    │          │              │          │            │          │
    │ -w file  │              │ http     │            │ Voir la  │
    │          │              │ dns      │            │ convers. │
    └──────────┘              └──────────┘            └──────────┘


FILTRES ESSENTIELS :

    http                    → Trafic web
    dns                     → Résolution de noms
    ip.addr == x.x.x.x      → Une machine
    tcp.port == 443         → HTTPS
    tcp.analysis.retransmission → Problèmes !


MÉTRIQUES DE PERFORMANCE :

    LATENCE           JITTER            PACKET LOSS
    ────────          ──────            ───────────
    Temps de          Variation         Paquets
    réponse           du délai          perdus

    < 50ms OK         < 20ms OK         < 1% OK
    > 200ms BAD       > 50ms BAD        > 2% BAD


CAPTURE À DISTANCE :

    ┌────────────┐         ┌────────────┐
    │  Serveur   │   SSH   │   Laptop   │
    │  tcpdump   │ ──────> │  Wireshark │
    │            │  PCAP   │            │
    └────────────┘         └────────────┘

    ssh user@server "tcpdump -w -" > capture.pcap
```
