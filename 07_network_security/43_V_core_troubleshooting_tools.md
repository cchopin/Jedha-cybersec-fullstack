# Outils de Troubleshooting Réseau - Version Simplifiée

## L'idée en une phrase

Les outils de diagnostic réseau sont comme une boîte à outils : ping pour vérifier si ça répond, traceroute pour voir le chemin, et dig pour les problèmes de noms.

---

## ping : "Es-tu là ?"

### C'est quoi ping ?

Ping envoie un message à une machine et attend la réponse. Simple et efficace.

```
Vous ────── "Coucou ?" ──────> Google
     <───── "Oui !" ──────────
              3ms
```

### Exemple

```bash
ping google.com
64 bytes from google.com: icmp_seq=1 ttl=119 time=3.10 ms
64 bytes from google.com: icmp_seq=2 ttl=119 time=5.82 ms
```

### Ce que ça vous dit

| Résultat | Signification |
|----------|---------------|
| Réponse avec temps | Ça marche ! |
| "Request timeout" | La machine ne répond pas |
| "Unknown host" | Problème DNS |

### Options utiles

```bash
# Linux : 4 pings seulement
ping -c 4 google.com

# Windows : 4 pings seulement
ping -n 4 google.com
```

---

## traceroute : "Par où ça passe ?"

### C'est quoi traceroute ?

Traceroute montre tous les routeurs traversés pour atteindre la destination.

```
Vous → Routeur 1 → Routeur 2 → Routeur 3 → Destination
         4ms         15ms        25ms         30ms
```

### Exemple

```bash
traceroute 8.8.8.8    # Linux/macOS
tracert 8.8.8.8       # Windows

1  bbox.lan (192.168.1.254)  4 ms
2  176.142.96.2              5 ms
3  * * *
4  62.34.2.2                 5 ms
5  dns.google (8.8.8.8)      4 ms
```

### Interprétation

| Sortie | Signification |
|--------|---------------|
| IP + temps | Routeur qui répond |
| `* * *` | Routeur muet (ICMP bloqué) |
| Temps élevé | Saut lent (problème ?) |

---

## ip route / route print : "Où envoyer les paquets ?"

### La table de routage en bref

```
"Je veux aller vers 10.0.0.50"
           │
           ▼
    Route spécifique ? ──── Non ───> Route par défaut
           │                              │
          Oui                             │
           │                              │
           ▼                              ▼
    Utiliser cette route          Passer par la gateway
```

### Linux

```bash
ip route
default via 192.168.1.254 dev wlan0    # Route par défaut
192.168.1.0/24 dev wlan0               # Réseau local
```

### Windows

```
route print
Network Destination    Gateway        Interface
0.0.0.0               192.168.1.254   192.168.1.105
192.168.1.0           On-link        192.168.1.105
```

### L'essentiel

| Élément | Signification |
|---------|---------------|
| default / 0.0.0.0 | Route par défaut (pour tout le reste) |
| Gateway | Routeur à utiliser |
| On-link | Directement accessible |

---

## nslookup et dig : "C'est quoi l'IP de ce nom ?"

### Le problème DNS

```
"www.google.com" ───> Serveur DNS ───> "142.250.185.46"
```

### nslookup (simple)

```bash
nslookup www.google.com

Server:   192.168.1.254
Name:     www.google.com
Address:  142.250.185.46
```

### dig (détaillé)

```bash
dig www.google.com

;; ANSWER SECTION:
www.google.com.    300    IN    A    142.250.185.46

;; Query time: 4 msec
```

### Quand utiliser quoi ?

| Outil | Usage |
|-------|-------|
| nslookup | Test rapide, Windows |
| dig | Analyse détaillée, scripts |

### Options courantes

```bash
# Interroger un serveur spécifique
nslookup www.google.com 8.8.8.8
dig @8.8.8.8 www.google.com

# Chercher les serveurs mail
nslookup -type=MX gmail.com
dig MX gmail.com
```

---

## MTU : "Le paquet est trop gros !"

### C'est quoi le MTU ?

MTU = taille maximale d'un paquet. Standard : 1500 octets.

```
Paquet 1500 octets
        │
        ▼
┌─────────────────┐
│  VPN MTU=1400   │ ← Problème !
└─────────────────┘
        │
    Fragmenté ou bloqué
```

### Détecter un problème MTU

```bash
# Linux : tester avec taille maximale
ping -M do -s 1472 google.com
# "Message too long" = MTU trop petit sur le chemin

# Windows
ping -f -l 1472 google.com
```

### Symptômes typiques

- La connexion marche pour les petits échanges
- Les gros téléchargements échouent
- SSH marche, mais SCP bloque

---

## Les termes à retenir

| Terme | Définition simple |
|-------|-------------------|
| **ping** | Tester si une machine répond |
| **traceroute** | Voir le chemin des paquets |
| **RTT** | Temps aller-retour (Round-Trip Time) |
| **TTL** | Durée de vie du paquet (sauts restants) |
| **Gateway** | Routeur vers d'autres réseaux |
| **DNS** | Annuaire qui traduit noms → IP |
| **MTU** | Taille max d'un paquet (1500 par défaut) |
| **ICMP** | Protocole des messages ping/traceroute |

---

## Résumé en 30 secondes

```
CONNECTIVITÉ    CHEMIN          ROUTAGE         DNS             TAILLE
───────────     ──────          ───────         ───             ──────
ping            traceroute      ip route        nslookup        ping -M do
                tracert         route print     dig             ping -f

"Répond ?"      "Par où ?"      "Routes OK?"    "Nom → IP?"     "Trop gros?"
```

---

## Schéma récapitulatif

```
ARBRE DE DÉCISION SIMPLIFIÉ :

    Le site ne marche pas
             │
             ▼
        ping site.com
             │
      ┌──────┴──────┐
      │             │
     OK           Échec
      │             │
      ▼             ▼
   Problème     ping 8.8.8.8
   applicatif        │
                ┌────┴────┐
                │         │
               OK       Échec
                │         │
                ▼         ▼
             DNS ?    traceroute
           nslookup        │
                      Où ça coince ?


OUTILS PAR OS :

    Linux/macOS              Windows
    ───────────              ───────
    ping                     ping
    traceroute               tracert
    ip route                 route print
    nslookup                 nslookup
    dig                      (pas par défaut)


COMMANDES ESSENTIELLES :

    # Tester la connectivité
    ping google.com

    # Voir le chemin
    traceroute google.com   (Linux)
    tracert google.com      (Windows)

    # Vérifier les routes
    ip route                (Linux)
    route print             (Windows)

    # Résoudre un nom
    nslookup google.com
    dig google.com

    # Tester la MTU
    ping -M do -s 1400 google.com  (Linux)
    ping -f -l 1400 google.com     (Windows)
```
