# Adresses IP Publiques vs Privées - Version Simplifiée

## L'idée en une phrase

Les adresses privées sont destinées au réseau local (maison, bureau), les adresses publiques sont pour Internet - et le NAT fait le lien entre les deux.

---

## Pourquoi cette distinction ?

Il n'y a pas assez d'adresses IPv4 pour attribuer une adresse unique à chaque appareil dans le monde. Solution : réutiliser les mêmes adresses dans différents réseaux privés !

**Analogie** : Les numéros d'appartement fonctionnent de la même façon. Le "12" existe dans de nombreux immeubles différents, mais dans chaque immeuble il n'y a qu'un seul "12".

---

## Adresse publique vs privée

| Caractéristique | Publique | Privée |
|-----------------|----------|--------|
| Visible sur Internet | Oui | Non |
| Unique au monde | Oui | Non (réutilisable) |
| Attribuée par | Le FAI | Le réseau local (ou DHCP local) |
| Coût | Inclus dans l'abonnement | Gratuit |
| Exemple | 203.0.113.50 | 192.168.1.42 |

---

## Les 3 plages d'adresses privées

Facile à retenir, il n'y en a que 3 :

| Plage | Notation CIDR | Usage typique |
|-------|---------------|---------------|
| **10.x.x.x** | 10.0.0.0/8 | Grandes entreprises (16 millions d'adresses) |
| **172.16.x.x à 172.31.x.x** | 172.16.0.0/12 | Moyennes structures (1 million d'adresses) |
| **192.168.x.x** | 192.168.0.0/16 | Maison, PME (65 000 adresses) |

### Comment reconnaître une adresse privée ?

```
Commence par 10.         → Privée
Commence par 172.16-31.  → Privée
Commence par 192.168.    → Privée
Autre chose              → Probablement publique
```

---

## Le NAT : le traducteur

### Le problème

Un PC possède l'adresse 192.168.1.42 (privée). Les serveurs sur Internet ne peuvent pas répondre à cette adresse car elle n'existe pas sur Internet !

### La solution : NAT (Network Address Translation)

La box Internet traduit l'adresse privée en adresse publique :

```
PC LOCAL                  BOX INTERNET                INTERNET
192.168.1.42  ────────►  203.0.113.5  ────────────►  Serveur Google
   (privé)                 (public)
```

### Comment cela fonctionne-t-il ?

1. Le PC envoie : "Connexion demandée vers google.com"
2. La box remplace 192.168.1.42 par 203.0.113.5 (son IP publique)
3. Google répond à 203.0.113.5
4. La box identifie l'expéditeur original et lui renvoie la réponse

**Analogie** : Le NAT fonctionne comme un concierge. Lors de l'envoi du courrier, il met l'adresse de l'immeuble. Lorsque le courrier arrive, il sait dans quel appartement le distribuer.

---

## Plusieurs PC, une seule IP publique

Tous les appareils d'un réseau local partagent la même IP publique :

```
PC (192.168.1.10)     ─┐
Téléphone (192.168.1.11)─┼──► BOX (NAT) ──► 203.0.113.5 ──► Internet
Tablette (192.168.1.12) ─┘
```

Le NAT utilise les **ports** pour savoir à qui renvoyer les réponses.

---

## Le port forwarding

Par défaut, personne sur Internet ne peut contacter les appareils internes (ils sont "cachés" derrière le NAT).

**Problème** : héberger un serveur web en local.

**Solution** : le port forwarding (redirection de port)

```
Internet ──► 203.0.113.5:80 ──► NAT ──► 192.168.1.50:80 (serveur local)
```

Configuration de la box : "Tout ce qui arrive sur le port 80, l'envoyer au PC 192.168.1.50"

---

## Autres adresses spéciales

| Plage | Description | À retenir |
|-------|------------|-----------|
| **127.0.0.1** | Loopback | "Moi-même" |
| **169.254.x.x** | APIPA | "Pas de DHCP, attribution automatique" |
| **100.64.x.x** | CGNAT | NAT du FAI (double NAT) |

---

## Implications en sécurité

### Le NAT comme "protection" (partielle)

| Avantage | Limite |
|----------|--------|
| Les appareils sont cachés | Ce n'est pas un vrai firewall |
| Pas directement accessibles | Port forwarding = porte ouverte |
| L'attaquant doit passer par la box | Si la box est compromise, tout l'est |

### Filtrage anti-spoofing

Un paquet venant d'Internet avec une adresse source privée = **forcément faux** !

Les firewalls bloquent cela :
```
Si le paquet vient d'Internet ET a une source en 10.x.x.x → BLOQUÉ
Si le paquet vient d'Internet ET a une source en 192.168.x.x → BLOQUÉ
```

---

## Et en IPv6 ?

IPv6 dispose de tellement d'adresses que le NAT n'est plus nécessaire. Chaque appareil peut avoir sa propre adresse publique.

**Cependant** : des adresses "privées" (ULA) sont conservées pour l'interne :
- Préfixe : `fd00::/8`

| IPv4 | IPv6 |
|------|------|
| 192.168.x.x (privé) | fd00::... (ULA) |
| Adresse publique via NAT | Adresse publique directe (GUA) |

---

## Les termes à retenir

| Terme | Définition simple |
|-------|------------------|
| **IP publique** | Visible sur Internet, unique au monde |
| **IP privée** | Utilisable en local, réutilisable partout |
| **NAT** | Traduit les adresses privées en publiques |
| **PAT** | NAT avec gestion des ports (plusieurs PC, une IP) |
| **Port forwarding** | Rediriger un port vers un appareil interne |
| **RFC 1918** | Le document qui définit les plages privées |
| **ULA** | Équivalent des adresses privées en IPv6 |

---

## Résumé en 30 secondes

1. **Adresses privées** = utilisables en local (10.x, 172.16-31.x, 192.168.x)
2. **Adresses publiques** = visibles sur Internet
3. **NAT** = traduit privé vers public
4. **Plusieurs appareils** partagent la même IP publique
5. **Port forwarding** = pour héberger un serveur en local
6. **Sécurité** : le NAT cache les appareils mais ce n'est pas un firewall

---

## Commandes utiles

```bash
# Voir son IP publique
curl ifconfig.me

# Voir ses IPs privées (Linux)
ip addr show

# Voir ses IPs (Windows)
ipconfig

# Voir la table NAT (Linux)
iptables -t nat -L
```
